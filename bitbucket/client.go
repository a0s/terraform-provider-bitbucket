package bitbucket

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Error represents a error from the bitbucket api.
type Error struct {
	APIError struct {
		Message string `json:"message,omitempty"`
	} `json:"error,omitempty"`
	Type       string `json:"type,omitempty"`
	StatusCode int
	Endpoint   string
}

func (e Error) Error() string {
	return fmt.Sprintf("API Error: %d %s %s", e.StatusCode, e.Endpoint, e.APIError.Message)
}

const (
	// BitbucketEndpointAPI is the fqdn used to talk to bitbucket
	BitbucketEndpointAPI string = "https://api.bitbucket.org/"
	// BitbucketEndpoint is the fqdb used to talk to bitbucket's site
	BitbucketEndpoint string = "https://bitbucket.org"
)

type OAuthAccessToken struct {
	Scopes       string `json:"scopes"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	State        string `json:"state"`
	RefreshToken string `json:"refresh_token"`
}

// Client is the base internal Client to talk to bitbuckets API. This should be a username and password
// the password should be a app-password.
type Client struct {
	Username         string
	Password         string
	OAuthKey         string
	OAuthSecret      string
	OAuthAccessToken *OAuthAccessToken
	OAuthExpiration  int64
	HTTPClient       *http.Client
}

// Do Will just call the bitbucket api but also add auth to it and some extra headers
func (c *Client) Do(method, endpoint string, payload *bytes.Buffer) (*http.Response, error) {
	absoluteendpoint := BitbucketEndpointAPI + endpoint
	log.Printf("[DEBUG] Sending request to %s %s", method, absoluteendpoint)

	var bodyreader io.Reader

	if payload != nil {
		log.Printf("[DEBUG] With payload %s", payload.String())
		bodyreader = payload
	}

	req, err := http.NewRequest(method, absoluteendpoint, bodyreader)
	if err != nil {
		return nil, err
	}

	if c.Username != "" && c.Password != "" {
		req.SetBasicAuth(c.Username, c.Password)
	} else if c.OAuthKey != "" && c.OAuthSecret != "" {
		if c.OAuthExpiration == 0 {
			err := c.OAuthGetAccessToken()
			if err != nil {
				return nil, fmt.Errorf("OAuthGetAccessToken: %w", *err)
			}
		} else {
			if c.OAuthExpiration <= time.Now().Unix() {
				errRefresh := c.OAuthRefreshAccessToken()
				if errRefresh != nil {
					errAccess := c.OAuthGetAccessToken()
					if errAccess != nil {
						var errStrings []string
						errStrings = append(errStrings, fmt.Errorf("OAuthRefreshAccessToken: %w", *errRefresh).Error())
						errStrings = append(errStrings, fmt.Errorf("OAuthGetAccessToken: %w", *errAccess).Error())
						return nil, fmt.Errorf(strings.Join(errStrings, "\n"))
					}
				}
			}
		}
		req.Header.Del("Authorization")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.OAuthAccessToken.AccessToken))
	} else {
		return nil, errors.New("auth: unknown method")
	}

	if payload != nil {
		// Can cause bad request when putting default reviews if set.
		req.Header.Add("Content-Type", "application/json")
	}

	req.Close = true

	resp, err := c.HTTPClient.Do(req)
	log.Printf("[DEBUG] Resp: %v Err: %v", resp, err)
	if resp.StatusCode >= 400 || resp.StatusCode < 200 {
		apiError := Error{
			StatusCode: resp.StatusCode,
			Endpoint:   endpoint,
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		log.Printf("[DEBUG] Resp Body: %s", string(body))

		err = json.Unmarshal(body, &apiError)
		if err != nil {
			apiError.APIError.Message = string(body)
		}

		return resp, error(apiError)

	}
	return resp, err
}

func (c *Client) OAuthGetAccessToken() *error {
	client := &http.Client{}

	form := url.Values{}
	form.Add("grant_type", "client_credentials")
	reader := strings.NewReader(form.Encode())

	request, err := http.NewRequest("POST", BitbucketEndpoint+"/site/oauth2/access_token", reader)
	if err != nil {
		return &err
	}
	request.PostForm = form
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(c.OAuthKey, c.OAuthSecret)

	response, err := client.Do(request)
	if err != nil {
		return &err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return &err
	}
	err = json.Unmarshal(body, c.OAuthAccessToken)
	if err != nil {
		return &err
	}
	c.OAuthExpiration = time.Now().Unix() + c.OAuthAccessToken.ExpiresIn

	return nil
}

func (c *Client) OAuthRefreshAccessToken() *error {
	client := &http.Client{}

	form := url.Values{}
	form.Add("grant_type", "client_credentials")
	form.Add("refresh_token", c.OAuthAccessToken.RefreshToken)
	reader := strings.NewReader(form.Encode())

	request, err := http.NewRequest("POST", BitbucketEndpoint+"/site/oauth2/access_token", reader)
	if err != nil {
		return &err
	}
	request.PostForm = form
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(c.OAuthKey, c.OAuthSecret)

	response, err := client.Do(request)
	if err != nil {
		return &err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return &err
	}
	err = json.Unmarshal(body, c.OAuthAccessToken)
	if err != nil {
		return &err
	}
	c.OAuthExpiration = time.Now().Unix() + c.OAuthAccessToken.ExpiresIn

	return nil
}

// Get is just a helper method to do but with a GET verb
func (c *Client) Get(endpoint string) (*http.Response, error) {
	return c.Do("GET", endpoint, nil)
}

// Post is just a helper method to do but with a POST verb
func (c *Client) Post(endpoint string, jsonpayload *bytes.Buffer) (*http.Response, error) {
	return c.Do("POST", endpoint, jsonpayload)
}

// Put is just a helper method to do but with a PUT verb
func (c *Client) Put(endpoint string, jsonpayload *bytes.Buffer) (*http.Response, error) {
	return c.Do("PUT", endpoint, jsonpayload)
}

// PutOnly is just a helper method to do but with a PUT verb and a nil body
func (c *Client) PutOnly(endpoint string) (*http.Response, error) {
	return c.Do("PUT", endpoint, nil)
}

// Delete is just a helper to Do but with a DELETE verb
func (c *Client) Delete(endpoint string) (*http.Response, error) {
	return c.Do("DELETE", endpoint, nil)
}
