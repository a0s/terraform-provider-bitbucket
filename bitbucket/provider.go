package bitbucket

import (
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Provider will create the necessary terraform provider to talk to the Bitbucket APIs you should
// specify a USERNAME and PASSWORD
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"username": {
				Optional:    true,
				Type:        schema.TypeString,
				DefaultFunc: schema.EnvDefaultFunc("BITBUCKET_USERNAME", nil),
			},
			"password": {
				Optional:    true,
				Type:        schema.TypeString,
				DefaultFunc: schema.EnvDefaultFunc("BITBUCKET_PASSWORD", nil),
			},
			"oauth_key": {
				Optional:    true,
				Type:        schema.TypeString,
				DefaultFunc: schema.EnvDefaultFunc("BITBUCKET_OAUTH_KEY", nil),
			},
			"oauth_secret": {
				Optional:    true,
				Type:        schema.TypeString,
				DefaultFunc: schema.EnvDefaultFunc("BITBUCKET_OAUTH_SECRET", nil),
			},
		},
		ConfigureFunc: providerConfigure,
		ResourcesMap: map[string]*schema.Resource{
			"bitbucket_hook":                resourceHook(),
			"bitbucket_default_reviewers":   resourceDefaultReviewers(),
			"bitbucket_repository":          resourceRepository(),
			"bitbucket_repository_variable": resourceRepositoryVariable(),
			"bitbucket_project":             resourceProject(),
			"bitbucket_branch_restriction":  resourceBranchRestriction(),
			"bitbucket_deployment":          resourceDeployment(),
			"bitbucket_deployment_variable": resourceDeploymentVariable(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"bitbucket_user": dataUser(),
		},
	}
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	client := &Client{
		Username:         d.Get("username").(string),
		Password:         d.Get("password").(string),
		OAuthKey:         d.Get("oauth_key").(string),
		OAuthSecret:      d.Get("oauth_secret").(string),
		HTTPClient:       &http.Client{},
		OAuthAccessToken: &OAuthAccessToken{},
	}

	return client, nil
}
