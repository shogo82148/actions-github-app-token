package github

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
)

type CreateAppAccessTokenRequest struct {
	Repositories  []string `json:"repositories,omitempty"`
	RepositoryIDs []uint64 `json:"repository_ids,omitempty"`

	Permissions *CreateAppAccessTokenRequestPermissions `json:"permissions,omitempty"`
}

type CreateAppAccessTokenRequestPermissions struct {
	Actions                                    string `json:"actions,omitempty"`
	Administration                             string `json:"administration,omitempty"`
	ArtifactMetadata                           string `json:"artifact_metadata,omitempty"`
	Attestations                               string `json:"attestations,omitempty"`
	Checks                                     string `json:"checks,omitempty"`
	Codespaces                                 string `json:"codespaces,omitempty"`
	Contents                                   string `json:"contents,omitempty"`
	CustomPropertiesForOrganizations           string `json:"custom_properties_for_organizations,omitempty"`
	DependabotSecrets                          string `json:"dependabot_secrets,omitempty"`
	Deployments                                string `json:"deployments,omitempty"`
	Discussions                                string `json:"discussions,omitempty"`
	EmailAddresses                             string `json:"email_addresses,omitempty"`
	EnterpriseCustomPropertiesForOrganizations string `json:"enterprise_custom_properties_for_organizations,omitempty"`
	Environments                               string `json:"environments,omitempty"`
	Followers                                  string `json:"followers,omitempty"`
	GitSSHKeys                                 string `json:"git_ssh_keys,omitempty"`
	GPGKeys                                    string `json:"gpg_keys,omitempty"`
	InteractionLimits                          string `json:"interaction_limits,omitempty"`
	Issues                                     string `json:"issues,omitempty"`
	Members                                    string `json:"members,omitempty"`
	MergeQueues                                string `json:"merge_queues,omitempty"`
	Metadata                                   string `json:"metadata,omitempty"`
	OrganizationAdministration                 string `json:"organization_administration,omitempty"`
	OrganizationAnnouncementBanners            string `json:"organization_announcement_banners,omitempty"`
	OrganizationCopilotSeatManagement          string `json:"organization_copilot_seat_management,omitempty"`
	OrganizationCustomOrgRoles                 string `json:"organization_custom_org_roles,omitempty"`
	OrganizationCustomProperties               string `json:"organization_custom_properties,omitempty"`
	OrganizationCustomRoles                    string `json:"organization_custom_roles,omitempty"`
	OrganizationEvents                         string `json:"organization_events,omitempty"`
	OrganizationHooks                          string `json:"organization_hooks,omitempty"`
	OrganizationPackages                       string `json:"organization_packages,omitempty"`
	OrganizationPersonalAccessTokenRequests    string `json:"organization_personal_access_token_requests,omitempty"`
	OrganizationPersonalAccessTokens           string `json:"organization_personal_access_tokens,omitempty"`
	OrganizationPlan                           string `json:"organization_plan,omitempty"`
	OrganizationProjects                       string `json:"organization_projects,omitempty"`
	OrganizationSecrets                        string `json:"organization_secrets,omitempty"`
	OrganizationSelfHostedRunners              string `json:"organization_self_hosted_runners,omitempty"`
	OrganizationUserBlocking                   string `json:"organization_user_blocking,omitempty"`
	Packages                                   string `json:"packages,omitempty"`
	Pages                                      string `json:"pages,omitempty"`
	Profile                                    string `json:"profile,omitempty"`
	PullRequests                               string `json:"pull_requests,omitempty"`
	RepositoryCustomProperties                 string `json:"repository_custom_properties,omitempty"`
	RepositoryHooks                            string `json:"repository_hooks,omitempty"`
	RepositoryProjects                         string `json:"repository_projects,omitempty"`
	SecretScanningAlerts                       string `json:"secret_scanning_alerts,omitempty"`
	Secrets                                    string `json:"secrets,omitempty"`
	SecurityEvents                             string `json:"security_events,omitempty"`
	SingleFile                                 string `json:"single_file,omitempty"`
	Starring                                   string `json:"starring,omitempty"`
	Statuses                                   string `json:"statuses,omitempty"`
	TeamDiscussions                            string `json:"team_discussions,omitempty"`
	VulnerabilityAlerts                        string `json:"vulnerability_alerts,omitempty"`
	Workflows                                  string `json:"workflows,omitempty"`
}

type CreateAppAccessTokenResponse struct {
	Token string `json:"token"`

	// omit other fields, we don't use them.
}

// CreateAppAccessToken creates an installation access token for the app
// https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app
func (c *Client) CreateAppAccessToken(ctx context.Context, installationID uint64, permissions *CreateAppAccessTokenRequest) (*CreateAppAccessTokenResponse, error) {
	token, err := c.generateJWT(ctx)
	if err != nil {
		return nil, err
	}

	// build the request
	u := c.baseURL.JoinPath("app", "installations", strconv.FormatUint(installationID, 10), "access_tokens")
	body, err := json.Marshal(permissions)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", githubUserAgent)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	req.Header.Set("X-Github-Next-Global-ID", "1")

	// send the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// parse the response
	if resp.StatusCode != http.StatusCreated {
		return nil, newErrUnexpectedStatusCode(resp)
	}

	var ret *CreateAppAccessTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
}
