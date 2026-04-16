import * as core from "@actions/core";
import * as http from "@actions/http-client";

interface GetTokenParams {
  providerEndpoint: string;
  audience: string;
  repositories: string[];
  permissions?: GetTokenPermissions;
}

interface GetTokenPayload {
  api_url: string;
  repositories: string[];
  permissions?: GetTokenPermissions;
}

interface GetTokenPermissions {
  actions?: "read" | "write";
  administration?: "read" | "write";
  artifact_metadata?: "read" | "write";
  attestations?: "read" | "write";
  checks?: "read" | "write";
  codespaces?: "read" | "write";
  contents?: "read" | "write";
  custom_properties_for_organizations?: "read" | "write";
  dependabot_secrets?: "read" | "write";
  deployments?: "read" | "write";
  discussions?: "read" | "write";
  email_addresses?: "read" | "write";
  enterprise_custom_properties_for_organizations?: "read" | "write" | "admin";
  environments?: "read" | "write";
  followers?: "read" | "write";
  git_ssh_keys?: "read" | "write";
  gpg_keys?: "read" | "write";
  interaction_limits?: "read" | "write";
  issues?: "read" | "write";
  members?: "read" | "write";
  merge_queues?: "read" | "write";
  metadata?: "read" | "write";
  organization_administration?: "read" | "write";
  organization_announcement_banners?: "read" | "write";
  organization_copilot_seat_management?: "write";
  organization_custom_org_roles?: "read" | "write";
  organization_custom_properties?: "read" | "write" | "admin";
  organization_custom_roles?: "read" | "write";
  organization_events?: "read";
  organization_hooks?: "read" | "write";
  organization_packages?: "read" | "write";
  organization_personal_access_token_requests?: "read" | "write";
  organization_personal_access_tokens?: "read" | "write";
  organization_plan?: "read";
  organization_projects?: "read" | "write" | "admin";
  organization_secrets?: "read" | "write";
  organization_self_hosted_runners?: "read" | "write";
  organization_user_blocking?: "read" | "write";
  packages?: "read" | "write";
  pages?: "read" | "write";
  profile?: "write";
  pull_requests?: "read" | "write";
  repository_custom_properties?: "read" | "write";
  repository_hooks?: "read" | "write";
  repository_projects?: "read" | "write" | "admin";
  secret_scanning_alerts?: "read" | "write";
  secrets?: "read" | "write";
  security_events?: "read" | "write";
  single_file?: "read" | "write";
  starring?: "read" | "write";
  statuses?: "read" | "write";
  team_discussions?: "read" | "write";
  vulnerability_alerts?: "read" | "write";
  workflows?: "write";
}

interface GetTokenResult {
  github_token: string;
  message?: string;
  warning?: string;
}

interface GetTokenError {
  message: string;
}

export async function assumeRole(params: GetTokenParams) {
  const GITHUB_API_URL = process.env["GITHUB_API_URL"] || "https://api.github.com";

  const payload: GetTokenPayload = {
    api_url: GITHUB_API_URL,
    repositories: params.repositories,
    permissions: params.permissions,
  };
  const headers: { [name: string]: string } = {};

  if (!isIdTokenAvailable()) {
    core.error(
      `OIDC provider is not available. please enable it. see https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect`,
    );
  }
  const token = await core.getIDToken(params.audience);
  headers["Authorization"] = `Bearer ${token}`;

  const client = new http.HttpClient("actions-github-app-token");
  const result = await client.postJson<GetTokenResult | GetTokenError>(params.providerEndpoint, payload, headers);
  if (result.statusCode !== http.HttpCodes.OK) {
    const resp = result.result as GetTokenError;
    core.setFailed(resp?.message || "unknown error");
    return;
  }
  const resp = result.result as GetTokenResult;

  if (resp.message) {
    core.info(resp.message);
  }

  if (resp.warning) {
    core.warning(resp.warning);
  }

  core.setSecret(resp.github_token);
  core.setOutput("token", resp.github_token);
  core.saveState("token", resp.github_token);
}

function isIdTokenAvailable(): boolean {
  const token = process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"];
  const url = process.env["ACTIONS_ID_TOKEN_REQUEST_URL"];
  return token && url ? true : false;
}

function parseRepositories(s: string): string[] {
  if (!s) {
    return [];
  }
  return s.split(/\s+/);
}

async function run() {
  let errorCount: number = 0;

  // getReadOnlyPermission returns "read" if the input is "read", otherwise returns undefined and logs an error if the input is not empty or "read".
  const getReadOnlyPermission = (name: string): "read" | undefined => {
    const value = core.getInput(`permission-${name}`);
    if (value === "read") {
      return value;
    } else if (value) {
      core.error(`invalid permission value for ${name}: ${value}`);
      errorCount++;
    }
    return undefined;
  };

  // getWriteOnlyPermission returns "write" if the input is "write", otherwise returns undefined and logs an error if the input is not empty or "write".
  const getWriteOnlyPermission = (name: string): "write" | undefined => {
    const value = core.getInput(`permission-${name}`);
    if (value === "write") {
      return value;
    } else if (value) {
      core.error(`invalid permission value for ${name}: ${value}`);
      errorCount++;
    }
    return undefined;
  };

  // getReadWritePermission returns "read" or "write" if the input is valid, otherwise returns undefined and logs an error if the input is not empty.
  const getReadWritePermission = (name: string): "read" | "write" | undefined => {
    const value = core.getInput(`permission-${name}`);
    if (value === "read" || value === "write") {
      return value;
    } else if (value) {
      core.error(`invalid permission value for ${name}: ${value}`);
      errorCount++;
    }
    return undefined;
  };

  // getReadWriteAdminPermission returns "read", "write" or "admin" if the input is valid, otherwise returns undefined and logs an error if the input is not empty.
  const getReadWriteAdminPermission = (name: string): "read" | "write" | "admin" | undefined => {
    const value = core.getInput(`permission-${name}`);
    if (value === "read" || value === "write" || value === "admin") {
      return value;
    } else if (value) {
      core.error(`invalid permission value for ${name}: ${value}`);
      errorCount++;
    }
    return undefined;
  };

  const defaultProviderEndpoint = "https://aznfkxv2k8.execute-api.us-east-1.amazonaws.com/";
  const defaultAppID = "136245";
  const audiencePrefix = "https://github-app.shogo82148.com/";
  try {
    const providerEndpoint = core.getInput("provider-endpoint") || defaultProviderEndpoint;
    const appID = core.getInput("app-id") || defaultAppID;
    const audience = audiencePrefix + appID;
    const repositories = parseRepositories(core.getInput("repositories"));
    const permissions: GetTokenPermissions = {
      actions: getReadWritePermission("actions"),
      administration: getReadWritePermission("administration"),
      artifact_metadata: getReadWritePermission("artifact-metadata"),
      attestations: getReadWritePermission("attestations"),
      checks: getReadWritePermission("checks"),
      codespaces: getReadWritePermission("codespaces"),
      contents: getReadWritePermission("contents"),
      custom_properties_for_organizations: getReadWritePermission("custom-properties-for-organizations"),
      dependabot_secrets: getReadWritePermission("dependabot-secrets"),
      deployments: getReadWritePermission("deployments"),
      discussions: getReadWritePermission("discussions"),
      email_addresses: getReadWritePermission("email-addresses"),
      enterprise_custom_properties_for_organizations: getReadWriteAdminPermission(
        "enterprise-custom-properties-for-organizations",
      ),
      environments: getReadWritePermission("environments"),
      followers: getReadWritePermission("followers"),
      git_ssh_keys: getReadWritePermission("git-ssh-keys"),
      gpg_keys: getReadWritePermission("gpg-keys"),
      interaction_limits: getReadWritePermission("interaction-limits"),
      issues: getReadWritePermission("issues"),
      members: getReadWritePermission("members"),
      merge_queues: getReadWritePermission("merge-queues"),
      metadata: getReadWritePermission("metadata"),
      organization_administration: getReadWritePermission("organization-administration"),
      organization_announcement_banners: getReadWritePermission("organization-announcement-banners"),
      organization_copilot_seat_management: getWriteOnlyPermission("organization-copilot-seat-management"),
      organization_custom_org_roles: getReadWritePermission("organization-custom-org-roles"),
      organization_custom_properties: getReadWriteAdminPermission("organization-custom-properties"),
      organization_custom_roles: getReadWritePermission("organization-custom-roles"),
      organization_events: getReadOnlyPermission("organization-events"),
      organization_hooks: getReadWritePermission("organization-hooks"),
      organization_packages: getReadWritePermission("organization-packages"),
      organization_personal_access_token_requests: getReadWritePermission(
        "organization-personal-access-token-requests",
      ),
      organization_personal_access_tokens: getReadWritePermission("organization-personal-access-tokens"),
      organization_plan: getReadOnlyPermission("organization-plan"),
      organization_projects: getReadWriteAdminPermission("organization-projects"),
      organization_secrets: getReadWritePermission("organization-secrets"),
      organization_self_hosted_runners: getReadWritePermission("organization-self-hosted-runners"),
      organization_user_blocking: getReadWritePermission("organization-user-blocking"),
      packages: getReadWritePermission("packages"),
      pages: getReadWritePermission("pages"),
      profile: getWriteOnlyPermission("profile"),
      pull_requests: getReadWritePermission("pull-requests"),
      repository_custom_properties: getReadWritePermission("repository-custom-properties"),
      repository_hooks: getReadWritePermission("repository-hooks"),
      repository_projects: getReadWriteAdminPermission("repository-projects"),
      secret_scanning_alerts: getReadWritePermission("secret-scanning-alerts"),
      secrets: getReadWritePermission("secrets"),
      security_events: getReadWritePermission("security-events"),
      single_file: getReadWritePermission("single-file"),
      starring: getReadWritePermission("starring"),
      statuses: getReadWritePermission("statuses"),
      team_discussions: getReadWritePermission("team-discussions"),
      vulnerability_alerts: getReadWritePermission("vulnerability-alerts"),
      workflows: getWriteOnlyPermission("workflows"),
    };
    if (errorCount > 0) {
      core.setFailed(`invalid permissions: ${errorCount} error(s) found`);
      return;
    }

    await assumeRole({
      providerEndpoint,
      audience,
      repositories,
      permissions,
    });
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error);
    } else {
      core.setFailed(`${error}`);
    }
  }
}

/* istanbul ignore next */
run();
