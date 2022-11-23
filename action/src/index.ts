import * as core from "@actions/core";
import * as http from "@actions/http-client";

interface GetTokenParams {
  providerEndpoint: string;
  audience: string;
  repositories: string[];
}

interface GetTokenPayload {
  api_url: string;
  repositories: string[];
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
  };
  const headers: { [name: string]: string } = {};

  if (!isIdTokenAvailable()) {
    core.error(
      `OIDC provider is not available. please enable it. see https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect`
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
  const defaultProviderEndpoint = "https://aznfkxv2k8.execute-api.us-east-1.amazonaws.com/";
  const defaultAppID = "136245";
  const audiencePrefix = "https://github-app.shogo82148.com/";
  try {
    const providerEndpoint = core.getInput("provider-endpoint") || defaultProviderEndpoint;
    const appID = core.getInput("app-id") || defaultAppID;
    const audience = audiencePrefix + appID;
    const repositories = parseRepositories(core.getInput("repositories"));

    await assumeRole({
      providerEndpoint,
      audience,
      repositories,
    });
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error);
    } else {
      core.setFailed(`${error}`);
    }
  }
}

if (require.main === module) {
  run();
}
