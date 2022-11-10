import * as core from "@actions/core";
import * as http from "@actions/http-client";

interface GetTokenParams {
  providerEndpoint: string;
  audience: string;
}

interface GetTokenPayload {
  api_url: string;
  repository: string;
  sha: string;
}

interface GetTokenResult {
  github_token: string;
  message?: string;
  warning?: string;
}

interface GetTokenError {
  message: string;
}

function assertIsDefined<T>(val: T): asserts val is NonNullable<T> {
  if (val === undefined || val === null) {
    throw new Error(`Missing required environment value. Are you running in GitHub Actions?`);
  }
}

export async function assumeRole(params: GetTokenParams) {
  const { GITHUB_REPOSITORY, GITHUB_SHA } = process.env;
  assertIsDefined(GITHUB_REPOSITORY);
  assertIsDefined(GITHUB_SHA);
  const GITHUB_API_URL = process.env["GITHUB_API_URL"] || "https://api.github.com";

  const payload: GetTokenPayload = {
    api_url: GITHUB_API_URL,
    repository: GITHUB_REPOSITORY,
    sha: GITHUB_SHA,
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

async function run() {
  const defaultProviderEndpoint = "https://aznfkxv2k8.execute-api.us-east-1.amazonaws.com/";
  const defaultAppID = "136245";
  const audiencePrefix = "https://github-app.shogo82148.com/";
  try {
    const providerEndpoint = core.getInput("provider-endpoint") || defaultProviderEndpoint;
    const appID = core.getInput("app-id") || defaultAppID;
    const audience = audiencePrefix + appID;

    await assumeRole({
      providerEndpoint,
      audience,
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
