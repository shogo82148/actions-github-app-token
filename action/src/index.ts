import * as core from "@actions/core";
import * as http from "@actions/http-client";

interface GetTokenParams {
  githubToken: string;
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

function validateGitHubToken(token: string) {
  if (token.length < 4) {
    throw new Error("GITHUB_TOKEN has invalid format");
  }
  switch (token.substring(0, 4)) {
    case "ghp_":
      // Personal Access Tokens
      throw new Error(
        "GITHUB_TOKEN looks like Personal Access Token. `github-token` must be `${{ github.token }}` or `${{ secrets.GITHUB_TOKEN }}`."
      );

    case "gho_":
      // OAuth Access tokens
      throw new Error(
        "GITHUB_TOKEN looks like OAuth Access token. `github-token` must be `${{ github.token }}` or `${{ secrets.GITHUB_TOKEN }}`."
      );

    case "ghu_":
      // GitHub App user-to-server tokens
      throw new Error(
        "GITHUB_TOKEN looks like GitHub App user-to-server token. `github-token` must be `${{ github.token }}` or `${{ secrets.GITHUB_TOKEN }}`."
      );

    case "ghs_":
      // GitHub App server-to-server tokens
      return; // it's OK

    case "ghr_":
      throw new Error(
        "GITHUB_TOKEN looks like GitHub App refresh token. `github-token` must be `${{ github.token }}` or `${{ secrets.GITHUB_TOKEN }}`."
      );
  }
  // maybe Old Format Personal Access Tokens
  throw new Error(
    "GITHUB_TOKEN looks like Personal Access Token. `github-token` must be `${{ github.token }}` or `${{ secrets.GITHUB_TOKEN }}`."
  );
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

  let token: string;
  if (isIdTokenAvailable()) {
    token = await core.getIDToken(params.audience);
    core.info(`JWT issued by ${params.audience} is available.`);
  } else {
    validateGitHubToken(params.githubToken);
    token = params.githubToken;
    core.info("GitHub Token is available.");
  }
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
  const defaultAudience = "https://aznfkxv2k8.execute-api.us-east-1.amazonaws.com";
  try {
    const required = {
      required: true,
    };
    const githubToken = core.getInput("github-token", required);
    const providerEndpoint = core.getInput("provider-endpoint") || defaultProviderEndpoint;
    const audience = core.getInput("audience", { required: false }) || defaultAudience;

    await assumeRole({
      githubToken,
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
