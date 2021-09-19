import * as core from "@actions/core";
import * as http from "@actions/http-client";

async function cleanup() {
  try {
    // revoke the access token
    // https://docs.github.com/en/rest/reference/apps#revoke-an-installation-access-token
    const apiUrl = process.env["GITHUB_API_URL"] || "https://api.github.com";
    const client = new http.HttpClient("actions-github-app-token");
    const token = core.getState("token");
    if (!token) {
      return;
    }
    const resp = await client.del(`${apiUrl}/installation/token`, {
      Authorization: `token ${token}`,
      Accept: "application/vnd.github.v3+json",
    });
    const statusCode = resp.message.statusCode;
    if (statusCode === 204) {
      // revoked successfully
      return;
    }
    const body = await resp.readBody();
    core.info(`[warning] unexpected ${statusCode}, ${body}`);
  } catch (error) {
    // it's not a critical error, so we just show a warning.
    // the token will expire after an hour.
    core.info(`[warning] ${error}`);
  }
}

cleanup();
