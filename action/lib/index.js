"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.assumeRole = void 0;
const core = __importStar(require("@actions/core"));
const http = __importStar(require("@actions/http-client"));
function assertIsDefined(val) {
    if (val === undefined || val === null) {
        throw new Error(`Missing required environment value. Are you running in GitHub Actions?`);
    }
}
async function assumeRole(params) {
    const { GITHUB_REPOSITORY, GITHUB_SHA } = process.env;
    assertIsDefined(GITHUB_REPOSITORY);
    assertIsDefined(GITHUB_SHA);
    const GITHUB_API_URL = process.env["GITHUB_API_URL"] || "https://api.github.com";
    const payload = {
        api_url: GITHUB_API_URL,
        repository: GITHUB_REPOSITORY,
        sha: GITHUB_SHA,
    };
    const headers = {};
    if (!isIdTokenAvailable()) {
        core.error(`OIDC provider is not available. please enable it. see https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect`);
    }
    const token = await core.getIDToken(params.audience);
    headers["Authorization"] = `Bearer ${token}`;
    const client = new http.HttpClient("actions-github-app-token");
    const result = await client.postJson(params.providerEndpoint, payload, headers);
    if (result.statusCode !== http.HttpCodes.OK) {
        const resp = result.result;
        core.setFailed(resp?.message || "unknown error");
        return;
    }
    const resp = result.result;
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
exports.assumeRole = assumeRole;
function isIdTokenAvailable() {
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
    }
    catch (error) {
        if (error instanceof Error) {
            core.setFailed(error);
        }
        else {
            core.setFailed(`${error}`);
        }
    }
}
if (require.main === module) {
    run();
}
