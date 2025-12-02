# actions-github-app-token

A GitHub Action that generates a GitHub App Installation Token.

## Motivation

There are several ways to use tokens in GitHub Actions.
However, they have some limitations.

- [`secrets.GITHUB_TOKEN`](https://help.github.com/en/actions/configuring-and-managing-workflows/authenticating-with-the-github_token)
  - It has some limitations such as [not being able to triggering a new workflow from another workflow](https://github.community/t5/GitHub-Actions/Triggering-a-new-workflow-from-another-workflow/td-p/31676).
- [Personal Access Tokens (PATs)](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)
  - PATs allow to access all repositories the user can access.
  - It's too much authority for using in GitHub Actions workflows.
- [GitHub Apps](https://docs.github.com/en/developers/apps/getting-started-with-apps/about-apps)
  - There are [some actions that generate installation tokens](#related-works).
  - You can limit the repositories an app can access, but if you own a lot of repositories, you need to manage multiple apps.

The action provides [the GitHub Token Vending API](./provider) to manage token permissions.

## Usage

### Install the GitHub App

Create a new your own GitHub App, or install [My Demonstration App](https://github.com/apps/shogo82148-slim).

### Deploy the GitHub Token Vending API

[Install the AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html),
and deploy the API to your AWS Account.

```
cd provider/
sam build
sam deploy
```

### Use the Action in Your Workflow

```yaml
jobs:
  job:
    runs-on: ubuntu-latest
    # use GitHub Actions OIDC Token
    permissions:
      id-token: write
      contents: read

    steps:
      - id: generate
        uses: shogo82148/actions-github-app-token@v1
        # Optional (defaults to My Demonstration App).
        # with:
        #   provider-endpoint: https://EXAMPLE.execute-api.us-east-1.amazonaws.com/
      - run: |
          gh issue create --title "Do something using GITHUB_TOKEN"
        env:
          GITHUB_TOKEN: ${{ steps.generate.outputs.token }}
```

## How It Works

![How It Works](how-it-works.svg)

1. Request a new credential with OIDC (OpenID Connect) Token.\
   The `shogo82148/actions-github-app-token` action sends a temporary id token to the credential token vendor.
2. The vendor signs the request using the long term credential.\
   The long term credential doesn't leave AWS environment. It keeps the workflow safer.
3. The vendor a new credential with JWT (JSON Web Token).
4. GitHub returns a temporary credential.

## Related Works

- [actions/create-github-app-token](https://github.com/actions/create-github-app-token)
- [jwenz723/github-app-installation-token](https://github.com/jwenz723/github-app-installation-token)
- [tibdex/github-app-token](https://github.com/tibdex/github-app-token)
- [getsentry/action-github-app-token](https://github.com/getsentry/action-github-app-token)
- [navikt/github-app-token-generator](https://github.com/navikt/github-app-token-generator)
- [angie1148/action-github-app-token](https://github.com/angie1148/action-github-app-token)
