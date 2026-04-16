# GitHub Token Vending API

## How to install the API to your AWS Account

### Create a new GitHub App on GitHub

1. Open [GitHub Apps](https://github.com/settings/apps) page
2. Click [New GitHub Apps](https://github.com/settings/apps/new) button
3. Fill in the required fields and click the "Create GitHub App" button
4. Make a note of the AppID.
5. Click the "generate a private key" button under the Private keys section.

### AWS and GitHub App integration settings

Register the AppID and private key to the AWS account.

Register the AppID:

```bash
aws ssm put-parameter \
  --name "/github-app-token/app-id" \
  --value "${YOUR_APP_ID}" \
  --type "String"
```

Register the private key:

```bash
# Create a new KMS Key.
aws kms create-key \
    --key-spec RSA_2048 \
    --key-usage SIGN_VERIFY \
    --origin EXTERNAL \
    --description "GitHub App JWT signing key"

# import the private key.
./import-key.sh "${KEY_ID}" ${PRIVATE_KEY_PEM}

# create an alias.
aws kms create-alias \
    --alias-name alias/github-app \
    --target-key-id "${KEY_ID}"
```

### Deploy the API

```bash
make oidc-provider
make cicd
make build
make deploy
```
