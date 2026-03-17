
.PHONY: build
build:
	sam build

.PHONY: deploy
deploy:
	./deploy.sh

# prepare resources for CI/CD
.PHONY: cicd
cicd:
	aws cloudformation deploy \
		--region us-east-1 \
		--stack-name "github-app-token-cicd" \
		--template-file "cicd.yaml" \
		--capabilities CAPABILITY_NAMED_IAM \
		--parameter-overrides Environment=${APP_ENV}

.PHONY: oidc-provider
oidc-provider:
	aws cloudformation deploy \
		--region us-east-1 \
		--stack-name "github-app-token-oidc-provider" \
		--template-file "oidc-provider.yaml"
