
.PHONY: build
build:
	sam build

.PHONY: deploy
deploy:
	sam deploy

# prepare resrouces for CI/CD
.PHONY: cicd
cicd:
	aws cloudformation deploy \
		--region us-east-1 \
		--stack-name "github-app-token-cicd" \
		--template-file "cicd.yaml" \
		--capabilities CAPABILITY_NAMED_IAM
