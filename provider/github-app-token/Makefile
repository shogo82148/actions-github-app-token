
.PHONY: build-ProviderFunction
build-ProviderFunction:
	GOOS=linux GOARCH=amd64 go build -o $(ARTIFACTS_DIR)/bootstrap -tags lambda.norpc ./cmd/bootstrap

.PHONY: test
test:
	go test -v ./...
