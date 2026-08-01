.PHONY: check format build cross-build coverage integration fuzz fuzz-frame fuzz-datagram binfmt containers container-smoke validate-deploy audit

GO ?= mise x go@1.26.5 -- go
GOFMT ?= mise x go@1.26.5 -- gofmt
COVERAGE_DIR := .coverage

check:
	$(GO) test -race -shuffle=on ./...
	$(GO) vet ./...
	files="$$( $(GOFMT) -l . )" && test -z "$$files"
	$(GO) mod verify
	$(GO) mod tidy -diff
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
	$(MAKE) build cross-build

format:
	$(GOFMT) -w .

build:
	$(GO) build ./cmd/...

cross-build:
	GOOS=linux GOARCH=amd64 $(GO) build ./cmd/...
	GOOS=linux GOARCH=arm64 $(GO) build ./cmd/...

coverage: integration
	mkdir -p $(COVERAGE_DIR)
	$(GO) test -covermode=atomic -coverpkg=./... -coverprofile=$(COVERAGE_DIR)/coverage.unit.out ./...
	$(GO) run ./.tools/mergecoverage $(COVERAGE_DIR)/coverage.out $(COVERAGE_DIR)/coverage.unit.out $(COVERAGE_DIR)/coverage.integration.out $(COVERAGE_DIR)/coverage.edge.out $(COVERAGE_DIR)/coverage.echo.out $(COVERAGE_DIR)/coverage.connector-one.out $(COVERAGE_DIR)/coverage.connector-two.out
	$(GO) run ./.tools/checkcoverage $(COVERAGE_DIR)/coverage.out

integration:
	mkdir -p $(COVERAGE_DIR)
	: > $(COVERAGE_DIR)/coverage.integration.out
	: > $(COVERAGE_DIR)/coverage.edge.out
	: > $(COVERAGE_DIR)/coverage.echo.out
	: > $(COVERAGE_DIR)/coverage.connector-one.out
	: > $(COVERAGE_DIR)/coverage.connector-two.out
	docker build --file integration/Dockerfile --tag tailbridge-integration:local .
	docker run --privileged --rm --volume "$(CURDIR)/$(COVERAGE_DIR):/artifacts" tailbridge-integration:local

fuzz: fuzz-frame fuzz-datagram

fuzz-frame:
	$(GO) test ./internal/protocol -run=^$$ -fuzz=^FuzzReadFrame$$ -fuzztime=30s

fuzz-datagram:
	$(GO) test ./internal/protocol -run=^$$ -fuzz=^FuzzDecodeUDP$$ -fuzztime=30s

binfmt:
	docker run --privileged --rm tonistiigi/binfmt:qemu-v10.0.4@sha256:8f58e6214f4cc9dc83ce8f5acad1ece508eb6b20e696a8c1e9f274481982c541 --install arm64

containers: binfmt
	docker buildx build --platform linux/amd64,linux/arm64 --file Dockerfile.edge --tag tailbridge-edge:audit .
	docker buildx build --platform linux/amd64,linux/arm64 --file Dockerfile.connector --tag tailbridge-connector:audit .
	docker buildx build --platform linux/amd64,linux/arm64 --file Dockerfile.cli --tag tailbridge-cli:audit .

container-smoke:
	docker build --file Dockerfile.edge --tag tailbridge-edge:local .
	docker build --file Dockerfile.connector --tag tailbridge-connector:local .
	docker build --file Dockerfile.cli --tag tailbridge-cli:local .
	test "$$(docker image inspect --format '{{.Config.User}}' tailbridge-connector:local)" = "nonroot:nonroot"
	test "$$(docker image inspect --format '{{.Config.User}}' tailbridge-cli:local)" = "nonroot:nonroot"
	docker run --rm tailbridge-cli:local version
	code=0; docker run --rm tailbridge-edge:local || code=$$?; test $$code -eq 2
	code=0; docker run --rm tailbridge-connector:local || code=$$?; test $$code -eq 2

validate-deploy:
	docker compose --file deploy/docker-compose.edge.yml config --quiet --no-env-resolution
	python -c 'import pathlib,tomllib; tomllib.loads(pathlib.Path("deploy/railway.toml").read_text())'
	docker run --rm --entrypoint sh --volume "$(CURDIR)/deploy/digitalocean:/source:ro" hashicorp/terraform:1.14.5 -c 'cp -a /source /tmp/work && cd /tmp/work && terraform fmt -check && terraform init -backend=false && terraform validate'

audit: check coverage fuzz containers container-smoke validate-deploy
	git diff --check
