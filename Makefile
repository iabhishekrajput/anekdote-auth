# ==============================================================================
# Variables

APP_NAME := auth-server
MAIN_PKG := cmd/auth-server/main.go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
DATABASE_URL ?= "postgres://authuser:authpassword@localhost:5432/authdb?sslmode=disable"

# ==============================================================================
# Standard configuration

.DEFAULT_GOAL := help

# ==============================================================================
# Help Documentation

.PHONY: help
help: ## Display this help screen
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ==============================================================================
# Application Scripts

.PHONY: run
run: ## Run the application locally
	SMTP_INSECURE_SKIP_VERIFY=true go run $(MAIN_PKG)

.PHONY: generate
generate: ## Run templ generation
	go tool templ generate ./...

.PHONY: css-build
css-build: ## Build Tailwind CSS definitions
	npx @tailwindcss/cli -c tailwind.config.js -i ./web/static/tailwind.css -o ./web/static/app.css --minify

# ==============================================================================
# Docker Services

.PHONY: postgres-up
postgres-up: ## Start PostgreSQL via Docker Compose
	docker-compose up -d db

.PHONY: postgres-down
postgres-down: ## Stop PostgreSQL container
	docker-compose stop db

.PHONY: redis-up
redis-up: ## Start Redis via Docker Compose
	docker-compose up -d redis

.PHONY: redis-down
redis-down: ## Stop Redis container
	docker-compose stop redis

.PHONY: mailpit-up
mailpit-up: ## Start Mailpit via Docker Compose
	docker-compose up -d mailpit

.PHONY: mailpit-down
mailpit-down: ## Stop Mailpit container
	docker-compose stop mailpit

# ==============================================================================
# Database Migrations

.PHONY: install-goose
install-goose: ## Install goose migration CLI if missing
	@if ! command -v goose > /dev/null; then \
		echo "goose not found. Installing github.com/pressly/goose/v3/cmd/goose@latest..."; \
		go install github.com/pressly/goose/v3/cmd/goose@latest; \
	fi

.PHONY: migrate-up
migrate-up: install-goose ## Run database migrations up
	@goose -dir migrations postgres $(DATABASE_URL) up

.PHONY: migrate-down
migrate-down: install-goose ## Run database migrations down
	@goose -dir migrations postgres $(DATABASE_URL) down

# ==============================================================================
# Security and Certificates

.PHONY: generate-certs
generate-certs: ## Generate RSA private and public key pairs for JWT
	@if [ ! -d "certs" ]; then \
		echo "Creating certs directory..."; \
		mkdir -p certs; \
	fi
	@if [ ! -f "certs/private.pem" ]; then \
		echo "Generating private key..."; \
		openssl genpkey -algorithm RSA -out certs/private.pem -pkeyopt rsa_keygen_bits:2048; \
	else \
		echo "Private key already exists, skipping generation."; \
	fi
	@if [ ! -f "certs/public.pem" ]; then \
		echo "Generating public key..."; \
		openssl rsa -pubout -in certs/private.pem -out certs/public.pem; \
	else \
		echo "Public key already exists, skipping generation."; \
	fi

# ==============================================================================
# Quality Control

.PHONY: tidy
tidy: ## Tidy module dependencies and format all .go files
	@echo 'Tidying module dependencies...'
	go mod tidy
	@echo 'Verifying and vendoring module dependencies...'
	go mod verify
	go mod vendor
	@echo 'Formatting .go files...'
	go fmt ./...

.PHONY: audit
audit: ## Run quality control checks
	@echo 'Checking module dependencies...'
	go mod tidy -diff
	go mod verify
	@echo 'Vetting code...'
	go vet ./...
	go tool staticcheck ./...
	@echo 'Running tests...'
	go test -race -vet=off ./...

# ==============================================================================
# Build Output

.PHONY: build
build: ## Build the cmd/auth-server application binaries
	@echo 'Building cmd/auth-server...'
	go build -ldflags='-s -X main.version=${VERSION}' -o=./bin/auth-server ./cmd/auth-server
	GOOS=linux GOARCH=amd64 go build -ldflags='-s -X main.version=${VERSION}' -o=./bin/linux_amd64/auth-server ./cmd/auth-server

# ==============================================================================
# E2E Tests (Playwright)

E2E_DB_URL ?= $(DATABASE_URL)

.PHONY: e2e-install
e2e-install: ## Install Playwright browsers (run once)
	cd tests && npx playwright install --with-deps chromium

.PHONY: e2e-seed
e2e-seed: ## Seed E2E test data into the database
	@if command -v psql > /dev/null 2>&1; then \
		psql $(E2E_DB_URL) -f tests/seed.sql; \
	else \
		docker exec -i auth_postgres psql -U authuser -d authdb < tests/seed.sql; \
	fi

.PHONY: e2e
e2e: build generate-certs migrate-up e2e-seed ## Build server then run Playwright E2E tests
	@if [ ! -f ".env.test" ]; then \
		echo "No .env.test found — copy .env.test.example and fill in values."; \
		exit 1; \
	fi
	@set -a; . ./.env.test; set +a; cd tests && npx playwright test --config=playwright.config.ts

# ==============================================================================
# Container Images

IMAGE_NAME ?= anekdote-auth
IMAGE_REPO ?= $(IMAGE_NAME)
IMAGE_TAG  ?= $(VERSION)
PLATFORMS  ?= linux/amd64,linux/arm64

.PHONY: image
image: ## Build runtime image for host arch and load into local docker
	docker buildx build --target runtime --load \
		--build-arg VERSION=$(VERSION) \
		-t $(IMAGE_REPO):$(IMAGE_TAG) .

.PHONY: image-migrate
image-migrate: ## Build migrate image for host arch and load into local docker
	docker buildx build --target migrate --load \
		-t $(IMAGE_REPO)-migrate:$(IMAGE_TAG) .

.PHONY: image-push
image-push: ## Build and push multi-arch runtime+migrate images (set IMAGE_REPO)
	docker buildx build --target runtime --push --platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		-t $(IMAGE_REPO):$(IMAGE_TAG) .
	docker buildx build --target migrate --push --platform $(PLATFORMS) \
		-t $(IMAGE_REPO)-migrate:$(IMAGE_TAG) .
