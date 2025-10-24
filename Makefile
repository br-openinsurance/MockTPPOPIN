.PHONY: keys build

ORG_ID="4b75db2e-a0c0-4359-a077-684e88fa695c"
SOFTWARE_ID="fec2fd24-6b2e-4c96-9786-771595a33bff"

setup:
	@make keys

run:
	@docker compose up

clean-run:
	@make build-local
	@make run

build-ui:
	@cd ui && tailwindcss -i ./css/tailwind.css -o ./static/css/styles.css --minify

build-local:
	@docker compose build mockgw
	@docker compose build mocktpp

test:
	@go test ./internal/...

test-coverage:
	@go test -coverprofile=coverage.out ./internal/jwtutil ./internal/tpp
	@go tool cover -html="coverage.out" -o coverage.html
	@echo "Total Coverage: `go tool cover -func=coverage.out | grep total | grep -Eo '[0-9]+\.[0-9]+'` %"

keys:
	@docker compose run certmaker --org_id="${ORG_ID}"
