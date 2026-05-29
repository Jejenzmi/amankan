.PHONY: up down api worker build migrate tidy seed test smoke graph-up attackpath

up:
	docker compose up -d

down:
	docker compose down

graph-up:
	docker compose up -d neo4j

tidy:
	go mod tidy

build:
	go build -o bin/api ./cmd/api
	go build -o bin/worker ./cmd/worker

# Migrations run automatically on api/worker startup; this target forces them via the api binary.
migrate: build
	./bin/api -migrate-only

api:
	go run ./cmd/api

worker:
	go run ./cmd/worker

smoke:
	./scripts/smoke.sh

attackpath:
	./scripts/attackpath.sh

privesc:
	./scripts/privesc.sh

autoprivesc:
	./scripts/autoprivesc.sh

autograph:
	./scripts/autograph.sh
