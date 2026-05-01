.PHONY: check-docker up up-splunk down logs setup-index ingest-sample smoke ui-install ui-build

check-docker:
	@command -v docker >/dev/null 2>&1 || (echo "Docker is not installed or not on PATH. Install Docker, then rerun make up." && exit 127)
	@docker compose version >/dev/null 2>&1 || (echo "Docker Compose v2 is not available. Install the docker compose plugin." && exit 127)

up: check-docker
	docker compose up -d --build

up-splunk: check-docker
	docker compose --profile splunk up -d --build

down: check-docker
	docker compose down

logs: check-docker
	docker compose logs -f --tail=200

setup-index:
	./scripts/setup-index.sh

ingest-sample:
	./scripts/ingest-sample.sh

smoke:
	curl -fsS http://localhost:8000/health && echo ""

ui-install:
	cd frontend && npm install

ui-build:
	cd frontend && npm run build
