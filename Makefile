SHELL := /bin/bash
TARGET ?= ./eval/vulnerable_app
DC := docker compose

.PHONY: help up down nuke init fetch ingest refresh verify audit audit-ci eval mcp-add dump restore llm test logs shell

help:            ## show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[1m%-10s\033[0m %s\n", $$1, $$2}'

up:              ## clone-to-running: build, start Neo4j, load or build the graph, start MCP
	./scripts/bootstrap.sh

down:            ## stop everything (data kept)
	$(DC) --profile local-llm down

nuke:            ## stop and DELETE graph data volumes
	$(DC) --profile local-llm down -v

init:            ## re-apply ontology schema + seed
	$(DC) run --rm app cgraph init

fetch:           ## download all sources
	$(DC) run --rm app cgraph fetch

ingest:          ## load all fetched sources
	$(DC) run --rm app cgraph ingest

refresh:         ## refresh fast-moving feeds (KEV, EPSS)
	$(DC) run --rm app cgraph fetch --only cisa-kev first-epss --force
	$(DC) run --rm app cgraph ingest --only cisa-kev first-epss

verify:          ## graph health checks
	$(DC) run --rm app cgraph verify

audit:           ## interactive audit: make audit TARGET=/path/to/repo
	$(DC) run --rm -v "$$(realpath $(TARGET))":/target:ro app cgraph audit /target

audit-ci:        ## non-interactive audit, exit 2 if any open risk >= 20
	$(DC) run --rm -T -v "$$(realpath $(TARGET))":/target:ro app cgraph audit /target --non-interactive --fail-on 20

eval:            ## run the known-answer eval against the vulnerable app
	$(DC) run --rm -T app python scripts/run_eval.py

mcp-add:         ## print the Claude Code command to connect the MCP server
	@echo "claude mcp add --transport http compliance-graph http://localhost:8765/mcp"

dump:            ## write dumps/neo4j.dump (attach to a GitHub release)
	$(DC) stop neo4j app
	$(DC) run --rm --no-deps neo4j neo4j-admin database dump neo4j --to-path=/dumps --overwrite-destination=true
	$(DC) up -d neo4j app
	@ls -lh dumps/neo4j.dump

restore:         ## load dumps/neo4j.dump (overwrites the graph)
	$(DC) stop neo4j app
	$(DC) run --rm --no-deps neo4j neo4j-admin database load neo4j --from-path=/dumps --overwrite-destination=true
	$(DC) up -d neo4j app

llm:             ## start local Ollama and pull the model in .env
	$(DC) --profile local-llm up -d ollama
	$(DC) exec ollama ollama pull $$(grep ^CGRAPH_LLM_MODEL .env | cut -d= -f2)
	@echo "Set CGRAPH_LLM_PROVIDER=ollama in .env, then: docker compose up -d app"

test:            ## unit tests (no Neo4j needed)
	python -m pytest -q

logs:            ## tail logs
	$(DC) logs -f --tail=100

shell:           ## shell in the app container
	$(DC) run --rm app bash
