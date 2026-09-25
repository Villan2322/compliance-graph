#!/usr/bin/env bash
# One command from clone to a running, populated graph + MCP server.
set -euo pipefail
cd "$(dirname "$0")/.."

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

if [ ! -f .env ]; then
  cp .env.example .env
  pw=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24 || true)
  sed -i.bak "s/^NEO4J_PASSWORD=.*/NEO4J_PASSWORD=${pw}/" .env && rm -f .env.bak
  printf 'CG_UID=%s\nCG_GID=%s\n' "$(id -u)" "$(id -g)" >> .env
  say "created .env with a random Neo4j password"
fi
set -a; . ./.env; set +a
mkdir -p sources/raw out state dumps

cypher() { docker compose exec -T neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD" --format plain "$1" | tail -n 1; }
wait_healthy() {
  say "waiting for Neo4j"
  for _ in $(seq 1 90); do
    s=$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q neo4j)" 2>/dev/null || echo starting)
    [ "$s" = healthy ] && return 0; sleep 3
  done
  echo "Neo4j did not become healthy; check: docker compose logs neo4j" >&2; exit 1
}

say "building app image"
docker compose build app
docker compose up -d neo4j
wait_healthy

count=$(cypher "MATCH (w:Weakness) RETURN count(w)" || echo 0)
if [ "${count:-0}" = "0" ]; then
  if [ -n "${CGRAPH_DUMP_URL:-}" ] && [ ! -f dumps/neo4j.dump ]; then
    say "downloading prebuilt graph"
    curl -fL -o dumps/neo4j.dump "$CGRAPH_DUMP_URL"
  fi
  if [ -f dumps/neo4j.dump ]; then
    say "loading prebuilt graph from dumps/neo4j.dump"
    docker compose stop neo4j
    docker compose run --rm --no-deps neo4j neo4j-admin database load neo4j --from-path=/dumps --overwrite-destination=true
    docker compose up -d neo4j
    wait_healthy
    docker compose run --rm app cgraph init   # re-apply in case the ontology is newer than the dump
  else
    say "applying ontology"
    docker compose run --rm app cgraph init
    say "fetching sources (tier 1 + 2)"
    docker compose run --rm app cgraph fetch || echo "some sources failed to fetch; continuing with what we have"
    say "ingesting (a few minutes the first time)"
    docker compose run --rm app cgraph ingest
  fi
else
  say "graph already populated ($count weaknesses); applying ontology updates only"
  docker compose run --rm app cgraph init
fi

say "verifying graph"
docker compose run --rm app cgraph verify || echo "verify reported failures (see above)"

say "starting MCP server"
docker compose up -d app

cat <<MSG

  Neo4j Browser  http://localhost:7474   (user neo4j, password in .env)
  MCP server     http://localhost:8765/mcp

  Connect Claude Code (already wired for this repo via .mcp.json):
    claude mcp add --transport http compliance-graph http://localhost:8765/mcp

  Audit a repo:
    make audit TARGET=/path/to/repo
MSG
