#!/usr/bin/env sh
# Run the integration tests against real Neo4j, PostgreSQL and Redis.
#
#   scripts/integration.sh           start containers, test, remove them
#   KEEP=1 scripts/integration.sh    leave the containers running afterwards
#
# Uses docker-compose.test.yml: odd host ports (17687, 15432, 16379) and tmpfs
# storage, so it never touches the dev stack.

set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
COMPOSE="$ROOT/docker-compose.test.yml"
PYTHON="$ROOT/.venv/bin/python"
[ -x "$PYTHON" ] || PYTHON="$ROOT/.venv/Scripts/python.exe"
[ -x "$PYTHON" ] || PYTHON=python3

docker info >/dev/null 2>&1 || { echo "Docker is not running." >&2; exit 1; }

echo "Starting Neo4j, PostgreSQL and Redis (first run downloads the images)..."
docker compose -f "$COMPOSE" up -d --wait

cleanup() {
    if [ "${KEEP:-0}" != "1" ]; then
        echo "Removing the test containers..."
        docker compose -f "$COMPOSE" down -v >/dev/null
    fi
}
trap cleanup EXIT

export DG_TEST_NEO4J_URI=bolt://localhost:17687
export DG_TEST_NEO4J_PASSWORD=integration-test
export DG_TEST_DATABASE_URL=postgresql+psycopg://deception:integration-test@localhost:15432/deceptiongraph_test
export DG_TEST_REDIS_URL=redis://localhost:16379/15

"$PYTHON" -m pytest "$ROOT/tests/integration" -rA
