# Run the integration tests against real Neo4j, PostgreSQL and Redis.
#
#   .\scripts\integration.ps1            start containers, test, remove them
#   .\scripts\integration.ps1 -Keep      leave the containers running afterwards
#
# Needs Docker Desktop running. Uses docker-compose.test.yml: odd host ports
# (17687, 15432, 16379) and tmpfs storage, so it never touches the dev stack.

param([switch]$Keep)

# Not "Stop": docker writes progress to stderr, which Windows PowerShell 5.1
# turns into terminating errors. Exit codes are checked explicitly instead.
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$compose = Join-Path $root "docker-compose.test.yml"
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { $python = "python" }

docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker is not running. Start Docker Desktop and try again." -ForegroundColor Red
    exit 1
}

Write-Host "Starting Neo4j, PostgreSQL and Redis (first run downloads the images)..."
docker compose -f $compose up -d --wait
if ($LASTEXITCODE -ne 0) { Write-Host "Containers did not become healthy." -ForegroundColor Red; exit 1 }

$env:DG_TEST_NEO4J_URI = "bolt://localhost:17687"
$env:DG_TEST_NEO4J_PASSWORD = "integration-test"
$env:DG_TEST_DATABASE_URL = "postgresql+psycopg://deception:integration-test@localhost:15432/deceptiongraph_test"
$env:DG_TEST_REDIS_URL = "redis://localhost:16379/15"

try {
    & $python -m pytest (Join-Path $root "tests\integration") -rA
    $status = $LASTEXITCODE
}
finally {
    if (-not $Keep) {
        Write-Host "Removing the test containers..."
        docker compose -f $compose down -v | Out-Null
    }
}
exit $status
