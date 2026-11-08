# Single-stage image: the application is pure Python and the wheels it needs
# are small, so a multi-stage build would add complexity for a few megabytes.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first, so editing source does not invalidate the layer.
COPY pyproject.toml README.md ./
COPY src ./src
# storage: the Neo4j, PostgreSQL and Redis drivers the API uses when configured.
# ml: the `ml` placement strategy (needs a trained model mounted at /app/models).
# observability: OpenTelemetry traces and the Prometheus /metrics endpoint.
RUN pip install --no-cache-dir ".[service,storage,ml,observability]"

COPY data ./data

# Run as a non-root user: this container exposes an API that reports
# intrusions, and it has no reason to hold root.
RUN useradd --create-home --uid 10001 deception \
    && chown -R deception:deception /app
USER deception

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status==200 else 1)"

CMD ["uvicorn", "deceptiongraph.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
