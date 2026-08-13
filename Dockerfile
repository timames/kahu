FROM python:3.12-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping && rm -rf /var/lib/apt/lists/*

RUN addgroup --system kahu && adduser --system --ingroup kahu kahu

COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

COPY alembic/ ./alembic/
COPY alembic.ini ./

# Runtime JSON config (Pono weights, tuning/risk/canary configs). The package is
# installed into site-packages, so it cannot find these relative to its own path.
COPY config/ ./config/
ENV KAHU_CONFIG_DIR=/app/config

RUN chown -R kahu:kahu /app
USER kahu

EXPOSE 8000

CMD ["uvicorn", "kahu.main:app", "--host", "0.0.0.0", "--port", "8000"]
