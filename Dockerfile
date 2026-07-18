FROM python:3.12-slim AS base

WORKDIR /app

RUN addgroup --system kuahene && adduser --system --ingroup kuahene kuahene

COPY pyproject.toml ./
RUN pip install --no-cache-dir .

COPY src/ ./src/
COPY alembic/ ./alembic/
COPY alembic.ini ./

RUN chown -R kuahene:kuahene /app
USER kuahene

EXPOSE 8000

CMD ["uvicorn", "kuahene.main:app", "--host", "0.0.0.0", "--port", "8000"]
