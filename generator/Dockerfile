FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn pysnmp-lextudio httpx

COPY *.py ./app/
# Make it a package
RUN touch ./app/__init__.py

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
