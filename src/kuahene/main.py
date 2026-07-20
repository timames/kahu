import asyncio
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from kuahene.config import settings
from kuahene.api import router as api_router
from kuahene.db import engine
from kuahene.services.triage.poller import run_poller

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    # Startup — launch the Wazuh alert poller
    poller_task = asyncio.create_task(run_poller(interval=15.0))
    yield
    # Shutdown
    poller_task.cancel()
    await engine.dispose()


app = FastAPI(
    title="Kuahene Core",
    version="0.1.0",
    docs_url="/api/docs" if settings.debug else None,
    lifespan=lifespan,
)

app.include_router(api_router, prefix="/api")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def root():
    return FileResponse(STATIC_DIR / "index.html")
