import asyncio
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from kahu.config import settings
from kahu.api import router as api_router
from kahu.db import engine
from kahu.services.triage.poller import run_poller

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
    title="Kahu Core",
    version="0.1.0",
    docs_url="/api/docs" if settings.debug else None,
    lifespan=lifespan,
)

app.include_router(api_router, prefix="/api")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def root():
    return FileResponse(STATIC_DIR / "index.html")
