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
from kahu.services.pono import run_pono_loop
from kahu.services.triage.poller import run_poller
from kahu.services.triage.reeval import start_reeval_loop, stop_reeval_loop

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    # Auto-create tables for SQLite dev mode
    if settings.database_url.startswith("sqlite"):
        from kahu.db import create_tables
        await create_tables()

    # Startup — launch background tasks
    poller_task = asyncio.create_task(run_poller(interval=15.0))
    pono_task = asyncio.create_task(run_pono_loop(interval=300.0))
    await start_reeval_loop()
    yield
    # Shutdown
    poller_task.cancel()
    pono_task.cancel()
    await stop_reeval_loop()
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


@app.get("/sw.js")
async def service_worker():
    """Serve SW from root so it can control the entire scope."""
    return FileResponse(
        STATIC_DIR / "sw.js",
        media_type="application/javascript",
        headers={"Service-Worker-Allowed": "/"},
    )


@app.get("/registerSW.js")
async def register_sw():
    return FileResponse(STATIC_DIR / "registerSW.js", media_type="application/javascript")


@app.get("/manifest.webmanifest")
async def manifest():
    return FileResponse(STATIC_DIR / "manifest.webmanifest", media_type="application/manifest+json")


@app.get("/{full_path:path}")
async def spa_fallback(full_path: str):
    """Catch-all: serve index.html for client-side routes (React Router)."""
    # Serve actual static files if they exist
    static_file = STATIC_DIR / full_path
    if static_file.is_file():
        return FileResponse(static_file)
    return FileResponse(STATIC_DIR / "index.html")
