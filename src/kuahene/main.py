from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

from fastapi import FastAPI

from kuahene.config import settings
from kuahene.api import router as api_router
from kuahene.db import engine


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    # Startup
    yield
    # Shutdown
    await engine.dispose()


app = FastAPI(
    title="Kuahene Core",
    version="0.1.0",
    docs_url="/api/docs" if settings.debug else None,
    lifespan=lifespan,
)

app.include_router(api_router, prefix="/api")
