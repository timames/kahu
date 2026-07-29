from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine, AsyncSession

from kahu.config import settings

_connect_args = {}
if settings.database_url.startswith("sqlite"):
    _connect_args = {"check_same_thread": False}

engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    connect_args=_connect_args,
)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def create_tables() -> None:
    """Create all tables (for SQLite dev mode). No-op if tables exist."""
    from kahu.models.base import Base
    import kahu.models  # noqa: F401 — ensure all models are imported

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncSession:  # type: ignore[misc]
    async with async_session() as session:
        yield session
