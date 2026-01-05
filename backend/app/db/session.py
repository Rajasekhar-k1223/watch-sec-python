from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from pydantic_settings import BaseSettings, SettingsConfigDict
from motor.motor_asyncio import AsyncIOMotorClient


class Settings(BaseSettings):
    """
    Railway best practice:
    - NEVER hardcode internal hostnames
    - NEVER hardcode passwords
    - Railway injects env vars automatically
    """

    # =========================
    # Database URLs (Injected by Railway)
    # =========================
    DATABASE_URL: str
    MONGO_URL: str

    # =========================
    # CORS
    # =========================
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:3000",
        "https://watch-sec-frontend-production.up.railway.app",
    ]

    model_config = SettingsConfigDict(
        env_file=(".env", ".env.dev"),
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

# =========================
# SQLAlchemy (Async Engine)
# =========================
engine_args = {
    "echo": False,
    "pool_pre_ping": True,
    "pool_recycle": 300,
}

connect_args = {}

# SQLite handling (local dev)
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
else:
    engine_args.update(
        {
            "pool_size": 20,
            "max_overflow": 10,
        }
    )

engine = create_async_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    **engine_args,
)

AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

Base = declarative_base()

# =========================
# MongoDB (Async)
# =========================
mongo_client = AsyncIOMotorClient(
    settings.MONGO_URL,
    serverSelectionTimeoutMS=5000,
)

# =========================
# Dependencies
# =========================
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


async def get_mongo_db():
    yield mongo_client
