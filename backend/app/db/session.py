from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession # type: ignore
from sqlalchemy.orm import sessionmaker, declarative_base # type: ignore
from pydantic_settings import BaseSettings, SettingsConfigDict # type: ignore
from pydantic import field_validator # type: ignore
from motor.motor_asyncio import AsyncIOMotorClient # type: ignore
from dotenv import load_dotenv # type: ignore
import os # type: ignore

load_dotenv(override=False)


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
    BACKEND_CORS_ORIGINS: str | list[str] = [
        "https://monitorix.co.in",
        "https://www.monitorix.co.in",
    ]

    # =========================
    # Email Settings
    # =========================
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASS: str = ""
    SMTP_FROM: str = "noreply@watch-sec.com"

    model_config = SettingsConfigDict(
        env_file=(".env", ".env.dev"),
        env_file_encoding="utf-8",
        extra="ignore",
    )
    
    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    @field_validator("DATABASE_URL", "MONGO_URL", mode="before")
    @classmethod
    def strip_quotes(cls, v: str) -> str:
        if isinstance(v, str):
            return v.strip('"').strip("'")
        return v


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
            "pool_size": 30,       # Increased: handles concurrent agent heartbeats
            "max_overflow": 20,    # Increased: peak burst capacity
            "pool_timeout": 30,    # Wait up to 30s for a connection before giving up
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
