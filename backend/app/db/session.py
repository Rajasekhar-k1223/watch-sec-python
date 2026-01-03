from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from pydantic_settings import BaseSettings
import os
from dotenv import load_dotenv

load_dotenv(".env.dev")

class Settings(BaseSettings):
    DATABASE_URL: str = os.getenv("DATABASE_URL")
    MONGO_URL: str = os.getenv("MONGO_URL")

settings = Settings()

# SQLAlchemy Engine (Async)
# Handle SQLite attributes
connect_args = {}
engine_args = {
    "echo": False,
}

if "sqlite" in settings.DATABASE_URL:
    connect_args = {"check_same_thread": False}
else:
    engine_args["pool_size"] = 20
    engine_args["max_overflow"] = 10

engine = create_async_engine(
    settings.DATABASE_URL, 
    connect_args=connect_args,
    **engine_args
)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

Base = declarative_base()

# MongoDB Client (Async)
from motor.motor_asyncio import AsyncIOMotorClient
mongo_client = AsyncIOMotorClient(settings.MONGO_URL)

# Dependency Injection for Routes
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

async def get_mongo_db():
    yield mongo_client
