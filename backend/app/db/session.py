from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from pydantic_settings import BaseSettings
import os
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    DATABASE_URL: str = os.getenv("DATABASE_URL")
    MONGO_URL: str = os.getenv("MONGO_URL")

settings = Settings()

# SQLAlchemy Engine (Async)
engine = create_async_engine(
    settings.DATABASE_URL, 
    echo=False, # Optimized for Performance & Log Clarity
    pool_size=20,
    max_overflow=10
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
