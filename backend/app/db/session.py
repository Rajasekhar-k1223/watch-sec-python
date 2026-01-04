from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Railway will inject these automatically if services are linked, or you set them in "Variables"
    DATABASE_URL: str = "mysql+aiomysql://root:nBhlxqOuzWwFQkraCcNrVIoDVFqFbWEA@mysql.railway.internal:3306/railway"
    MONGO_URL: str = "mongodb://mongo:taOtHmJnOLgnMorrtJpDZLmozClPXmOq@mongodb.railway.internal:27017"
    
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:3000",
        "https://watch-sec-frontend-production.up.railway.app"
    ]

    model_config = SettingsConfigDict(
        env_file=(".env", ".env.dev"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

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
