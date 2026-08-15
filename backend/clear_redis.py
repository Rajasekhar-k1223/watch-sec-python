import asyncio
import redis.asyncio as redis

async def main():
    r = redis.Redis.from_url("redis://db.monitorix.co.in:49103/0")
    await r.delete("agent:EC2AMAZ-MLAM305")
    await r.delete("agent:agent_id:EC2AMAZ-MLAM305")
    print("Deleted redis cache")

if __name__ == "__main__":
    asyncio.run(main())
