import os
import redis
import sys

def check_redis(url):
    try:
        r = redis.from_url(url)
        r.ping()
        print(f"SUCCESS: {url}")
    except Exception as e:
        print(f"FAILED: {url} -> {e}")

check_redis("redis://:Redis2025Secure@watch-sec-redis:6379/0")
check_redis("redis://default:Redis2025Secure@watch-sec-redis:6379/0")
