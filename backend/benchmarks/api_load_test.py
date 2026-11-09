"""
Monitorix Enterprise — Phase 3 API Performance & Multi-Tenant Load Benchmark
Empirically measures:
  - Requests Per Second (RPS)
  - Average, p50, p95, p99 Latency
  - Error Rates
  - Authentication Overhead (JWT vs Health)
  - Concurrent Multi-Tenant Isolation Integrity
  - Frontend Response Times
"""

import time
import statistics
import concurrent.futures
import requests
import json
from datetime import timedelta
import os
import sys

API_BASE = os.getenv("API_BASE", "http://127.0.0.1:8000")
GATEWAY_BASE = os.getenv("GATEWAY_BASE", "http://watch-sec-load-balancer:80")
FRONTEND_BASE = os.getenv("FRONTEND_BASE", "https://watch-sec-frontend:443")

from app.core.security import create_access_token

def mint_token(username: str, role: str, tenant_id: int = 1) -> str:
    return create_access_token(
        data={"sub": username, "role": role, "tenantId": tenant_id},
        expires_delta=timedelta(hours=2)
    )

TOKEN_SUPER = mint_token("superadmin", "SuperAdmin", 1)
TOKEN_T1 = mint_token("elsea", "TenantAdmin", 1)
TOKEN_T3 = mint_token("sentinelx", "TenantAdmin", 3)
TOKEN_ANALYST = mint_token("secops_analyst_test@enterprise.corp", "Analyst", 1)

def run_http_benchmark(name: str, url: str, headers: dict = None, total_requests: int = 500, concurrency: int = 25):
    latencies = []
    errors = 0
    status_codes = {}

    def fetch_one(_):
        t0 = time.perf_counter()
        try:
            r = requests.get(url, headers=headers, timeout=5, verify=False)
            dt = (time.perf_counter() - t0) * 1000.0  # ms
            return dt, r.status_code, None
        except Exception as e:
            dt = (time.perf_counter() - t0) * 1000.0
            return dt, 0, str(e)

    start_wall = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        results = list(executor.map(fetch_one, range(total_requests)))
    total_time = time.perf_counter() - start_wall

    for dt, code, err in results:
        latencies.append(dt)
        status_codes[code] = status_codes.get(code, 0) + 1
        if code not in (200, 201, 204):
            errors += 1

    latencies.sort()
    avg_lat = statistics.mean(latencies)
    p50 = statistics.median(latencies)
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]
    rps = total_requests / total_time
    err_rate = (errors / total_requests) * 100.0

    print(f"\n================================================================================")
    print(f"  BENCHMARK: {name}")
    print(f"================================================================================")
    print(f"  URL:            {url}")
    print(f"  Requests:       {total_requests} (Concurrency: {concurrency})")
    print(f"  Total Duration: {total_time:.3f} s")
    print(f"  Throughput:     {rps:.2f} RPS")
    print(f"  Latencies (ms): Avg={avg_lat:.2f}ms | p50={p50:.2f}ms | p95={p95:.2f}ms | p99={p99:.2f}ms")
    print(f"  Min/Max (ms):   Min={latencies[0]:.2f}ms | Max={latencies[-1]:.2f}ms")
    print(f"  Error Rate:     {err_rate:.2f}% (Errors: {errors}, Statuses: {status_codes})")

    return {
        "name": name,
        "rps": rps,
        "avg_ms": avg_lat,
        "p50_ms": p50,
        "p95_ms": p95,
        "p99_ms": p99,
        "error_rate": err_rate,
        "total_requests": total_requests
    }

def benchmark_concurrent_tenant_isolation(total_rounds: int = 100, concurrency: int = 20):
    print(f"\n================================================================================")
    print(f"  CONCURRENT MULTI-TENANT ISOLATION BENCHMARK ({total_rounds} dual queries)")
    print(f"================================================================================")

    leaks = 0
    starvation_t1 = 0
    starvation_t3 = 0

    h_t1 = {"Authorization": f"Bearer {TOKEN_T1}"}
    h_t3 = {"Authorization": f"Bearer {TOKEN_T3}"}

    def verify_pair(round_id):
        r1 = requests.get(f"{API_BASE}/api/v2/soar/playbooks", headers=h_t1, timeout=5)
        r3 = requests.get(f"{API_BASE}/api/v2/soar/playbooks", headers=h_t3, timeout=5)

        round_leaks = 0
        if r1.status_code == 200 and r3.status_code == 200:
            leak1 = any(p.get("TenantId") == 3 for p in r1.json())
            leak3 = any(p.get("TenantId") == 1 for p in r3.json())
            if leak1 or leak3:
                round_leaks += 1
        return round_leaks, r1.status_code, r3.status_code

    t0 = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        outcomes = list(executor.map(verify_pair, range(total_rounds)))
    duration = time.perf_counter() - t0

    for l_cnt, c1, c3 in outcomes:
        leaks += l_cnt
        if c1 != 200: starvation_t1 += 1
        if c3 != 200: starvation_t3 += 1

    print(f"  Duration:         {duration:.3f} s ({(total_rounds*2)/duration:.2f} tenant queries/s)")
    print(f"  Cross-Tenant Leaks: {leaks} (Expected: 0)")
    print(f"  Tenant 1 Success:   {total_rounds - starvation_t1}/{total_rounds}")
    print(f"  Tenant 3 Success:   {total_rounds - starvation_t3}/{total_rounds}")
    print(f"  Isolation Verdict:  {'100% ISOLATED (PASS)' if leaks == 0 else 'LEAK DETECTED (FAIL)'}")

    return {
        "rounds": total_rounds,
        "leaks": leaks,
        "isolated": leaks == 0,
        "rate": (total_rounds * 2) / duration
    }

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    summary = []
    # 1. Unauthenticated Health Endpoint
    summary.append(run_http_benchmark("FastAPI Health Check (Unauthenticated)", f"{API_BASE}/api/health", total_requests=500, concurrency=25))

    # 2. Agent Gateway Health Check
    summary.append(run_http_benchmark("Agent Gateway Health Check (Port 8005)", f"{GATEWAY_BASE}/api/health", total_requests=500, concurrency=25))

    # 3. Authenticated SOAR Playbook Listing (DB Query + JWT Auth)
    h_auth = {"Authorization": f"Bearer {TOKEN_T1}"}
    summary.append(run_http_benchmark("Authenticated SOAR Playbooks (JWT + DB Join)", f"{API_BASE}/api/v2/soar/playbooks", headers=h_auth, total_requests=400, concurrency=20))

    # 4. Authenticated Notification Query
    summary.append(run_http_benchmark("Authenticated Notifications Query", f"{API_BASE}/api/notifications", headers=h_auth, total_requests=400, concurrency=20))

    # 5. Frontend React Assets (Static Nginx)
    try:
        summary.append(run_http_benchmark("Frontend Web Bundle", f"http://watch-sec-frontend:80/", total_requests=300, concurrency=15))
    except Exception as e:
        print(f"Frontend bench skipped: {e}")

    # 6. Multi-Tenant Isolation under concurrency
    iso_result = benchmark_concurrent_tenant_isolation(total_rounds=150, concurrency=20)

    # Auth overhead calculation:
    health_p50 = summary[0]["p50_ms"]
    auth_p50 = summary[2]["p50_ms"]
    auth_overhead_ms = auth_p50 - health_p50
    print(f"\n================================================================================")
    print(f"  AUTHENTICATION OVERHEAD ANALYSIS")
    print(f"================================================================================")
    print(f"  Unauthenticated Baseline Latency (p50): {health_p50:.2f} ms")
    print(f"  Authenticated + Scoped Query (p50):     {auth_p50:.2f} ms")
    print(f"  Net Auth & Scope Processing Delta:      {auth_overhead_ms:.2f} ms")

