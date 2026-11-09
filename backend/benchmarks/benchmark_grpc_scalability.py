"""
Monitorix Enterprise — Phase 3B gRPC Ingress Scalability Benchmark
=================================================================
Runs controlled concurrent mTLS streams through watch-sec-load-balancer:50051
across multiple concurrency tiers (100, 250, 500, 750, 1000 streams).
Measures:
  - Events/sec throughput
  - Latency percentiles (p50, p95, p99)
  - TLS handshake time
  - Replica distribution (grpc-gateway-1, 2, 3)
  - Error rate / Dropped events
"""

import os
import sys
import glob
import time
import json
import asyncio
import numpy as np
import grpc

from app import telemetry_pb2, telemetry_pb2_grpc

TARGET_LB = os.getenv("GRPC_LB", "watch-sec-load-balancer:50051")
CERT_BASE = os.getenv("CERT_BASE", "/app/storage/agent_certs")

def load_enrolled_agent_credentials():
    """Loads all valid client certificates and private keys from storage."""
    agents = []
    agent_dirs = [d for d in glob.glob(f"{CERT_BASE}/*") if os.path.isdir(d)]
    
    for adir in agent_dirs:
        ca_p = os.path.join(adir, "ca_chain.pem")
        crt_p = os.path.join(adir, "agent.crt")
        key_p = os.path.join(adir, "agent.key")
        
        if os.path.exists(ca_p) and os.path.exists(crt_p) and os.path.exists(key_p):
            agent_id = os.path.basename(adir)
            try:
                with open(ca_p, "rb") as f: ca_b = f.read()
                with open(crt_p, "rb") as f: crt_b = f.read()
                with open(key_p, "rb") as f: key_b = f.read()
                agents.append({
                    "agent_id": agent_id,
                    "ca": ca_b,
                    "cert": crt_b,
                    "key": key_b
                })
            except Exception:
                continue

    if not agents:
        raise RuntimeError(f"No valid enrolled agent certificates found in {CERT_BASE}")
    print(f"[*] Loaded {len(agents)} enrolled agent identities for mTLS load testing.")
    return agents

async def run_single_stream(agent_info, events_per_stream=5):
    """Executes a single mTLS client-streaming connection and sends events."""
    creds = grpc.ssl_channel_credentials(
        root_certificates=agent_info["ca"],
        private_key=agent_info["key"],
        certificate_chain=agent_info["cert"]
    )
    
    channel_opts = [
        ("grpc.ssl_target_name_override", "grpc-gateway"),
        ("grpc.max_receive_message_length", 100 * 1024 * 1024),
        ("grpc.max_send_message_length", 100 * 1024 * 1024),
    ]

    t_start = time.perf_counter()
    handshake_time = 0.0
    replica_id = "unknown"
    events_sent = 0
    status = "SUCCESS"
    err_msg = ""

    try:
        t0 = time.perf_counter()
        async with grpc.aio.secure_channel(TARGET_LB, creds, options=channel_opts) as channel:
            # Measure channel readiness / TLS handshake
            await asyncio.wait_for(channel.channel_ready(), timeout=8.0)
            handshake_time = (time.perf_counter() - t0) * 1000

            stub = telemetry_pb2_grpc.TelemetryGatewayStub(channel)

            async def generate_telemetry():
                nonlocal events_sent
                for seq in range(events_per_stream):
                    payload = {
                        "seq": seq,
                        "process": "monitorix_bench.exe",
                        "pid": 4000 + seq,
                        "cpu": 1.5,
                        "timestamp": time.time()
                    }
                    yield telemetry_pb2.AgentEvent(
                        agent_id=agent_info["agent_id"],
                        tenant_id="1",
                        event_type="PROCESS_START",
                        payload=json.dumps(payload),
                        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    )
                    events_sent += 1

            t_rpc_start = time.perf_counter()
            response = await asyncio.wait_for(stub.StreamEvents(generate_telemetry()), timeout=15.0)
            total_duration = (time.perf_counter() - t_start) * 1000

            # Detect handling replica
            msg = response.message or ""
            for r in ["grpc-gateway-1", "grpc-gateway-2", "grpc-gateway-3"]:
                if r in msg:
                    replica_id = r
                    break

            return {
                "status": "SUCCESS" if response.success else "FAILED",
                "events_sent": events_sent,
                "events_processed": response.events_processed,
                "handshake_ms": handshake_time,
                "total_duration_ms": total_duration,
                "replica": replica_id,
                "error": None
            }

    except Exception as e:
        total_duration = (time.perf_counter() - t_start) * 1000
        return {
            "status": "ERROR",
            "events_sent": events_sent,
            "events_processed": 0,
            "handshake_ms": handshake_time,
            "total_duration_ms": total_duration,
            "replica": "failed",
            "error": str(e)
        }

async def benchmark_tier(agents, concurrency, events_per_stream=5):
    """Executes a load tier with exact concurrent streams."""
    print(f"\n>>> Running Tier: {concurrency} Concurrent Streams (Events/Stream: {events_per_stream}, Total Target Events: {concurrency * events_per_stream})")
    
    tasks = []
    num_agents = len(agents)
    t_start = time.perf_counter()

    for i in range(concurrency):
        agent = agents[i % num_agents]
        tasks.append(run_single_stream(agent, events_per_stream=events_per_stream))

    results = await asyncio.gather(*tasks, return_exceptions=False)
    elapsed_total = time.perf_counter() - t_start

    successful = [r for r in results if r["status"] == "SUCCESS"]
    failed = [r for r in results if r["status"] != "SUCCESS"]
    
    total_events = sum(r["events_processed"] for r in successful)
    throughput_eps = total_events / elapsed_total if elapsed_total > 0 else 0

    durations = [r["total_duration_ms"] for r in successful] if successful else [0]
    handshakes = [r["handshake_ms"] for r in successful if r["handshake_ms"] > 0] if successful else [0]

    replica_counts = {}
    for r in successful:
        rep = r["replica"]
        replica_counts[rep] = replica_counts.get(rep, 0) + 1

    p50 = float(np.percentile(durations, 50))
    p95 = float(np.percentile(durations, 95))
    p99 = float(np.percentile(durations, 99))
    p50_hs = float(np.percentile(handshakes, 50))
    p95_hs = float(np.percentile(handshakes, 95))

    metrics = {
        "concurrency": concurrency,
        "total_streams": concurrency,
        "successful_streams": len(successful),
        "failed_streams": len(failed),
        "total_events": total_events,
        "elapsed_sec": round(elapsed_total, 2),
        "throughput_eps": round(throughput_eps, 1),
        "latency_p50_ms": round(p50, 2),
        "latency_p95_ms": round(p95, 2),
        "latency_p99_ms": round(p99, 2),
        "handshake_p50_ms": round(p50_hs, 2),
        "handshake_p95_ms": round(p95_hs, 2),
        "replica_distribution": replica_counts,
        "error_samples": [r["error"] for r in failed[:3]] if failed else []
    }

    print(f"  [RESULT] Elapsed: {metrics['elapsed_sec']}s | Throughput: {metrics['throughput_eps']} eps")
    print(f"  [LATENCY] p50: {metrics['latency_p50_ms']}ms | p95: {metrics['latency_p95_ms']}ms | p99: {metrics['latency_p99_ms']}ms")
    print(f"  [HANDSHAKE] p50: {metrics['handshake_p50_ms']}ms | p95: {metrics['handshake_p95_ms']}ms")
    print(f"  [DISTRIBUTION] {replica_counts}")
    print(f"  [SUCCESS/FAIL] {len(successful)} OK / {len(failed)} Failed (Loss Rate: {(len(failed)/concurrency)*100:.1f}%)")
    
    return metrics

async def main():
    agents = load_enrolled_agent_credentials()
    
    tiers = [100, 250, 500, 750, 1000]
    all_metrics = []

    for tier in tiers:
        metrics = await benchmark_tier(agents, concurrency=tier, events_per_stream=5)
        all_metrics.append(metrics)
        # 2-second cooldown between tiers to prevent socket exhaustion
        await asyncio.sleep(2.0)

    # Evaluate 1500 tier safety: only if tier 1000 had 0 critical errors and reasonable latency
    tier_1000 = all_metrics[-1]
    if tier_1000["failed_streams"] / tier_1000["total_streams"] < 0.05:
        print("\n[*] Tier 1000 remained within safety limits. Proceeding to evaluate Tier 1500...")
        tier_1500 = await benchmark_tier(agents, concurrency=1500, events_per_stream=3)
        all_metrics.append(tier_1500)
    else:
        print("\n[!] Tier 1000 exceeded error threshold. Omitting Tier 1500 to protect node stability.")

    # Dump results JSON for reporting
    out_path = "/app/benchmarks/grpc_scalability_results.json"
    with open(out_path, "w") as f:
        json.dump(all_metrics, f, indent=2)
    print(f"\n[+] Full benchmark results saved to {out_path}")

if __name__ == "__main__":
    asyncio.run(main())

