# Monitorix Enterprise — Central Backend & Security Engine

**Enterprise Level 4: Sovereign Autonomous Cybersecurity, SIEM & Extended Detection and Response (XDR)**

Monitorix Central Backend is an enterprise-scale distributed security engine built with Python 3.11, FastAPI, and asynchronous streaming architectures. It orchestrates real-time telemetry ingestion, correlation pipelines, autonomous containment actions, and 32 global regulatory compliance standards across heterogeneous enterprise infrastructure.

---

## 1. Core Architecture & Microservices

The backend operates as a coordinated multi-container cluster:

| Service | Container / Port | Technologies | Operational Role |
| :--- | :--- | :--- | :--- |
| **Central Backend API** | `watch-sec-backend` (Port 8010) | FastAPI, Uvicorn, SQLAlchemy | Core REST & WebSocket API, tenant scoping, policy distribution, auth, and analytics. |
| **Agent gRPC Gateway** | `watch-sec-grpc-gateway` (Port 50051) | gRPC, Protobuf, AsyncIO | High-throughput bi-directional event stream for Windows minifilters and Linux eBPF probes. |
| **Relational ACID DB** | `sentinel_postgres` (Port 5432) | PostgreSQL 15 | Sovereign tenant isolation, agent registry, policies, users, hash banks, and audit ledgers. |
| **Columnar SIEM Store** | `sentinel_clickhouse` (Port 8123) | ClickHouse Columnar DB | High-velocity storage and millisecond query execution for billions of raw security event logs. |
| **Activity Event Lake** | `sentinel_mongodb` (Port 27017) | MongoDB 6.0 | Raw process spawns, network socket telemetry, clipboard snapshots, and DLP inspection logs. |
| **Session Cache & Pub/Sub** | `sentinel_redis` (Port 6379) | Redis 7 | In-memory token revocation, agent rate limiters, active connection tracking, and pub/sub messaging. |
| **Event Streaming Bus** | `watch-sec-kafka` (Port 9092) | Apache Kafka 7.3.2 & Zookeeper | Partitioned message bus for high-volume EDR log ingest with zero message loss guarantee. |
| **Forensic Vault** | `sentinel_minio` (Port 9000/9001) | MinIO (S3 API) | Cryptographically sealed memory dumps, PCAP network captures, and executable detonation logs. |
| **Vector Neural Store** | `sentinel_qdrant` (Port 6333/6334) | Qdrant Vector DB | High-dimensional embedding storage for AI Security Copilot and semantic incident clustering. |
| **Background Task Workers**| `watch-sec-celery` & Kafka Consumer | Celery, Redis, aiokafka | Asynchronous vulnerability scanning, malware signature indexing, and SOAR execution. |

---

## 2. Global Compliance Center & Regulatory Frameworks

The backend includes a native, modular compliance engine (`app/compliance/`) supporting **32 Statutory Regulations**:
- **Statutory Frameworks**: DPDP India 2023, EU GDPR (Art. 32/44), US HIPAA, PCI-DSS v4.0, NIST SP 800-53 Rev. 5, ISO/IEC 27001:2022, SOC 2 Type II, RBI Cyber Security Framework, FedRAMP High, Saudi NCA ECC-1:2018, UAE NESA, CCPA/CPRA, Brazil LGPD, Canada PIPEDA, Singapore PDPA, etc.
- **Mathematical Checksum Validation**:
  - India Aadhaar (Verhoeff Dihedral D8 Checksum)
  - Canada SIN & Saudi National ID (Luhn Modulo 10 Algorithm)
  - UK NHS, Brazil CPF, New Zealand IRD, Chile RUT (Modulo 11 Weighted Algorithms)
  - Switzerland AHV/AVS (EAN-13 Algorithm)
- **Continuous Posture Derivation**: Controls evaluated against live database records, agent configs, and encryption states with tamper-evident SHA-256 evidence logging.
- **Accreditation**: Verified via 83/83 passed acceptance tests in `test_global_compliance_acceptance.py`.

---

## 3. Real-Time Telemetry & Zero Mock Data Standard

- All metrics exposed via `/api/dashboard/stats`, `/api/system/health`, `/api/agents`, `/v2/soc/dashboard`, `/v2/dlp/violations`, and `/v2/ueba/baselines` are computed directly from operational database tables and running processes.
- Zero synthetic sensor arrays or pseudo-random fallbacks exist in the platform.
- Live agent connections stream via Socket.IO events (`agent_registered`, `agent_disconnected`, `agent_status_changed`, `agent_list_update`).

---

## 4. Quick Start & Operational Commands

### Docker Compose Orchestration
```bash
# Navigate to the backend directory
cd /opt/projects/monitorix/watch-sec-python

# Start the full microservices cluster
docker compose up -d

# Check cluster health
docker compose ps
```

### Running Acceptance & Compliance Verification Suites
```bash
# Run 83 Global Compliance Acceptance Tests
python3 /opt/projects/monitorix/test_global_compliance_acceptance.py

# Run Consolidated 21 Enterprise Regression Suites
python3 /opt/projects/monitorix/run_consolidated_21_acceptance_suites.py
```

---

## 5. Security & Sovereignty Standards

- **Air-Gapped Invariant**: Completely functional without external internet connectivity.
- **Offline Cryptographic Licensing**: Verified using Ed25519 digital signatures (`license/customer-license.json`).
- **Data Protection**: Secrets encrypted via AES-256-GCM; passwords hashed via bcrypt.
- **Zero Third-Party Vendor Dependencies**: 100% sovereign Monitorix IP without RedRainbow or foreign SaaS ties.
