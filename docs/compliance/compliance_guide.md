# Monitorix Compliance & Privacy Framework

This document outlines the technical and procedural controls that ensure Monitorix remains compliant with global regulatory standards.

## 1. GDPR Compliance (EU)
- **Data Minimization**: Only essential security telemetry is collected. Non-security related activity is excluded by policy.
- **Right to be Forgotten**: Admins can execute a Data Subject Request (DSR) to permanently purge all data associated with a specific agent.
- **Automated Retention**: Data is automatically purged after 90 days (configurable by tenant) via the `maintenance` worker.

## 2. HIPAA Readiness (Healthcare)
- **Encryption-at-Rest**: All forensic screenshots and OCR logs are encrypted using **AES-256 (Fernet)** before storage.
- **Audit Logging**: Every access to sensitive PHI-related forensic data is logged in the `AuditLogs` table with actor and timestamp.
- **Access Control**: Strict Role-Based Access Control (RBAC) ensures only authorized personnel can view forensic telemetry.

## 3. SOC2 & ISO 27001 Alignment
- **Immutable Audit Trails**: Administrative actions are captured in a tamper-evident audit trail, exportable via the `/api/audit/export` endpoint.
- **Infrastructure Security**: Deployed using hardened multi-stage Docker containers and zero-trust Kubernetes NetworkPolicies.
- **Vulnerability ManagementCenter**: Integrated patching and status tracking provide evidence of continuous security maintenance.

## 4. Encryption Standards
| Layer | Protocol | Implementation |
| :--- | :--- | :--- |
| **Data-in-Transit** | TLS 1.3 | Enforced via Nginx Gateway and mTLS |
| **Data-at-Rest** | AES-256 | Implemented in Backend and Agent Cache |
| **Database** | TDE | Supported via managed RDS/Cloud SQL instances |
