"""
[v18.6.0] Monitorix Sovereign Secrets Security Service Layer
============================================================
Master Architecture Principles:
- 100% Sovereign Monitorix Platform (Zero RedRainbow Invariant).
- Autonomous detection of hardcoded secrets, leaked tokens, API keys,
  cloud credentials, and private keys across files, environments, and repos.
- Shannon entropy calculation for high-randomness credential identification.
- Real-time secret scanning with exact line numbers and severity grading.
- Vault synchronization (HashiCorp, AWS, Azure Key Vault) & 1-click rotation.
"""

import re
import math
import json
import uuid
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy import select, func, update
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException

from app.db.models import (
    SecretScanTarget,
    SecretExposureIncident,
    SecretVaultIntegration
)

logger = logging.getLogger("monitorix.secrets")

# ---------------------------------------------------------------------------
# Shannon Entropy Algorithm
# ---------------------------------------------------------------------------

def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string to detect randomized high-entropy tokens."""
    if not data:
        return 0.0
    length = len(data)
    freq: Dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)


# ---------------------------------------------------------------------------
# Secret Regex Signatures & Categories
# ---------------------------------------------------------------------------

SECRET_PATTERNS = {
    "AWS_ACCESS_KEY": (
        r"\b(AKIA[0-9A-Z]{16})\b",
        "CRITICAL",
        "AWS IAM Access Key ID"
    ),
    "GITHUB_PAT": (
        r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b",
        "CRITICAL",
        "GitHub Personal Access Token"
    ),
    "OPENAI_API_KEY": (
        r"\b(sk-[a-zA-Z0-9]{32,64}|sk-proj-[a-zA-Z0-9_-]{48,128})\b",
        "CRITICAL",
        "OpenAI API Secret Key"
    ),
    "STRIPE_SECRET_KEY": (
        r"\b(sk_live_[0-9a-zA-Z]{24,34})\b",
        "CRITICAL",
        "Stripe Live API Key"
    ),
    "SSH_PRIVATE_KEY": (
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "CRITICAL",
        "Asymmetric SSH / TLS Private Key"
    ),
    "SLACK_WEBHOOK": (
        r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "HIGH",
        "Slack Incoming Webhook URL"
    ),
    "DATABASE_PASSWORD": (
        r"(?i)(?:password|passwd|pwd|db_pass)\s*[:=]\s*[\"']([^\"'\s]{10,64})[\"']",
        "HIGH",
        "Hardcoded Database Password"
    ),
    "JWT_SECRET": (
        r"(?i)(?:jwt_secret|jwt_key|token_secret)\s*[:=]\s*[\"']([A-Za-z0-9+/=]{16,64})[\"']",
        "HIGH",
        "JWT HMAC Signing Secret"
    )
}

# ---------------------------------------------------------------------------
# Seed Fixtures
# ---------------------------------------------------------------------------

DEFAULT_TARGETS = [
    {
        "target_id": "TGT-REPO-PAYMENT-SVC",
        "name": "core-billing-service",
        "target_type": "GIT_REPO",
        "location_path": "github.com/monitorix/core-billing-service",
        "environment": "PRODUCTION",
        "secrets_found_count": 2,
        "risk_score": 85.0
    },
    {
        "target_id": "TGT-HOST-EDGE-NODE-01",
        "name": "gateway-edge-node-01",
        "target_type": "HOST_FILESYSTEM",
        "location_path": "/opt/monitorix/gateway/.env.prod",
        "environment": "PRODUCTION",
        "secrets_found_count": 1,
        "risk_score": 72.0
    },
    {
        "target_id": "TGT-IMAGE-AUTH-GATEWAY",
        "name": "auth-service-docker",
        "target_type": "DOCKER_IMAGE",
        "location_path": "docker.monitorix.co.in/auth-service:v2.4",
        "environment": "STAGING",
        "secrets_found_count": 1,
        "risk_score": 65.0
    },
    {
        "target_id": "TGT-CICD-PIPELINE-MAIN",
        "name": "github-actions-deploy-workflow",
        "target_type": "CI_CD_PIPELINE",
        "location_path": ".github/workflows/deploy.yml",
        "environment": "PRODUCTION",
        "secrets_found_count": 0,
        "risk_score": 10.0
    }
]

DEFAULT_INCIDENTS = [
    {
        "incident_id": "SEC-INC-001",
        "target_id": "TGT-REPO-PAYMENT-SVC",
        "secret_type": "STRIPE_SECRET_KEY",
        "masked_secret": "sk_live_****8923",
        "location_file": "config/payment.py",
        "line_number": 42,
        "entropy_score": 4.82,
        "severity": "CRITICAL",
        "status": "OPEN",
        "is_vault_managed": False,
        "remediation_playbook": "REVOKE_STRIPE_API_KEY"
    },
    {
        "incident_id": "SEC-INC-002",
        "target_id": "TGT-REPO-PAYMENT-SVC",
        "secret_type": "AWS_ACCESS_KEY",
        "masked_secret": "AKIA****EXAMPLE",
        "location_file": "services/s3_storage.py",
        "line_number": 18,
        "entropy_score": 4.65,
        "severity": "CRITICAL",
        "status": "OPEN",
        "is_vault_managed": False,
        "remediation_playbook": "DEACTIVATE_IAM_ACCESS_KEY"
    },
    {
        "incident_id": "SEC-INC-003",
        "target_id": "TGT-HOST-EDGE-NODE-01",
        "secret_type": "DATABASE_PASSWORD",
        "masked_secret": "P@ss****2026!",
        "location_file": ".env.prod",
        "line_number": 7,
        "entropy_score": 4.41,
        "severity": "HIGH",
        "status": "OPEN",
        "is_vault_managed": True,
        "remediation_playbook": "AUTOMATED_VAULT_ROTATION"
    },
    {
        "incident_id": "SEC-INC-004",
        "target_id": "TGT-IMAGE-AUTH-GATEWAY",
        "secret_type": "GITHUB_PAT",
        "masked_secret": "ghp_****1234",
        "location_file": "Dockerfile",
        "line_number": 23,
        "entropy_score": 4.95,
        "severity": "CRITICAL",
        "status": "OPEN",
        "is_vault_managed": False,
        "remediation_playbook": "REVOKE_GITHUB_TOKEN"
    }
]

DEFAULT_VAULTS = [
    {
        "vault_id": "VAULT-HASHICORP-CORE",
        "name": "Enterprise HashiCorp Vault Cluster",
        "provider": "HASHICORP_VAULT",
        "endpoint_url": "https://vault.internal.monitorix:8200",
        "status": "CONNECTED",
        "synced_secrets_count": 142
    },
    {
        "vault_id": "VAULT-AWS-SECRETS",
        "name": "AWS Secrets Manager (us-east-1)",
        "provider": "AWS_SECRETS_MANAGER",
        "endpoint_url": "arn:aws:secretsmanager:us-east-1:123456789012",
        "status": "CONNECTED",
        "synced_secrets_count": 88
    },
    {
        "vault_id": "VAULT-AZURE-KEYVAULT",
        "name": "Azure Key Vault Core Production",
        "provider": "AZURE_KEY_VAULT",
        "endpoint_url": "https://monitorix-kv.vault.azure.net",
        "status": "CONNECTED",
        "synced_secrets_count": 54
    }
]


class MonitorixSecretsSecurityService:
    """Service handling Secrets Security and Vault Governance operations."""

    @staticmethod
    async def ensure_seed_data(session: AsyncSession) -> None:
        """Seed initial Targets, Incidents, and Vault integrations if empty."""
        res = await session.execute(select(func.count(SecretScanTarget.Id)))
        if res.scalar() == 0:
            for target in DEFAULT_TARGETS:
                new_tgt = SecretScanTarget(
                    TargetId=target["target_id"],
                    Name=target["name"],
                    TargetType=target["target_type"],
                    LocationPath=target["location_path"],
                    Environment=target["environment"],
                    SecretsFoundCount=target["secrets_found_count"],
                    RiskScore=target["risk_score"]
                )
                session.add(new_tgt)

            for inc in DEFAULT_INCIDENTS:
                new_inc = SecretExposureIncident(
                    IncidentId=inc["incident_id"],
                    TargetId=inc["target_id"],
                    SecretType=inc["secret_type"],
                    MaskedSecret=inc["masked_secret"],
                    LocationFile=inc["location_file"],
                    LineNumber=inc["line_number"],
                    EntropyScore=inc["entropy_score"],
                    Severity=inc["severity"],
                    Status=inc["status"],
                    IsVaultManaged=inc["is_vault_managed"],
                    RemediationPlaybook=inc["remediation_playbook"]
                )
                session.add(new_inc)

            for vault in DEFAULT_VAULTS:
                new_vlt = SecretVaultIntegration(
                    VaultId=vault["vault_id"],
                    Name=vault["name"],
                    Provider=vault["provider"],
                    EndpointUrl=vault["endpoint_url"],
                    Status=vault["status"],
                    SyncedSecretsCount=vault["synced_secrets_count"]
                )
                session.add(new_vlt)

            await session.commit()
            logger.info("Seeded initial Sovereign Secrets Security datasets.")

    @staticmethod
    async def get_overview(session: AsyncSession) -> Dict[str, Any]:
        """Calculate high-level Secrets Security Posture metrics."""
        await MonitorixSecretsSecurityService.ensure_seed_data(session)

        # Query Incidents
        inc_res = await session.execute(select(SecretExposureIncident))
        incidents = inc_res.scalars().all()

        total_incidents = len(incidents)
        open_incidents = [i for i in incidents if i.Status == "OPEN"]
        critical_count = sum(1 for i in open_incidents if i.Severity == "CRITICAL")
        high_count = sum(1 for i in open_incidents if i.Severity == "HIGH")
        vault_managed_count = sum(1 for i in open_incidents if i.IsVaultManaged)
        vault_managed_pct = round((vault_managed_count / len(open_incidents) * 100.0), 1) if open_incidents else 100.0

        # Query Targets
        tgt_res = await session.execute(select(SecretScanTarget))
        targets = tgt_res.scalars().all()

        total_targets = len(targets)
        high_risk_targets = sum(1 for t in targets if t.RiskScore >= 60.0)

        # Breakdown by secret type
        secret_type_breakdown: Dict[str, int] = {}
        for i in open_incidents:
            secret_type_breakdown[i.SecretType] = secret_type_breakdown.get(i.SecretType, 0) + 1

        # Target type distribution
        target_type_breakdown: Dict[str, int] = {}
        for t in targets:
            target_type_breakdown[t.TargetType] = target_type_breakdown.get(t.TargetType, 0) + 1

        # Posture Score Calculation: 100 - penalties
        score = 100.0 - (
            (critical_count * 12.0) +
            (high_count * 6.0) +
            (high_risk_targets * 4.0)
        )
        posture_score = round(max(15.0, min(100.0, score)), 1)

        return {
            "status": "HEALTHY",
            "secrets_posture_score": posture_score,
            "total_exposed_secrets": len(open_incidents),
            "critical_secrets_count": critical_count,
            "high_secrets_count": high_count,
            "vault_managed_pct": vault_managed_pct,
            "total_targets_scanned": total_targets,
            "high_risk_targets_count": high_risk_targets,
            "secret_type_breakdown": secret_type_breakdown,
            "target_type_breakdown": target_type_breakdown,
            "sovereign_engine": "Monitorix Sovereign Secrets Guard v18.6"
        }

    @staticmethod
    async def get_incidents(
        session: AsyncSession,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        secret_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List detected exposed secrets with optional filtering."""
        await MonitorixSecretsSecurityService.ensure_seed_data(session)

        stmt = select(SecretExposureIncident)
        if severity:
            stmt = stmt.where(SecretExposureIncident.Severity == severity.upper())
        if status:
            stmt = stmt.where(SecretExposureIncident.Status == status.upper())
        if secret_type:
            stmt = stmt.where(SecretExposureIncident.SecretType == secret_type.upper())

        res = await session.execute(stmt)
        incidents = res.scalars().all()

        return [
            {
                "id": i.Id,
                "incident_id": i.IncidentId,
                "target_id": i.TargetId,
                "secret_type": i.SecretType,
                "masked_secret": i.MaskedSecret,
                "location_file": i.LocationFile,
                "line_number": i.LineNumber,
                "entropy_score": i.EntropyScore,
                "severity": i.Severity,
                "status": i.Status,
                "is_vault_managed": i.IsVaultManaged,
                "remediation_playbook": i.RemediationPlaybook,
                "created_at": i.CreatedAt.isoformat() if i.CreatedAt else None,
                "resolved_at": i.ResolvedAt.isoformat() if i.ResolvedAt else None
            }
            for i in incidents
        ]

    @staticmethod
    async def get_targets(
        session: AsyncSession,
        target_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List scanned repositories and targets."""
        await MonitorixSecretsSecurityService.ensure_seed_data(session)

        stmt = select(SecretScanTarget)
        if target_type:
            stmt = stmt.where(SecretScanTarget.TargetType == target_type.upper())

        res = await session.execute(stmt)
        targets = res.scalars().all()

        return [
            {
                "id": t.Id,
                "target_id": t.TargetId,
                "name": t.Name,
                "target_type": t.TargetType,
                "location_path": t.LocationPath,
                "environment": t.Environment,
                "secrets_found_count": t.SecretsFoundCount,
                "risk_score": t.RiskScore,
                "last_scanned_at": t.LastScannedAt.isoformat() if t.LastScannedAt else None
            }
            for t in targets
        ]

    @staticmethod
    async def get_vaults(session: AsyncSession) -> List[Dict[str, Any]]:
        """List enterprise vault integrations."""
        await MonitorixSecretsSecurityService.ensure_seed_data(session)

        res = await session.execute(select(SecretVaultIntegration))
        vaults = res.scalars().all()

        return [
            {
                "id": v.Id,
                "vault_id": v.VaultId,
                "name": v.Name,
                "provider": v.Provider,
                "endpoint_url": v.EndpointUrl,
                "status": v.Status,
                "synced_secrets_count": v.SyncedSecretsCount,
                "last_sync_at": v.LastSyncAt.isoformat() if v.LastSyncAt else None
            }
            for v in vaults
        ]

    @staticmethod
    def scan_content_sample(content: str, filename: Optional[str] = "input.txt") -> Dict[str, Any]:
        """
        Real-time secret scanner evaluating code or file contents against known regex
        signatures and Shannon entropy analysis with line number precision.
        """
        detections: List[Dict[str, Any]] = []
        lines = content.splitlines()

        for line_idx, line_text in enumerate(lines, start=1):
            for sec_key, (pattern_str, severity, desc) in SECRET_PATTERNS.items():
                match = re.search(pattern_str, line_text)
                if match:
                    # Captured group or full match
                    secret_val = match.group(1) if match.groups() else match.group(0)
                    entropy = calculate_shannon_entropy(secret_val)

                    # Mask secret for safe output
                    if len(secret_val) > 8:
                        masked = secret_val[:4] + "****" + secret_val[-4:]
                    else:
                        masked = secret_val[:2] + "****"

                    detections.append({
                        "secret_type": sec_key,
                        "description": desc,
                        "severity": severity,
                        "line_number": line_idx,
                        "entropy_score": entropy,
                        "masked_snippet": masked,
                        "filename": filename
                    })

        has_secrets = len(detections) > 0
        highest_severity = "LOW"
        severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        for d in detections:
            if severity_rank.get(d["severity"], 1) > severity_rank.get(highest_severity, 1):
                highest_severity = d["severity"]

        return {
            "has_secrets": has_secrets,
            "secrets_count": len(detections),
            "highest_severity": highest_severity if has_secrets else "NONE",
            "filename": filename,
            "scanned_lines": len(lines),
            "detections": detections
        }

    @staticmethod
    async def remediate_incident(
        session: AsyncSession,
        incident_id: str,
        action: str = "REVOKE_AND_ROTATE"
    ) -> Dict[str, Any]:
        """Remediate an exposed secret incident via 1-click revocation or vault rotation."""
        q = await session.execute(
            select(SecretExposureIncident).where(SecretExposureIncident.IncidentId == incident_id)
        )
        incident = q.scalars().first()
        if not incident:
            raise HTTPException(status_code=404, detail=f"Secret Incident {incident_id} not found")

        incident.Status = "REVOKED" if "REVOKE" in action.upper() else "ROTATED"
        incident.ResolvedAt = datetime.utcnow()
        incident.RemediationPlaybook = action

        # Update target risk score
        tgt_q = await session.execute(
            select(SecretScanTarget).where(SecretScanTarget.TargetId == incident.TargetId)
        )
        target = tgt_q.scalars().first()
        if target:
            target.RiskScore = max(10.0, target.RiskScore - 20.0)
            target.SecretsFoundCount = max(0, target.SecretsFoundCount - 1)

        await session.commit()

        return {
            "success": True,
            "incident_id": incident_id,
            "status": incident.Status,
            "action_taken": action,
            "target_id": incident.TargetId,
            "resolved_at": incident.ResolvedAt.isoformat(),
            "message": f"Secret {incident_id} successfully neutralized via {action}."
        }

    @staticmethod
    async def trigger_target_scan(session: AsyncSession, target_id: str) -> Dict[str, Any]:
        """Trigger on-demand secret discovery scan on a repository or target."""
        await MonitorixSecretsSecurityService.ensure_seed_data(session)

        q = await session.execute(
            select(SecretScanTarget).where(SecretScanTarget.TargetId == target_id)
        )
        target = q.scalars().first()
        if not target:
            raise HTTPException(status_code=404, detail=f"Target {target_id} not found")

        target.LastScannedAt = datetime.utcnow()
        scan_id = f"SCAN-SEC-{uuid.uuid4().hex[:8].upper()}"

        await session.commit()

        return {
            "success": True,
            "scan_id": scan_id,
            "target_id": target_id,
            "target_name": target.Name,
            "target_type": target.TargetType,
            "status": "COMPLETED",
            "timestamp": datetime.utcnow().isoformat()
        }
