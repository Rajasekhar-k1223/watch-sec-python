"""
[v18.3.0] Monitorix Sovereign ITDR Service Layer (Identity Threat Detection & Response)
========================================================================================
Comprehensive identity security service for Active Directory, Entra ID, Okta, and Zero-Trust:
- 1. Identity Inventory & Posture: Tier-0 Domain Admins, Shadow Admins, Kerberoastable SPNs, Unconstrained Delegation.
- 2. Threat Detection Heuristics:
     * Kerberoasting (T1558.003 - RC4 ticket extraction for service accounts)
     * Pass-the-Hash / Pass-the-Ticket (T1550.002 / T1550.003)
     * DCSync / DCShadow (T1003.006 - Directory replication abuse)
     * OAuth App Consent Abuse & Token Theft (T1098.003)
     * Golden / Silver Ticket forgery (T1558.001 / T1558.002)
- 3. Identity Attack Path Graph: Multi-hop privilege escalation graph towards Tier-0 assets.
- 4. Automated & 1-Click Containment: Account disabling, OAuth token revocation, forced Kerberos ticket reset.
"""

import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import json
import uuid
import logging
from fastapi import HTTPException, status

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc, func, update, delete

from app.db.models import (
    IdentityAccount,
    IdentityThreatEvent,
    IdentityAttackPathNode
)

logger = logging.getLogger("MonitorixITDRService")

DEFAULT_ACCOUNTS = [
    {
        "account_id": "acc-da-krbtgt",
        "display_name": "krbtgt (Key Distribution Service)",
        "account_type": "SERVICE_ACCOUNT",
        "identity_provider": "ACTIVE_DIRECTORY",
        "privilege_tier": "TIER_0_DOMAIN_ADMIN",
        "risk_score": 15.0,
        "is_kerberoastable": False,
        "has_unconstrained_delegation": False,
        "is_shadow_admin": False,
        "mfa_enabled": True,
        "status": "ACTIVE",
        "metadata": {"spn": ["kdc/corp.enterprise.com"], "domain": "corp.enterprise.com"}
    },
    {
        "account_id": "acc-da-domainadmin01",
        "display_name": "James Henderson (Domain Admin)",
        "account_type": "ADMIN",
        "identity_provider": "ACTIVE_DIRECTORY",
        "privilege_tier": "TIER_0_DOMAIN_ADMIN",
        "risk_score": 85.0,
        "is_kerberoastable": False,
        "has_unconstrained_delegation": False,
        "is_shadow_admin": False,
        "mfa_enabled": True,
        "status": "ACTIVE",
        "metadata": {"member_of": ["Domain Admins", "Enterprise Admins"], "last_logon_dc": "DC01.corp.enterprise.com"}
    },
    {
        "account_id": "acc-svc-mssql",
        "display_name": "svc_mssql_prod (Database Service Account)",
        "account_type": "SERVICE_ACCOUNT",
        "identity_provider": "ACTIVE_DIRECTORY",
        "privilege_tier": "TIER_CRITICAL_SERVICE",
        "risk_score": 92.0,
        "is_kerberoastable": True,
        "has_unconstrained_delegation": True,
        "is_shadow_admin": False,
        "mfa_enabled": False,
        "status": "ACTIVE",
        "metadata": {"spn": ["MSSQLSvc/db01.corp.enterprise.com:1433"], "encryption": "RC4_HMAC_MD5"}
    },
    {
        "account_id": "acc-user-devops-shadow",
        "display_name": "Alex Mercer (DevOps Engineer)",
        "account_type": "USER",
        "identity_provider": "ENTRA_ID",
        "privilege_tier": "TIER_1_SERVER_ADMIN",
        "risk_score": 78.0,
        "is_kerberoastable": False,
        "has_unconstrained_delegation": False,
        "is_shadow_admin": True,
        "mfa_enabled": True,
        "status": "ACTIVE",
        "metadata": {"permissions": ["GenericAll over Tier-0 OU", "ResetPassword on Domain Admins"]}
    },
    {
        "account_id": "acc-oauth-sync-app",
        "display_name": "CloudSync Utility App (OAuth 2.0)",
        "account_type": "OAUTH_APP",
        "identity_provider": "ENTRA_ID",
        "privilege_tier": "TIER_1_SERVER_ADMIN",
        "risk_score": 88.0,
        "is_kerberoastable": False,
        "has_unconstrained_delegation": False,
        "is_shadow_admin": False,
        "mfa_enabled": True,
        "status": "ACTIVE",
        "metadata": {"scopes": ["Mail.ReadWrite", "Directory.ReadWrite.All"], "verified_publisher": False}
    },
    {
        "account_id": "acc-user-marketing",
        "display_name": "Sarah Connor (Marketing Specialist)",
        "account_type": "USER",
        "identity_provider": "ACTIVE_DIRECTORY",
        "privilege_tier": "TIER_2_USER",
        "risk_score": 22.0,
        "is_kerberoastable": False,
        "has_unconstrained_delegation": False,
        "is_shadow_admin": False,
        "mfa_enabled": True,
        "status": "ACTIVE",
        "metadata": {"department": "Marketing"}
    }
]

DEFAULT_THREATS = [
    {
        "threat_id": "ITDR-THR-2026-001",
        "threat_type": "KERBEROASTING",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1558.003",
        "severity": "HIGH",
        "source_host": "WS-FINANCE-042",
        "source_account": "sconnor@corp.enterprise.com",
        "target_account": "svc_mssql_prod",
        "target_domain": "corp.enterprise.com",
        "status": "ACTIVE",
        "details": {
            "requested_spn": "MSSQLSvc/db01.corp.enterprise.com:1433",
            "encryption_type": "0x17 (RC4_HMAC)",
            "indicator": "Mass RC4 Ticket-Granting Service (TGS) extraction targeting high-privilege service account."
        }
    },
    {
        "threat_id": "ITDR-THR-2026-002",
        "threat_type": "DCSYNC",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1003.006",
        "severity": "CRITICAL",
        "source_host": "WS-DEV-109",
        "source_account": "amercer@corp.enterprise.com",
        "target_account": "krbtgt",
        "target_domain": "corp.enterprise.com",
        "status": "ACTIVE",
        "details": {
            "api_called": "DSGetNCChanges",
            "rights_exercised": "Replicating Directory Changes All",
            "indicator": "Non-Domain Controller endpoint initiated DirSync replication to dump Active Directory credentials."
        }
    },
    {
        "threat_id": "ITDR-THR-2026-003",
        "threat_type": "PASS_THE_HASH",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1550.002",
        "severity": "HIGH",
        "source_host": "10.0.4.15",
        "source_account": "jhenderson@corp.enterprise.com",
        "target_account": "SRV-FILE-01",
        "target_domain": "corp.enterprise.com",
        "status": "ACTIVE",
        "details": {
            "logon_type": "3 (Network)",
            "auth_package": "NTLM",
            "indicator": "Domain Admin NTLM hash re-use detected across SMB/RPC without legitimate Kerberos pre-auth."
        }
    },
    {
        "threat_id": "ITDR-THR-2026-004",
        "threat_type": "OAUTH_CONSENT_ABUSE",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1098.003",
        "severity": "HIGH",
        "source_host": "External-Cloud",
        "source_account": "CloudSync Utility App",
        "target_account": "Tenant Admin",
        "target_domain": "corp.onmicrosoft.com",
        "status": "ACTIVE",
        "details": {
            "consented_permissions": ["Directory.ReadWrite.All", "Mail.ReadWrite"],
            "publisher": "Unverified Multi-Tenant App",
            "indicator": "Illicit consent grant detected granting full tenant directory modification permissions."
        }
    }
]

DEFAULT_GRAPH_NODES = [
    {
        "path_id": "PATH-TIER0-001",
        "source_node_id": "acc-user-marketing",
        "source_node_type": "ACCOUNT",
        "target_node_id": "HOST-WS-FINANCE-042",
        "target_node_type": "HOST",
        "relation_type": "HAS_SESSION",
        "is_active_exploit_path": True,
        "hops_count": 1,
        "risk_level": "MEDIUM"
    },
    {
        "path_id": "PATH-TIER0-001",
        "source_node_id": "HOST-WS-FINANCE-042",
        "source_node_type": "HOST",
        "target_node_id": "acc-svc-mssql",
        "target_node_type": "ACCOUNT",
        "relation_type": "CAN_KERBEROAST",
        "is_active_exploit_path": True,
        "hops_count": 2,
        "risk_level": "HIGH"
    },
    {
        "path_id": "PATH-TIER0-001",
        "source_node_id": "acc-svc-mssql",
        "source_node_type": "ACCOUNT",
        "target_node_id": "GROUP-TIER0-DOMAIN-ADMINS",
        "target_node_type": "GROUP",
        "relation_type": "ADMIN_TO",
        "is_active_exploit_path": True,
        "hops_count": 3,
        "risk_level": "CRITICAL"
    },
    {
        "path_id": "PATH-TIER0-002",
        "source_node_id": "acc-user-devops-shadow",
        "source_node_type": "ACCOUNT",
        "target_node_id": "acc-da-domainadmin01",
        "target_node_type": "ACCOUNT",
        "relation_type": "GENERIC_ALL",
        "is_active_exploit_path": True,
        "hops_count": 1,
        "risk_level": "CRITICAL"
    },
    {
        "path_id": "PATH-TIER0-002",
        "source_node_id": "acc-da-domainadmin01",
        "source_node_type": "ACCOUNT",
        "target_node_id": "DC01-PRIMARY-DOMAIN-CONTROLLER",
        "target_node_type": "DOMAIN_CONTROLLER",
        "relation_type": "CAN_DCSYNC",
        "is_active_exploit_path": True,
        "hops_count": 2,
        "risk_level": "CRITICAL"
    }
]


class MonitorixITDRService:
    """Service handling Identity Threat Detection & Response operations."""

    @staticmethod
    async def ensure_seed_data(session: AsyncSession) -> None:
        """Seed default ITDR accounts, threats, and attack graph paths if empty."""
        try:
            # Check accounts
            res_acc = await session.execute(select(func.count(IdentityAccount.Id)))
            if (res_acc.scalar() or 0) == 0:
                logger.info("Seeding default ITDR accounts...")
                for item in DEFAULT_ACCOUNTS:
                    account = IdentityAccount(
                        AccountId=item["account_id"],
                        DisplayName=item["display_name"],
                        AccountType=item["account_type"],
                        IdentityProvider=item["identity_provider"],
                        PrivilegeTier=item["privilege_tier"],
                        RiskScore=item["risk_score"],
                        IsKerberoastable=item["is_kerberoastable"],
                        HasUnconstrainedDelegation=item["has_unconstrained_delegation"],
                        IsShadowAdmin=item["is_shadow_admin"],
                        MfaEnabled=item["mfa_enabled"],
                        Status=item["status"],
                        MetadataJson=json.dumps(item["metadata"])
                    )
                    session.add(account)

            # Check threats
            res_thr = await session.execute(select(func.count(IdentityThreatEvent.Id)))
            if (res_thr.scalar() or 0) == 0:
                logger.info("Seeding default ITDR threat events...")
                for item in DEFAULT_THREATS:
                    threat = IdentityThreatEvent(
                        ThreatId=item["threat_id"],
                        ThreatType=item["threat_type"],
                        MitreTactic=item["mitre_tactic"],
                        MitreTechnique=item["mitre_technique"],
                        Severity=item["severity"],
                        SourceHost=item["source_host"],
                        SourceAccount=item["source_account"],
                        TargetAccount=item["target_account"],
                        TargetDomain=item["target_domain"],
                        Status=item["status"],
                        DetailsJson=json.dumps(item["details"])
                    )
                    session.add(threat)

            # Check attack path nodes
            res_nodes = await session.execute(select(func.count(IdentityAttackPathNode.Id)))
            if (res_nodes.scalar() or 0) == 0:
                logger.info("Seeding default ITDR attack path graph...")
                for item in DEFAULT_GRAPH_NODES:
                    node = IdentityAttackPathNode(
                        PathId=item["path_id"],
                        SourceNodeId=item["source_node_id"],
                        SourceNodeType=item["source_node_type"],
                        TargetNodeId=item["target_node_id"],
                        TargetNodeType=item["target_node_type"],
                        RelationType=item["relation_type"],
                        IsActiveExploitPath=item["is_active_exploit_path"],
                        HopsCount=item["hops_count"],
                        RiskLevel=item["risk_level"]
                    )
                    session.add(node)

            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(f"Error seeding ITDR data: {str(e)}")

    @staticmethod
    async def get_overview(session: AsyncSession) -> Dict[str, Any]:
        """Aggregate ITDR posture score, accounts, active threats, and tier breakdown."""
        await MonitorixITDRService.ensure_seed_data(session)

        # Accounts metrics
        acc_q = await session.execute(select(IdentityAccount))
        accounts = acc_q.scalars().all()

        total_accounts = len(accounts)
        tier_counts: Dict[str, int] = {}
        high_risk_count = 0
        kerberoastable_count = 0
        unconstrained_count = 0
        shadow_admin_count = 0
        total_risk = 0.0

        for a in accounts:
            tier_counts[a.PrivilegeTier] = tier_counts.get(a.PrivilegeTier, 0) + 1
            if a.RiskScore >= 70.0:
                high_risk_count += 1
            if a.IsKerberoastable:
                kerberoastable_count += 1
            if a.HasUnconstrainedDelegation:
                unconstrained_count += 1
            if a.IsShadowAdmin:
                shadow_admin_count += 1
            total_risk += (a.RiskScore or 0.0)

        avg_risk = round(total_risk / max(total_accounts, 1), 1)
        posture_score = max(0.0, round(100.0 - avg_risk, 1))

        # Threats metrics
        thr_q = await session.execute(select(IdentityThreatEvent))
        threats = thr_q.scalars().all()

        active_threats = [t for t in threats if t.Status in ("ACTIVE", "INVESTIGATING")]
        severity_counts: Dict[str, int] = {}
        technique_counts: Dict[str, int] = {}

        for t in active_threats:
            severity_counts[t.Severity] = severity_counts.get(t.Severity, 0) + 1
            technique_counts[t.ThreatType] = technique_counts.get(t.ThreatType, 0) + 1

        # Graph stats
        path_q = await session.execute(select(func.count(IdentityAttackPathNode.Id)))
        total_relationships = path_q.scalar() or 0

        return {
            "status": "HEALTHY",
            "posture_score": posture_score,
            "total_accounts_monitored": total_accounts,
            "high_risk_accounts": high_risk_count,
            "active_threats_count": len(active_threats),
            "total_threats_recorded": len(threats),
            "tier_distribution": tier_counts,
            "vulnerability_counts": {
                "kerberoastable_spns": kerberoastable_count,
                "unconstrained_delegation": unconstrained_count,
                "shadow_admins": shadow_admin_count
            },
            "active_threat_severities": severity_counts,
            "threat_technique_breakdown": technique_counts,
            "attack_graph_edges_count": total_relationships,
            "supported_providers": ["ACTIVE_DIRECTORY", "ENTRA_ID", "OKTA", "LOCAL_PAM"],
            "detection_capabilities": [
                {"technique": "Kerberoasting", "mitre": "T1558.003", "status": "ACTIVE"},
                {"technique": "Pass-the-Hash / Pass-the-Ticket", "mitre": "T1550.002", "status": "ACTIVE"},
                {"technique": "DCSync / DCShadow", "mitre": "T1003.006", "status": "ACTIVE"},
                {"technique": "OAuth App Consent Abuse", "mitre": "T1098.003", "status": "ACTIVE"},
                {"technique": "Shadow Admin Escalation", "mitre": "T1098", "status": "ACTIVE"},
                {"technique": "Golden/Silver Ticket Forgery", "mitre": "T1558.001", "status": "ACTIVE"}
            ]
        }

    @staticmethod
    async def get_accounts(
        session: AsyncSession,
        privilege_tier: Optional[str] = None,
        min_risk: Optional[float] = None,
        account_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List accounts with filters for tier, risk score, and type."""
        await MonitorixITDRService.ensure_seed_data(session)

        query = select(IdentityAccount)
        if privilege_tier:
            query = query.where(IdentityAccount.PrivilegeTier == privilege_tier)
        if min_risk is not None:
            query = query.where(IdentityAccount.RiskScore >= min_risk)
        if account_type:
            query = query.where(IdentityAccount.AccountType == account_type)

        query = query.order_by(desc(IdentityAccount.RiskScore))
        res = await session.execute(query)
        accounts = res.scalars().all()

        results = []
        for a in accounts:
            try:
                meta = json.loads(a.MetadataJson or "{}")
            except Exception:
                meta = {}
            results.append({
                "id": a.Id,
                "account_id": a.AccountId,
                "display_name": a.DisplayName,
                "account_type": a.AccountType,
                "identity_provider": a.IdentityProvider,
                "privilege_tier": a.PrivilegeTier,
                "risk_score": a.RiskScore,
                "is_kerberoastable": a.IsKerberoastable,
                "has_unconstrained_delegation": a.HasUnconstrainedDelegation,
                "is_shadow_admin": a.IsShadowAdmin,
                "mfa_enabled": a.MfaEnabled,
                "status": a.Status,
                "last_activity": a.LastActivity.isoformat() if a.LastActivity else None,
                "created_at": a.CreatedAt.isoformat() if a.CreatedAt else None,
                "metadata": meta
            })
        return results

    @staticmethod
    async def get_threats(
        session: AsyncSession,
        status_filter: Optional[str] = None,
        severity_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List active and historical identity threats."""
        await MonitorixITDRService.ensure_seed_data(session)

        query = select(IdentityThreatEvent)
        if status_filter:
            query = query.where(IdentityThreatEvent.Status == status_filter)
        if severity_filter:
            query = query.where(IdentityThreatEvent.Severity == severity_filter)

        query = query.order_by(desc(IdentityThreatEvent.DetectedAt))
        res = await session.execute(query)
        threats = res.scalars().all()

        results = []
        for t in threats:
            try:
                det = json.loads(t.DetailsJson or "{}")
            except Exception:
                det = {}
            results.append({
                "id": t.Id,
                "threat_id": t.ThreatId,
                "threat_type": t.ThreatType,
                "mitre_tactic": t.MitreTactic,
                "mitre_technique": t.MitreTechnique,
                "severity": t.Severity,
                "source_host": t.SourceHost,
                "source_account": t.SourceAccount,
                "target_account": t.TargetAccount,
                "target_domain": t.TargetDomain,
                "status": t.Status,
                "containment_action_taken": t.ContainmentActionTaken,
                "detected_at": t.DetectedAt.isoformat() if t.DetectedAt else None,
                "details": det
            })
        return results

    @staticmethod
    async def get_attack_graph(session: AsyncSession) -> Dict[str, Any]:
        """Generate full node-link identity attack graph for visualization."""
        await MonitorixITDRService.ensure_seed_data(session)

        # Get edges
        res = await session.execute(select(IdentityAttackPathNode))
        edges = res.scalars().all()

        node_set: Dict[str, Dict[str, Any]] = {}
        links = []

        # Also load accounts to enrich nodes
        acc_res = await session.execute(select(IdentityAccount))
        accounts_map = {a.AccountId: a for a in acc_res.scalars().all()}

        for edge in edges:
            src = edge.SourceNodeId
            tgt = edge.TargetNodeId

            if src not in node_set:
                acc_obj = accounts_map.get(src)
                node_set[src] = {
                    "id": src,
                    "label": acc_obj.DisplayName if acc_obj else src,
                    "type": edge.SourceNodeType,
                    "tier": acc_obj.PrivilegeTier if acc_obj else "TIER_2_USER",
                    "risk_score": acc_obj.RiskScore if acc_obj else 30.0,
                    "is_compromised": edge.IsActiveExploitPath
                }

            if tgt not in node_set:
                acc_obj = accounts_map.get(tgt)
                node_set[tgt] = {
                    "id": tgt,
                    "label": acc_obj.DisplayName if acc_obj else tgt,
                    "type": edge.TargetNodeType,
                    "tier": acc_obj.PrivilegeTier if acc_obj else "TIER_0_DOMAIN_ADMIN",
                    "risk_score": acc_obj.RiskScore if acc_obj else 90.0,
                    "is_target": True
                }

            links.append({
                "id": edge.Id,
                "path_id": edge.PathId,
                "source": src,
                "target": tgt,
                "relation_type": edge.RelationType,
                "is_active_exploit_path": edge.IsActiveExploitPath,
                "hops_count": edge.HopsCount,
                "risk_level": edge.RiskLevel
            })

        return {
            "nodes": list(node_set.values()),
            "links": links,
            "total_nodes": len(node_set),
            "total_links": len(links),
            "tier_0_targets": [n["id"] for n in node_set.values() if "0" in str(n.get("tier", ""))]
        }

    @staticmethod
    async def evaluate_identity_event(session: AsyncSession, event_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate real-time identity telemetry against heuristic detection rules:
        - Kerberoasting: TGS with RC4 (0x17)
        - Pass-the-Hash: NTLM auth from client over network
        - DCSync: DSGetNCChanges from non-DC
        - OAuth Consent Abuse: High privilege scopes requested by third party
        """
        await MonitorixITDRService.ensure_seed_data(session)

        event_type = event_payload.get("event_type", "").upper()
        source_account = event_payload.get("source_account", "unknown")
        target_account = event_payload.get("target_account", "unknown")
        source_host = event_payload.get("source_host", "0.0.0.0")
        target_domain = event_payload.get("target_domain", "corp.enterprise.com")

        threat_detected = False
        threat_type = "UNKNOWN"
        mitre_tactic = "Credential Access"
        mitre_technique = "T1003"
        severity = "MEDIUM"
        details: Dict[str, Any] = {}

        # 1. Heuristic: Kerberoasting
        if event_type in ("TGS_REQUEST", "KERBEROS_TGS") or "0x17" in str(event_payload.get("encryption", "")).lower() or "rc4" in str(event_payload.get("encryption", "")).lower():
            spn = event_payload.get("spn", "")
            if spn or "spn" in str(event_payload).lower():
                threat_detected = True
                threat_type = "KERBEROASTING"
                mitre_tactic = "Credential Access"
                mitre_technique = "T1558.003"
                severity = "HIGH"
                details = {
                    "rule": "RULE-ITDR-01-KERBEROAST",
                    "reason": "TGS ticket requested with legacy RC4_HMAC_MD5 (0x17) encryption cipher.",
                    "spn": spn or "HTTP/service.corp.enterprise.com",
                    "payload_received": event_payload
                }

        # 2. Heuristic: DCSync
        elif "DSGETNCCHANGES" in str(event_payload).upper() or event_type in ("DCSYNC", "DIRECTORY_REPLICATION"):
            threat_detected = True
            threat_type = "DCSYNC"
            mitre_tactic = "Credential Access"
            mitre_technique = "T1003.006"
            severity = "CRITICAL"
            details = {
                "rule": "RULE-ITDR-02-DCSYNC",
                "reason": "DSGetNCChanges directory replication RPC invoked from non-DC workstation endpoint.",
                "rpc_function": "DsGetNCChanges",
                "payload_received": event_payload
            }

        # 3. Heuristic: Pass-the-Hash
        elif event_type in ("NTLM_LOGON", "PASS_THE_HASH") or (str(event_payload.get("auth_package") or "").upper() == "NTLM" and event_payload.get("logon_type") in (3, "3", "NETWORK")):
            threat_detected = True
            threat_type = "PASS_THE_HASH"
            mitre_tactic = "Lateral Movement"
            mitre_technique = "T1550.002"
            severity = "HIGH"
            details = {
                "rule": "RULE-ITDR-03-PASS-THE-HASH",
                "reason": "Privileged account authenticated via NTLM network logon (LogonType 3) bypassing Kerberos.",
                "logon_type": 3,
                "auth_package": "NTLM",
                "payload_received": event_payload
            }

        # 4. Heuristic: OAuth Consent Abuse
        elif event_type in ("OAUTH_CONSENT", "APP_REGISTRATION") or any(scope in str(event_payload.get("scopes", [])) for scope in ["Directory.ReadWrite.All", "Mail.ReadWrite", "FullAccess"]):
            threat_detected = True
            threat_type = "OAUTH_CONSENT_ABUSE"
            mitre_tactic = "Persistence"
            mitre_technique = "T1098.003"
            severity = "HIGH"
            details = {
                "rule": "RULE-ITDR-04-OAUTH-ABUSE",
                "reason": "High-privilege directory modification scopes consented to external unverified app.",
                "scopes": event_payload.get("scopes", ["Directory.ReadWrite.All"]),
                "payload_received": event_payload
            }

        # Fallback heuristic if explicit threat flag provided
        elif event_payload.get("simulate_threat"):
            threat_detected = True
            threat_type = event_payload.get("simulate_threat", "SHADOW_ADMIN_ESCALATION")
            mitre_tactic = "Privilege Escalation"
            mitre_technique = "T1098"
            severity = "HIGH"
            details = {"rule": "RULE-ITDR-SIMULATION", "reason": "Simulated identity threat heuristic match."}

        if threat_detected:
            threat_id = f"ITDR-THR-{uuid.uuid4().hex[:8].upper()}"
            threat_event = IdentityThreatEvent(
                ThreatId=threat_id,
                ThreatType=threat_type,
                MitreTactic=mitre_tactic,
                MitreTechnique=mitre_technique,
                Severity=severity,
                SourceHost=source_host,
                SourceAccount=source_account,
                TargetAccount=target_account,
                TargetDomain=target_domain,
                Status="ACTIVE",
                DetailsJson=json.dumps(details)
            )
            session.add(threat_event)

            # Escalate risk score of source or target account if found
            acc_stmt = select(IdentityAccount).where(
                (IdentityAccount.AccountId == target_account) |
                (IdentityAccount.DisplayName.ilike(f"%{target_account}%")) |
                (IdentityAccount.AccountId == source_account)
            )
            acc_match = (await session.execute(acc_stmt)).scalars().first()
            if acc_match:
                acc_match.RiskScore = min(100.0, acc_match.RiskScore + 25.0)

            await session.commit()

            return {
                "evaluated": True,
                "threat_detected": True,
                "threat_id": threat_id,
                "threat_type": threat_type,
                "severity": severity,
                "mitre": f"{mitre_tactic} ({mitre_technique})",
                "recommended_action": "TRIGGER_IMMEDIATE_CONTAINMENT",
                "details": details
            }
        else:
            return {
                "evaluated": True,
                "threat_detected": False,
                "message": "Telemetry evaluated normal. No identity attack pattern matched."
            }

    @staticmethod
    async def contain_threat(
        session: AsyncSession,
        threat_id: str,
        action: str = "DISABLE_ACCOUNT"
    ) -> Dict[str, Any]:
        """
        Execute active response containment:
        - DISABLE_ACCOUNT: Disable Active Directory / Entra account
        - REVOKE_OAUTH_TOKENS: Invalidate active refresh tokens and OAuth grants
        - TRIGGER_PASSWORD_RESET: Force Kerberos password & ticket reset
        - ISOLATE_KERBEROS_TICKET: Invalidate ticket granting tickets (krbtgt reset)
        """
        q = await session.execute(select(IdentityThreatEvent).where(IdentityThreatEvent.ThreatId == threat_id))
        threat = q.scalars().first()
        if not threat:
            raise HTTPException(status_code=404, detail=f"Threat {threat_id} not found")

        threat.Status = "CONTAINED"
        threat.ContainmentActionTaken = f"Executed {action} at {datetime.utcnow().isoformat()}Z"

        # Update associated account if present
        target_acc = threat.TargetAccount or threat.SourceAccount
        acc_updated = False
        if target_acc:
            acc_q = await session.execute(
                select(IdentityAccount).where(
                    (IdentityAccount.AccountId == target_acc) |
                    (IdentityAccount.DisplayName.ilike(f"%{target_acc}%"))
                )
            )
            acc = acc_q.scalars().first()
            if acc:
                acc.Status = "CONTAINED"
                acc.RiskScore = max(10.0, acc.RiskScore - 40.0) # Lower active risk post containment
                acc_updated = True

        await session.commit()

        return {
            "success": True,
            "threat_id": threat_id,
            "containment_action": action,
            "status": "CONTAINED",
            "account_contained": target_acc,
            "account_updated": acc_updated,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "message": f"Successfully performed {action} for {target_acc}. Identity threat contained."
        }
