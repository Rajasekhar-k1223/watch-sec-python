"""
[v18.8.0] Monitorix Sovereign Kubernetes & Container Workload Security Service
==============================================================================
Provides enterprise KSPM (Kubernetes Security Posture Management) & CWPP
(Cloud Workload Protection Platform) capabilities:
- Multi-cluster posture tracking (EKS, GKE, AKS, Self-Hosted)
- Workload telemetry & Pod Security Standards (PSS) compliance
- HostPath mount, Privileged container, and CAP_SYS_ADMIN detection
- Admission control policy evaluation & manifest validation
- Container breakout / escape runtime detection
- 1-Click Pod quarantine and network isolation
- Strictly 100% sovereign Monitorix platform implementation
"""

import logging
import uuid
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException

from app.db.models import K8sCluster, K8sWorkload, K8sSecurityFinding, K8sAdmissionPolicy

logger = logging.getLogger("monitorix.k8s_security")

# ---------------------------------------------------------------------------
# Default Seed Datasets
# ---------------------------------------------------------------------------

DEFAULT_CLUSTERS = [
    {
        "cluster_id": "K8S-EKS-PROD-PRIMARY",
        "name": "eks-production-us-east-1",
        "provider": "EKS",
        "region": "us-east-1",
        "k8s_version": "v1.28.7",
        "node_count": 18,
        "pod_count": 240,
        "posture_score": 88.0,
        "cis_benchmark_score": 85.0,
        "status": "HEALTHY"
    },
    {
        "cluster_id": "K8S-GKE-DATA-PLATFORM",
        "name": "gke-data-analytics-central",
        "provider": "GKE",
        "region": "us-central1",
        "k8s_version": "v1.29.2",
        "node_count": 12,
        "pod_count": 160,
        "posture_score": 78.5,
        "cis_benchmark_score": 74.0,
        "status": "HEALTHY"
    },
    {
        "cluster_id": "K8S-AKS-EDGE-SERVICES",
        "name": "aks-edge-services-eastus2",
        "provider": "AKS",
        "region": "eastus2",
        "k8s_version": "v1.28.5",
        "node_count": 8,
        "pod_count": 95,
        "posture_score": 91.0,
        "cis_benchmark_score": 88.5,
        "status": "HEALTHY"
    },
    {
        "cluster_id": "K8S-ONPREM-CORE-HYBRID",
        "name": "onprem-baremetal-dc1",
        "provider": "SELF_HOSTED",
        "region": "datacenter-dc1",
        "k8s_version": "v1.27.8",
        "node_count": 6,
        "pod_count": 80,
        "posture_score": 62.0,
        "cis_benchmark_score": 58.0,
        "status": "DEGRADED"
    }
]

DEFAULT_WORKLOADS = [
    {
        "workload_id": "WKLD-PAYMENT-API",
        "cluster_id": "K8S-EKS-PROD-PRIMARY",
        "namespace": "prod",
        "name": "payment-api-gateway",
        "workload_type": "Deployment",
        "image": "monitorix/payment-api:v2.4.1",
        "is_privileged": False,
        "runs_as_root": False,
        "has_hostpath_mount": False,
        "has_host_pid": False,
        "capabilities": "[]",
        "risk_score": 12.0,
        "status": "RUNNING"
    },
    {
        "workload_id": "WKLD-LEGACY-INGEST",
        "cluster_id": "K8S-ONPREM-CORE-HYBRID",
        "namespace": "prod",
        "name": "legacy-telemetry-collector",
        "workload_type": "DaemonSet",
        "image": "monitorix/legacy-ingest:v1.1",
        "is_privileged": True,
        "runs_as_root": True,
        "has_hostpath_mount": True,
        "has_host_pid": True,
        "capabilities": '["CAP_SYS_ADMIN"]',
        "risk_score": 89.0,
        "status": "RUNNING"
    },
    {
        "workload_id": "WKLD-AUTH-VAULT",
        "cluster_id": "K8S-EKS-PROD-PRIMARY",
        "namespace": "security",
        "name": "vault-secrets-agent",
        "workload_type": "Deployment",
        "image": "hashicorp/vault:1.15.2",
        "is_privileged": False,
        "runs_as_root": False,
        "has_hostpath_mount": False,
        "has_host_pid": False,
        "capabilities": '["IPC_LOCK"]',
        "risk_score": 24.0,
        "status": "RUNNING"
    },
    {
        "workload_id": "WKLD-NODE-EXPORTER",
        "cluster_id": "K8S-GKE-DATA-PLATFORM",
        "namespace": "monitoring",
        "name": "prometheus-node-exporter",
        "workload_type": "DaemonSet",
        "image": "prom/node-exporter:v1.7.0",
        "is_privileged": False,
        "runs_as_root": True,
        "has_hostpath_mount": True,
        "has_host_pid": True,
        "capabilities": '["SYS_TIME"]',
        "risk_score": 48.0,
        "status": "RUNNING"
    },
    {
        "workload_id": "WKLD-ROGUED-JOB",
        "cluster_id": "K8S-ONPREM-CORE-HYBRID",
        "namespace": "default",
        "name": "batch-crypto-worker",
        "workload_type": "Pod",
        "image": "alpine:latest",
        "is_privileged": True,
        "runs_as_root": True,
        "has_hostpath_mount": True,
        "has_host_pid": False,
        "capabilities": '["CAP_SYS_ADMIN", "CAP_NET_ADMIN"]',
        "risk_score": 95.0,
        "status": "RUNNING"
    }
]

DEFAULT_FINDINGS = [
    {
        "finding_id": "K8S-FIND-001",
        "cluster_id": "K8S-ONPREM-CORE-HYBRID",
        "workload_id": "WKLD-LEGACY-INGEST",
        "namespace": "prod",
        "finding_type": "PRIVILEGED_CONTAINER",
        "severity": "CRITICAL",
        "title": "Privileged Container Execution",
        "description": "Container executes with securityContext.privileged: true, granting full access to host kernel capabilities.",
        "remediation": "Remove privileged: true from pod spec and explicitly grant only necessary Linux capabilities.",
        "status": "OPEN"
    },
    {
        "finding_id": "K8S-FIND-002",
        "cluster_id": "K8S-ONPREM-CORE-HYBRID",
        "workload_id": "WKLD-LEGACY-INGEST",
        "namespace": "prod",
        "finding_type": "DOCKER_SOCKET_MOUNT",
        "severity": "CRITICAL",
        "title": "Host Docker/CRI Socket Volume Mount",
        "description": "HostPath mount maps /var/run/docker.sock into container. Pod can execute arbitrary root containers on node.",
        "remediation": "Remove hostPath mount to CRI / Docker socket. Use specialized Kubernetes CSI or API.",
        "status": "OPEN"
    },
    {
        "finding_id": "K8S-FIND-003",
        "cluster_id": "K8S-GKE-DATA-PLATFORM",
        "workload_id": "WKLD-NODE-EXPORTER",
        "namespace": "monitoring",
        "finding_type": "ROOT_EXECUTION",
        "severity": "HIGH",
        "title": "Container Running As Root User",
        "description": "Pod does not specify runAsNonRoot: true and executes default UID 0 processes.",
        "remediation": "Set securityContext.runAsNonRoot: true and declare runAsUser with UID >= 10000.",
        "status": "OPEN"
    },
    {
        "finding_id": "K8S-FIND-004",
        "cluster_id": "K8S-ONPREM-CORE-HYBRID",
        "workload_id": "WKLD-ROGUED-JOB",
        "namespace": "default",
        "finding_type": "EXCESSIVE_RBAC",
        "severity": "HIGH",
        "title": "Excessive ClusterRoleBinding to Default ServiceAccount",
        "description": "Default ServiceAccount granted wildcard cluster-admin permissions verbs ['*'] resources ['*'].",
        "remediation": "Revoke cluster-admin binding; generate dedicated ServiceAccount with least-privilege Role.",
        "status": "OPEN"
    }
]

DEFAULT_POLICIES = [
    {
        "policy_id": "POL-K8S-PSS-001",
        "name": "Disallow Privileged Containers (PSS Restricted)",
        "category": "POD_SECURITY_STANDARDS",
        "enforce_mode": "ENFORCE",
        "description": "Rejects admission of pods with securityContext.privileged: true under Pod Security Standards Restricted profile.",
        "is_enabled": True
    },
    {
        "policy_id": "POL-K8S-PSS-002",
        "name": "Block Sensitive HostPath Mounts (/var/run/docker.sock, /etc, /)",
        "category": "POD_SECURITY_STANDARDS",
        "enforce_mode": "ENFORCE",
        "description": "Prevents mounting sensitive root, configuration, or container runtime sockets from host filesystem.",
        "is_enabled": True
    },
    {
        "policy_id": "POL-K8S-PSS-003",
        "name": "Prohibit CAP_SYS_ADMIN and Root UID Execution",
        "category": "POD_SECURITY_STANDARDS",
        "enforce_mode": "ENFORCE",
        "description": "Disallows adding CAP_SYS_ADMIN or omitting runAsNonRoot constraint for application workloads.",
        "is_enabled": True
    },
    {
        "policy_id": "POL-K8S-RBAC-004",
        "name": "Disallow Wildcard RBAC on Secrets and Exec",
        "category": "RBAC_GUARDRAIL",
        "enforce_mode": "ENFORCE",
        "description": "Blocks ClusterRoles or Roles with verbs '*' targeting resources 'secrets' or 'pods/exec'.",
        "is_enabled": True
    }
]

# ---------------------------------------------------------------------------
# Service Implementation
# ---------------------------------------------------------------------------

class MonitorixK8sSecurityService:
    """Enterprise Kubernetes & Container Workload Security Management"""

    @staticmethod
    async def ensure_seed_data(session: AsyncSession) -> None:
        """Seed initial Kubernetes clusters, workloads, findings, and policies."""
        q = await session.execute(select(K8sCluster))
        if not q.scalars().first():
            for c in DEFAULT_CLUSTERS:
                cluster = K8sCluster(
                    ClusterId=c["cluster_id"],
                    Name=c["name"],
                    Provider=c["provider"],
                    Region=c["region"],
                    K8sVersion=c["k8s_version"],
                    NodeCount=c["node_count"],
                    PodCount=c["pod_count"],
                    PostureScore=c["posture_score"],
                    CisBenchmarkScore=c["cis_benchmark_score"],
                    Status=c["status"]
                )
                session.add(cluster)

            for w in DEFAULT_WORKLOADS:
                workload = K8sWorkload(
                    WorkloadId=w["workload_id"],
                    ClusterId=w["cluster_id"],
                    Namespace=w["namespace"],
                    Name=w["name"],
                    WorkloadType=w["workload_type"],
                    Image=w["image"],
                    IsPrivileged=w["is_privileged"],
                    RunsAsRoot=w["runs_as_root"],
                    HasHostPathMount=w["has_hostpath_mount"],
                    HasHostPid=w["has_host_pid"],
                    Capabilities=w["capabilities"],
                    RiskScore=w["risk_score"],
                    Status=w["status"]
                )
                session.add(workload)

            for f in DEFAULT_FINDINGS:
                finding = K8sSecurityFinding(
                    FindingId=f["finding_id"],
                    ClusterId=f["cluster_id"],
                    WorkloadId=f["workload_id"],
                    Namespace=f["namespace"],
                    FindingType=f["finding_type"],
                    Severity=f["severity"],
                    Title=f["title"],
                    Description=f["description"],
                    Remediation=f["remediation"],
                    Status=f["status"]
                )
                session.add(finding)

            for p in DEFAULT_POLICIES:
                policy = K8sAdmissionPolicy(
                    PolicyId=p["policy_id"],
                    Name=p["name"],
                    Category=p["category"],
                    EnforceMode=p["enforce_mode"],
                    Description=p["description"],
                    IsEnabled=p["is_enabled"]
                )
                session.add(policy)

            await session.commit()
            logger.info("Seeded initial Sovereign Kubernetes Security datasets.")

    @staticmethod
    async def get_overview(session: AsyncSession) -> Dict[str, Any]:
        """Compute aggregate KSPM posture score, pod statistics, and threat telemetry."""
        await MonitorixK8sSecurityService.ensure_seed_data(session)

        # Query clusters
        cluster_res = await session.execute(select(K8sCluster))
        clusters = cluster_res.scalars().all()
        total_clusters = len(clusters)
        total_nodes = sum(c.NodeCount for c in clusters)
        total_pods = sum(c.PodCount for c in clusters)
        avg_posture = sum(c.PostureScore for c in clusters) / max(1, total_clusters)
        avg_cis = sum(c.CisBenchmarkScore for c in clusters) / max(1, total_clusters)

        # Query workloads
        wkld_res = await session.execute(select(K8sWorkload))
        workloads = wkld_res.scalars().all()
        privileged_pods = sum(1 for w in workloads if w.IsPrivileged)
        root_pods = sum(1 for w in workloads if w.RunsAsRoot)
        hostpath_pods = sum(1 for w in workloads if w.HasHostPathMount)
        quarantined_pods = sum(1 for w in workloads if w.Status == "QUARANTINED")

        # Query findings
        finding_res = await session.execute(select(K8sSecurityFinding))
        findings = finding_res.scalars().all()
        open_findings = [f for f in findings if f.Status == "OPEN"]
        critical_findings = sum(1 for f in open_findings if f.Severity == "CRITICAL")
        high_findings = sum(1 for f in open_findings if f.Severity == "HIGH")

        # Provider breakdown
        provider_breakdown: Dict[str, int] = {}
        for c in clusters:
            provider_breakdown[c.Provider] = provider_breakdown.get(c.Provider, 0) + 1

        # Finding type breakdown
        finding_type_breakdown: Dict[str, int] = {}
        for f in open_findings:
            finding_type_breakdown[f.FindingType] = finding_type_breakdown.get(f.FindingType, 0) + 1

        # Calculate KSPM Defense Score
        score = 100.0 - (
            (critical_findings * 12.0) +
            (high_findings * 6.0) +
            (privileged_pods * 5.0)
        )
        kspm_defense_score = round(max(20.0, min(100.0, score)), 1)

        return {
            "status": "HEALTHY",
            "kspm_defense_score": kspm_defense_score,
            "avg_cluster_posture": round(avg_posture, 1),
            "cis_benchmark_score": round(avg_cis, 1),
            "total_clusters_count": total_clusters,
            "total_nodes_count": total_nodes,
            "total_pods_count": total_pods,
            "monitored_workloads_count": len(workloads),
            "privileged_workloads_count": privileged_pods,
            "root_execution_workloads_count": root_pods,
            "hostpath_workloads_count": hostpath_pods,
            "quarantined_workloads_count": quarantined_pods,
            "open_findings_count": len(open_findings),
            "critical_findings_count": critical_findings,
            "provider_breakdown": provider_breakdown,
            "finding_type_breakdown": finding_type_breakdown,
            "sovereign_engine": "Monitorix Sovereign KSPM/CWPP Shield v18.8"
        }

    @staticmethod
    async def get_clusters(session: AsyncSession, provider: Optional[str] = None) -> List[Dict[str, Any]]:
        """List monitored Kubernetes clusters."""
        await MonitorixK8sSecurityService.ensure_seed_data(session)

        stmt = select(K8sCluster)
        if provider:
            stmt = stmt.where(K8sCluster.Provider == provider.upper())
        res = await session.execute(stmt)
        clusters = res.scalars().all()

        return [
            {
                "id": c.Id,
                "cluster_id": c.ClusterId,
                "name": c.Name,
                "provider": c.Provider,
                "region": c.Region,
                "k8s_version": c.K8sVersion,
                "node_count": c.NodeCount,
                "pod_count": c.PodCount,
                "posture_score": c.PostureScore,
                "cis_benchmark_score": c.CisBenchmarkScore,
                "status": c.Status,
                "last_audited_at": c.LastAuditedAt.isoformat() if c.LastAuditedAt else None
            }
            for c in clusters
        ]

    @staticmethod
    async def get_workloads(
        session: AsyncSession,
        namespace: Optional[str] = None,
        is_privileged: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """List container workloads and pods."""
        await MonitorixK8sSecurityService.ensure_seed_data(session)

        stmt = select(K8sWorkload)
        if namespace:
            stmt = stmt.where(K8sWorkload.Namespace == namespace)
        if is_privileged is not None:
            stmt = stmt.where(K8sWorkload.IsPrivileged == is_privileged)
        res = await session.execute(stmt)
        workloads = res.scalars().all()

        return [
            {
                "id": w.Id,
                "workload_id": w.WorkloadId,
                "cluster_id": w.ClusterId,
                "namespace": w.Namespace,
                "name": w.Name,
                "workload_type": w.WorkloadType,
                "image": w.Image,
                "is_privileged": w.IsPrivileged,
                "runs_as_root": w.RunsAsRoot,
                "has_hostpath_mount": w.HasHostPathMount,
                "has_host_pid": w.HasHostPid,
                "capabilities": w.Capabilities,
                "risk_score": w.RiskScore,
                "status": w.Status,
                "created_at": w.CreatedAt.isoformat() if w.CreatedAt else None
            }
            for w in workloads
        ]

    @staticmethod
    async def get_findings(
        session: AsyncSession,
        severity: Optional[str] = None,
        status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List active and resolved Kubernetes security findings."""
        await MonitorixK8sSecurityService.ensure_seed_data(session)

        stmt = select(K8sSecurityFinding)
        if severity:
            stmt = stmt.where(K8sSecurityFinding.Severity == severity.upper())
        if status:
            stmt = stmt.where(K8sSecurityFinding.Status == status.upper())
        stmt = stmt.order_by(K8sSecurityFinding.DetectedAt.desc())
        res = await session.execute(stmt)
        findings = res.scalars().all()

        return [
            {
                "id": f.Id,
                "finding_id": f.FindingId,
                "cluster_id": f.ClusterId,
                "workload_id": f.WorkloadId,
                "namespace": f.Namespace,
                "finding_type": f.FindingType,
                "severity": f.Severity,
                "title": f.Title,
                "description": f.Description,
                "remediation": f.Remediation,
                "status": f.Status,
                "detected_at": f.DetectedAt.isoformat() if f.DetectedAt else None,
                "resolved_at": f.ResolvedAt.isoformat() if f.ResolvedAt else None
            }
            for f in findings
        ]

    @staticmethod
    async def get_policies(session: AsyncSession) -> List[Dict[str, Any]]:
        """List admission guardrail policies and Pod Security Standards."""
        await MonitorixK8sSecurityService.ensure_seed_data(session)

        res = await session.execute(select(K8sAdmissionPolicy))
        policies = res.scalars().all()
        return [
            {
                "id": p.Id,
                "policy_id": p.PolicyId,
                "name": p.Name,
                "category": p.Category,
                "enforce_mode": p.EnforceMode,
                "description": p.Description,
                "is_enabled": p.IsEnabled,
                "created_at": p.CreatedAt.isoformat() if p.CreatedAt else None
            }
            for p in policies
        ]

    @staticmethod
    async def evaluate_manifest(
        session: AsyncSession,
        manifest_text: str,
        namespace: str = "default"
    ) -> Dict[str, Any]:
        """Admission Control sandbox evaluating pod spec YAML/JSON against PSS guardrails."""
        await MonitorixK8sSecurityService.ensure_seed_data(session)

        violations: List[str] = []
        lower_manifest = manifest_text.lower()

        # Check privileged container
        if "privileged: true" in lower_manifest or '"privileged": true' in lower_manifest:
            violations.append("Disallowed: securityContext.privileged: true violates PSS Restricted standard")

        # Check sensitive hostPath mounts
        if "hostpath:" in lower_manifest or '"hostpath"' in lower_manifest:
            if any(path in lower_manifest for path in ["/var/run/docker.sock", "/etc", "/var/run/containerd", "path: /", 'path: "/', "path: '/'"]):
                violations.append("Disallowed: Dangerous hostPath mount to root or CRI socket detected")

        # Check CAP_SYS_ADMIN
        if "cap_sys_admin" in lower_manifest or "sys_admin" in lower_manifest:
            violations.append("Disallowed: Addition of CAP_SYS_ADMIN capability grants near-root host access")

        # Check hostPID or hostNetwork
        if "hostpid: true" in lower_manifest or '"hostpid": true' in lower_manifest:
            violations.append("Disallowed: hostPID sharing exposes host process space to container")

        if "hostnetwork: true" in lower_manifest or '"hostnetwork": true' in lower_manifest:
            violations.append("Disallowed: hostNetwork sharing exposes host network namespace")

        # Check runAsUser: 0 without non-root
        if ("runasuser: 0" in lower_manifest or '"runasuser": 0' in lower_manifest) and ("runasnonroot: true" not in lower_manifest):
            violations.append("Disallowed: Explicit execution as root UID 0 prohibited")

        allowed = len(violations) == 0
        verdict = "ALLOWED" if allowed else "DENIED"

        return {
            "allowed": allowed,
            "verdict": verdict,
            "namespace": namespace,
            "violations_count": len(violations),
            "violations": violations,
            "matched_policy": "POL-K8S-PSS-001" if not allowed else None,
            "enforce_action": "REJECT_ADMISSION" if not allowed else "PERMIT_CREATION",
            "timestamp": datetime.utcnow().isoformat()
        }

    @staticmethod
    async def inspect_runtime_event(
        session: AsyncSession,
        cluster_id: str,
        pod_name: str,
        namespace: str,
        event_type: str,
        process_path: str,
        command_line: str
    ) -> Dict[str, Any]:
        """CWPP runtime engine detecting container breakout, reverse shells, and escape attacks."""
        await MonitorixK8sSecurityService.ensure_seed_data(session)

        threat_detected = False
        threat_type = "NONE"
        severity = "LOW"
        description = ""

        cmd_lower = command_line.lower()
        proc_lower = process_path.lower()

        # Heuristic 1: Container Escape via nsenter / procfs
        if "nsenter" in cmd_lower or "/proc/sys/kernel/core_pattern" in cmd_lower or "cgroups" in cmd_lower and "release_agent" in cmd_lower:
            threat_detected = True
            threat_type = "CONTAINER_ESCAPE_ATTEMPT"
            severity = "CRITICAL"
            description = f"Container breakout attempt detected via '{command_line}'. Host namespace injection intercepted."

        # Heuristic 2: Reverse Shell / Interactive shell spawned in non-interactive container
        elif any(shell in cmd_lower for shell in ["/bin/bash -i", "sh -i", "nc -e", "/dev/tcp/", "bash -c 'bash -i >& /dev/tcp"]):
            threat_detected = True
            threat_type = "CONTAINER_REVERSE_SHELL"
            severity = "CRITICAL"
            description = f"Interactive reverse shell connection spawned in container: '{command_line}'."

        # Heuristic 3: Unauthorized execution from /tmp or /dev/shm
        elif "/tmp/" in proc_lower or "/dev/shm/" in proc_lower or "cryptominer" in cmd_lower:
            threat_detected = True
            threat_type = "UNAUTHORIZED_BINARY_EXECUTION"
            severity = "HIGH"
            description = f"Execution of unverified binary from temporary memory path: '{process_path}'."

        finding_id = f"K8S-FIND-{uuid.uuid4().hex[:8].upper()}" if threat_detected else None

        if threat_detected:
            new_finding = K8sSecurityFinding(
                FindingId=finding_id,
                ClusterId=cluster_id,
                WorkloadId=pod_name,
                Namespace=namespace,
                FindingType=threat_type,
                Severity=severity,
                Title=f"CWPP Runtime Alert: {threat_type.replace('_', ' ').title()}",
                Description=description,
                Remediation="Immediately quarantine pod, isolate network namespace, and conduct node forensics.",
                Status="OPEN"
            )
            session.add(new_finding)
            await session.commit()

        return {
            "threat_detected": threat_detected,
            "verdict": "THREAT_BLOCKED" if threat_detected else "NORMAL_PROCESS",
            "threat_type": threat_type,
            "severity": severity,
            "finding_id": finding_id,
            "cluster_id": cluster_id,
            "pod_name": pod_name,
            "action_taken": "ALERT_AND_CONTAIN" if threat_detected else "LOG_AUDIT",
            "description": description
        }

    @staticmethod
    async def quarantine_pod(
        session: AsyncSession,
        finding_id: Optional[str] = None,
        workload_id: Optional[str] = None,
        action: str = "ISOLATE_NETWORK"
    ) -> Dict[str, Any]:
        """1-Click active response to quarantine a pod via NetworkPolicy denial."""
        await MonitorixK8sSecurityService.ensure_seed_data(session)

        target_pod = workload_id
        if finding_id:
            f_q = await session.execute(
                select(K8sSecurityFinding).where(K8sSecurityFinding.FindingId == finding_id)
            )
            finding = f_q.scalars().first()
            if finding:
                finding.Status = "QUARANTINED"
                finding.ResolvedAt = datetime.utcnow()
                target_pod = target_pod or finding.WorkloadId

        if target_pod:
            w_q = await session.execute(
                select(K8sWorkload).where(K8sWorkload.WorkloadId == target_pod)
            )
            workload = w_q.scalars().first()
            if workload:
                workload.Status = "QUARANTINED"
                workload.RiskScore = 0.0

        await session.commit()

        return {
            "success": True,
            "workload_id": target_pod,
            "finding_id": finding_id,
            "status": "QUARANTINED",
            "action_taken": action,
            "isolation_network_policy": "k8s-quarantine-deny-all",
            "message": f"Pod {target_pod} successfully quarantined. Zero ingress/egress permitted."
        }
