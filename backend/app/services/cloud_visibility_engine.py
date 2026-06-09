"""
[v2.4.0] Cloud Visibility Engine
Processes cloud VM metadata, Docker/containerd containers, and Kubernetes assets.
Generates security signals for privileged containers, stale assets, and IAM risks.
Forwards enriched telemetry to the internal event bus.
"""
import json
import logging
import datetime
from typing import List, Dict, Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore
from sqlalchemy.future import select  # type: ignore

from ..db.models import CloudMetadata, ContainerAsset, KubernetesAsset  # type: ignore

logger = logging.getLogger("CloudVisibilityEngine")


class CloudVisibilityEngine:

    # ---------------------------------------------------------------------------
    # Internal Event Bus
    # ---------------------------------------------------------------------------

    def _emit_security_signal(self, signal: str, severity: str, context: Dict[str, Any]):
        """Emits a structured security signal to the internal log + external webhook (if configured)."""
        event = {
            "source": "cloud_visibility",
            "signal": signal,
            "severity": severity,
            "context": context,
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
        logger.warning(f"[CloudSignal] {severity.upper()} — {signal}: {context}")
        # TODO: forward to SIEM/webhook via dispatcher_service if configured
        return event

    # ---------------------------------------------------------------------------
    # VM / Cloud Metadata
    # ---------------------------------------------------------------------------

    async def process_cloud_metadata(
        self, db: AsyncSession, agent_id: str, payload: Dict[str, Any]
    ) -> CloudMetadata:
        """Upserts cloud VM metadata (AWS EC2, Azure VM, GCP Compute)."""
        result = await db.execute(
            select(CloudMetadata).where(CloudMetadata.AgentId == agent_id)
        )
        meta = result.scalars().first()
        if not meta:
            meta = CloudMetadata(AgentId=agent_id)
            db.add(meta)

        meta.Provider = payload.get("provider")
        meta.AccountId = payload.get("account_id")
        meta.Region = payload.get("region")
        meta.Zone = payload.get("zone")
        meta.InstanceId = payload.get("instance_id")
        meta.InstanceType = payload.get("instance_type")
        meta.IamRole = payload.get("iam_role")
        meta.TagsJson = json.dumps(payload.get("tags", {}))
        meta.LastSeen = datetime.datetime.utcnow()

        await db.commit()

        # IAM Risk Signal: overly permissive roles
        iam = payload.get("iam_role", "") or ""
        if any(term in iam.lower() for term in ("admin", "root", "superuser", "*")):
            self._emit_security_signal(
                signal="OverlyPermissiveIAMRole",
                severity="High",
                context={"agent_id": agent_id, "iam_role": iam, "provider": meta.Provider}
            )

        # Untagged instance signal
        if not payload.get("tags"):
            self._emit_security_signal(
                signal="UntaggedCloudInstance",
                severity="Low",
                context={"agent_id": agent_id, "instance_id": meta.InstanceId, "provider": meta.Provider}
            )

        return meta

    # ---------------------------------------------------------------------------
    # Container State
    # ---------------------------------------------------------------------------

    async def process_container_state(
        self, db: AsyncSession, agent_id: str, containers: List[Dict[str, Any]]
    ):
        """
        Processes a snapshot of running Docker/containerd containers.
        Marks containers not present in the snapshot as 'Stopped'.
        """
        seen_ids = set()
        signals = []

        for c in containers:
            container_id = c.get("container_id", "")
            if not container_id:
                continue

            result = await db.execute(
                select(ContainerAsset).where(ContainerAsset.ContainerId == container_id)
            )
            asset = result.scalars().first()
            if not asset:
                asset = ContainerAsset(AgentId=agent_id, ContainerId=container_id)
                db.add(asset)

            asset.ImageName = c.get("image_name")
            asset.ImageHash = c.get("image_hash")
            asset.State = c.get("state", "Running")
            asset.IsPrivileged = c.get("is_privileged", False)
            asset.PortsJson = json.dumps(c.get("ports", []))
            asset.MountsJson = json.dumps(c.get("mounts", []))
            asset.LastSeen = datetime.datetime.utcnow()
            seen_ids.add(container_id)

            # Security signals
            if asset.IsPrivileged:
                signals.append(self._emit_security_signal(
                    signal="PrivilegedContainerDetected",
                    severity="High",
                    context={"agent_id": agent_id, "container_id": container_id, "image": asset.ImageName}
                ))

            # Detect containers using host network
            ports = c.get("ports", [])
            if any(p.get("host_port", 0) in (22, 2375, 2376) for p in ports if isinstance(p, dict)):
                signals.append(self._emit_security_signal(
                    signal="ContainerExposingDangerousPort",
                    severity="Critical",
                    context={"agent_id": agent_id, "container_id": container_id, "ports": ports}
                ))

        await db.commit()

        # Mark containers not in this snapshot as Stopped
        await self.mark_missing_containers_stopped(db, agent_id, seen_ids)
        return signals

    async def mark_missing_containers_stopped(
        self, db: AsyncSession, agent_id: str, seen_ids: set
    ):
        """Marks containers from previous snapshot not seen in current one as Stopped."""
        result = await db.execute(
            select(ContainerAsset).where(
                ContainerAsset.AgentId == agent_id,
                ContainerAsset.State == "Running"
            )
        )
        running = result.scalars().all()
        for container in running:
            if container.ContainerId not in seen_ids:
                container.State = "Stopped"
        await db.commit()

    # ---------------------------------------------------------------------------
    # Kubernetes
    # ---------------------------------------------------------------------------

    async def process_k8s_state(
        self, db: AsyncSession, agent_id: str, pods: List[Dict[str, Any]]
    ):
        """Upserts Kubernetes pod/namespace/cluster state."""
        for pod in pods:
            pod_name = pod.get("pod_name", "")
            result = await db.execute(
                select(KubernetesAsset).where(
                    KubernetesAsset.AgentId == agent_id,
                    KubernetesAsset.PodName == pod_name
                )
            )
            asset = result.scalars().first()
            if not asset:
                asset = KubernetesAsset(AgentId=agent_id, PodName=pod_name)
                db.add(asset)

            asset.ClusterName = pod.get("cluster_name")
            asset.Namespace = pod.get("namespace")
            asset.Status = pod.get("status", "Running")
            asset.LastSeen = datetime.datetime.utcnow()

        await db.commit()

    # ---------------------------------------------------------------------------
    # Cloud Context Enrichment
    # ---------------------------------------------------------------------------

    async def enrich_telemetry(
        self, db: AsyncSession, agent_id: str, raw_event: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Injects cloud + Kubernetes context into a raw endpoint telemetry event."""
        meta_result = await db.execute(
            select(CloudMetadata).where(CloudMetadata.AgentId == agent_id)
        )
        meta = meta_result.scalars().first()

        k8s_result = await db.execute(
            select(KubernetesAsset).where(KubernetesAsset.AgentId == agent_id)
        )
        k8s = k8s_result.scalars().first()

        enriched = raw_event.copy()
        if meta:
            enriched["cloud"] = {
                "provider": meta.Provider,
                "account_id": meta.AccountId,
                "region": meta.Region,
                "instance_id": meta.InstanceId,
                "iam_role": meta.IamRole,
            }
        if k8s:
            enriched["kubernetes"] = {
                "cluster": k8s.ClusterName,
                "namespace": k8s.Namespace,
                "pod": k8s.PodName,
            }
        return enriched

    # ---------------------------------------------------------------------------
    # Cloud Inventory Summary
    # ---------------------------------------------------------------------------

    async def get_cloud_inventory_summary(self, db: AsyncSession) -> Dict[str, Any]:
        """Returns aggregated cloud inventory stats for the SOC dashboard."""
        vm_result = await db.execute(select(CloudMetadata))
        vms = vm_result.scalars().all()

        container_result = await db.execute(select(ContainerAsset))
        containers = container_result.scalars().all()

        k8s_result = await db.execute(select(KubernetesAsset))
        k8s_assets = k8s_result.scalars().all()

        # Provider breakdown
        providers: Dict[str, int] = {}
        regions: Dict[str, int] = {}
        for vm in vms:
            p = vm.Provider or "Unknown"
            providers[p] = providers.get(p, 0) + 1
            r = vm.Region or "Unknown"
            regions[r] = regions.get(r, 0) + 1

        privileged = sum(1 for c in containers if c.IsPrivileged)
        running = sum(1 for c in containers if c.State == "Running")

        return {
            "total_vms": len(vms),
            "total_containers": len(containers),
            "running_containers": running,
            "privileged_containers": privileged,
            "total_k8s_pods": len(k8s_assets),
            "providers": providers,
            "regions": regions,
        }

    # ---------------------------------------------------------------------------
    # Risk Signal Aggregation
    # ---------------------------------------------------------------------------

    async def generate_cloud_risk_signals(self, db: AsyncSession) -> List[Dict[str, Any]]:
        """Scans current cloud inventory and generates pending risk signals."""
        signals = []
        vm_result = await db.execute(select(CloudMetadata))
        vms = vm_result.scalars().all()

        for vm in vms:
            if not vm.TagsJson or vm.TagsJson == "{}":
                signals.append({
                    "type": "UntaggedInstance",
                    "severity": "Low",
                    "agent_id": vm.AgentId,
                    "detail": f"Instance {vm.InstanceId} in {vm.Region} has no tags"
                })
            iam = vm.IamRole or ""
            if any(t in iam.lower() for t in ("admin", "root", "*")):
                signals.append({
                    "type": "OverlyPermissiveIAM",
                    "severity": "High",
                    "agent_id": vm.AgentId,
                    "detail": f"IAM role '{iam}' on {vm.InstanceId} is overly permissive"
                })

        container_result = await db.execute(select(ContainerAsset).where(ContainerAsset.IsPrivileged == True))
        priv_containers = container_result.scalars().all()
        for c in priv_containers:
            signals.append({
                "type": "PrivilegedContainer",
                "severity": "High",
                "agent_id": c.AgentId,
                "detail": f"Container {c.ContainerId} ({c.ImageName}) is running in privileged mode"
            })

        return signals


cloud_engine = CloudVisibilityEngine()
