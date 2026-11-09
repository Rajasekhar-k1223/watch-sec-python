"""
Monitorix Enterprise Detection Alert Persistence Service
========================================================
High-reliability, tenant-isolated persistence for Sigma and SIEM detection matches.

Key Capabilities:
1. Idempotency & Deduplication: 5-minute sliding window on (AgentId, RuleId, MatchedContent).
2. Kafka Replay Immunity: Replayed events increment HitCount and update LastSeenAt without duplicating rows.
3. Metadata Preservation: Rule ID, MITRE ATT&CK tactic/technique, severity, agent identity, timestamps.
4. Tenant Isolation: Associates authoritative TenantId with each alert.
5. Transactional Integrity: Atomic session commits with explicit rollback on error.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc

from app.db.models import DetectionAlert, DetectionRule, Agent
from app.services.detection.sigma_compiler import DetectionResult

logger = logging.getLogger("monitorix.detection.persistence")

DEDUPLICATION_WINDOW_MINUTES = 5


class AlertPersistenceService:
    """
    Dedicated detection alert persistence manager with sliding-window deduplication
    and multi-tenant isolation guarantees.
    """

    def __init__(self, dedup_window_minutes: int = DEDUPLICATION_WINDOW_MINUTES):
        self.dedup_window_minutes = dedup_window_minutes

    async def persist_detection_match(
        self,
        db: AsyncSession,
        event: Dict[str, Any],
        match: DetectionResult,
        agent_id: str,
        authoritative_tenant_id: Optional[int],
        telemetry_id: int = 0
    ) -> Tuple[DetectionAlert, bool]:
        """
        Persists a single detection result into DetectionAlerts with sliding-window deduplication.
        
        Returns:
            Tuple[DetectionAlert, bool]: (alert_instance, is_new_alert)
            where is_new_alert is True if a new alert was created, False if deduplicated.
        """
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=self.dedup_window_minutes)

        # Build human-readable matched content
        evidence_summary = []
        details_map = getattr(match, "matched_fields", getattr(match, "details", {})) or {}
        if isinstance(details_map, dict):
            for k, v in list(details_map.items())[:5]:
                evidence_summary.append(f"{k}={v}")
        
        evidence_str = ", ".join(evidence_summary) if evidence_summary else "pattern match"
        
        # Command line or search target for correlation
        cmdline = (
            event.get("CommandLine") or 
            event.get("cmdline") or 
            event.get("cmd") or 
            (event.get("Payload", {}).get("cmdline") if isinstance(event.get("Payload"), dict) else "")
        ) or ""
        
        rule_name = getattr(match, "rule_name", getattr(match, "rule_title", f"Rule #{match.rule_id}"))
        matched_content = f"[{rule_name}] Matched: {evidence_str}"
        if cmdline:
            matched_content += f" | CommandLine: {str(cmdline)[:300]}"

        # Deduplication query with strict multi-tenant isolation
        dedup_conditions = [
            DetectionAlert.AgentId == agent_id,
            DetectionAlert.RuleId == match.rule_id,
            DetectionAlert.MatchedContent == matched_content,
            DetectionAlert.LastSeenAt >= cutoff
        ]
        if hasattr(DetectionAlert, "TenantId"):
            if authoritative_tenant_id is not None:
                dedup_conditions.append(DetectionAlert.TenantId == authoritative_tenant_id)
            else:
                dedup_conditions.append(DetectionAlert.TenantId == None)

        query = (
            select(DetectionAlert)
            .where(*dedup_conditions)
            .order_by(desc(DetectionAlert.Id))
            .limit(1)
        )
        res = await db.execute(query)
        existing_alert = res.scalars().first()

        if existing_alert:
            # Replay / Deduplication path: increment hit count and refresh timestamp
            existing_alert.HitCount = (existing_alert.HitCount or 1) + 1
            existing_alert.LastSeenAt = now
            return existing_alert, False

        # Reject alert creation if authoritative tenant identity is missing
        if authoritative_tenant_id is None:
            logger.warning(
                f"[AlertPersistence] Dropping alert creation for agent '{agent_id}': "
                f"Missing authoritative tenant identity"
            )
            return None, False

        # New alert creation with authoritative tenant attribution
        event_ts = self._extract_event_timestamp(event)
        new_alert = DetectionAlert(
            TenantId=authoritative_tenant_id,
            AgentId=agent_id,
            RuleId=match.rule_id,
            TelemetryId=telemetry_id,
            MatchedContent=matched_content,
            Status="New",
            Timestamp=event_ts,
            HitCount=1,
            LastSeenAt=now
        )

        db.add(new_alert)
        return new_alert, True

    async def persist_matches_batch(
        self,
        db: AsyncSession,
        event: Dict[str, Any],
        matches: List[DetectionResult],
        agent_id: str,
        authoritative_tenant_id: Optional[int],
        telemetry_id: int = 0
    ) -> List[Tuple[DetectionAlert, bool]]:
        """
        Persists a collection of detection results inside an atomic transaction.
        Rolls back on error and re-raises.
        """
        if not matches:
            return []

        if authoritative_tenant_id is None:
            logger.warning(
                f"[AlertPersistence] Rejecting batch alert persistence for agent '{agent_id}': "
                f"Missing authoritative tenant identity"
            )
            return []

        results: List[Tuple[DetectionAlert, bool]] = []
        try:
            for match in matches:
                alert, is_new = await self.persist_detection_match(
                    db=db,
                    event=event,
                    match=match,
                    agent_id=agent_id,
                    authoritative_tenant_id=authoritative_tenant_id,
                    telemetry_id=telemetry_id
                )
                if alert is not None:
                    results.append((alert, is_new))

            await db.commit()
            
            # Post-commit: trigger async notifications for newly created alerts
            for alert, is_new in results:
                if is_new:
                    await self._notify_alert_async(alert, authoritative_tenant_id)

            return results

        except Exception as e:
            await db.rollback()
            logger.error(f"[AlertPersistence] Transaction failed for agent {agent_id}: {e}")
            raise

    def _extract_event_timestamp(self, event: Dict[str, Any]) -> datetime:
        """Extracts and normalizes client or ingest timestamp from event dictionary."""
        raw_ts = (
            event.get("original_timestamp") or
            event.get("Timestamp") or
            event.get("timestamp") or
            event.get("detected_at") or
            event.get("TimeCreated")
        )
        if not raw_ts:
            return datetime.utcnow()

        try:
            if isinstance(raw_ts, str):
                return datetime.fromisoformat(raw_ts.replace("Z", "+00:00")).replace(tzinfo=None)
            elif isinstance(raw_ts, (int, float)):
                return datetime.utcfromtimestamp(raw_ts)
        except Exception:
            pass
        return datetime.utcnow()

    async def _notify_alert_async(self, alert: DetectionAlert, tenant_id: Optional[int]):
        """Non-blocking notification hook for WebSockets and downstream systems."""
        try:
            from app.socket_instance import sio
            room = f"tenant_{tenant_id}" if tenant_id else "global_alerts"
            payload = {
                "alert_id": alert.Id,
                "agent_id": alert.AgentId,
                "rule_id": alert.RuleId,
                "matched_content": alert.MatchedContent,
                "hit_count": alert.HitCount,
                "timestamp": alert.Timestamp.isoformat() if alert.Timestamp else datetime.utcnow().isoformat()
            }
            await sio.emit("detection_alert", payload, room=room)
        except Exception as e:
            logger.debug(f"[AlertPersistence] Socket notification suppressed or unavailable: {e}")


alert_persistence_service = AlertPersistenceService()
