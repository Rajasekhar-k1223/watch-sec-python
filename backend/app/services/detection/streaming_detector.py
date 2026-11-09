"""
Monitorix Enterprise Real-Time Streaming Detection Engine
=========================================================
Connects Kafka telemetry streams to the native Sigma compiler and alert persistence.

Flow:
1. Receive Kafka event (ProcessExecution, PROCESS_START, process_creation).
2. Validate event schema & handle malformed data safely.
3. Resolve trusted agent identity.
4. Resolve authoritative tenant ownership (prevent tenant spoofing).
5. Normalize event fields for optimal Sigma evaluation.
6. Retrieve applicable compiled detection rules (tenant-specific + global).
7. Evaluate rules using evaluate_all().
8. Collect matching DetectionResult objects.
9. Pass matches to AlertPersistenceService with deduplication.
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.db.models import Agent, DetectionRule, DetectionAlert
from app.services.detection.sigma_compiler import (
    sigma_compiler,
    sigma_registry,
    evaluate_all,
    CompiledSigmaRule,
    DetectionResult
)
from app.services.detection.alert_persistence import alert_persistence_service

logger = logging.getLogger("monitorix.detection.streaming")

SUPPORTED_EVENT_TYPES = {
    "ProcessExecution",
    "PROCESS_START",
    "process_creation",
    "ProcessCreate",
    "4688"
}


class StreamingDetectionEngine:
    """
    High-throughput streaming detection engine processing endpoint execution events
    in real time with tenant isolation and safe error handling.
    """

    def __init__(self):
        # Local in-memory agent-to-tenant cache with simple TTL
        self._agent_tenant_cache: Dict[str, Tuple[Optional[int], float]] = {}
        self._cache_ttl_seconds = 300  # 5 minutes
        self.total_events_evaluated = 0
        self.total_matches_detected = 0
        self.total_errors = 0

    async def resolve_authoritative_tenant(
        self,
        db: AsyncSession,
        agent_id: str,
        declared_tenant_id: Optional[Any] = None
    ) -> Optional[int]:
        """
        Resolves trusted tenant ownership from the database.
        Prevents tenant spoofing: if the event declares TenantId=2 but the Agent
        belongs to TenantId=1 in the database, the DB value is authoritative.
        """
        now = datetime.utcnow().timestamp()

        # Check in-memory cache
        if agent_id in self._agent_tenant_cache:
            cached_tenant, expiry = self._agent_tenant_cache[agent_id]
            if now < expiry:
                return cached_tenant

        try:
            # Query DB for agent
            query = select(Agent).where(Agent.AgentId == agent_id)
            res = await db.execute(query)
            agent = res.scalars().first()

            if agent and agent.TenantId is not None:
                authoritative_tenant = agent.TenantId
                self._agent_tenant_cache[agent_id] = (authoritative_tenant, now + self._cache_ttl_seconds)
                return authoritative_tenant

        except Exception as e:
            logger.warning(f"[StreamingDetector] Database error resolving agent tenant for {agent_id}: {e}")

        # Fall back to declared tenant if agent record is not found or DB query failed
        fallback_tenant = None
        if declared_tenant_id is not None:
            try:
                fallback_tenant = int(declared_tenant_id)
            except (ValueError, TypeError):
                fallback_tenant = None

        self._agent_tenant_cache[agent_id] = (fallback_tenant, now + 60)
        return fallback_tenant

    def normalize_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalizes Kafka telemetry event into canonical dictionary format.
        Unpacks nested Payload structures and preserves standard field names.
        """
        normalized = dict(event)
        
        # Unpack nested Payload if present
        payload = event.get("Payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = None
                
        if isinstance(payload, dict):
            for k, v in payload.items():
                if k not in normalized or normalized[k] is None or normalized[k] == "":
                    normalized[k] = v

        # Ensure canonical field aliases are readily available
        if "process_name" in normalized and "Image" not in normalized:
            normalized["Image"] = normalized["process_name"]
        elif "Image" in normalized and "process_name" not in normalized:
            normalized["process_name"] = normalized["Image"]

        if "cmdline" in normalized and "CommandLine" not in normalized:
            normalized["CommandLine"] = normalized["cmdline"]
        elif "CommandLine" in normalized and "cmdline" not in normalized:
            normalized["cmdline"] = normalized["CommandLine"]

        if "parent_process_name" in normalized and "ParentImage" not in normalized:
            normalized["ParentImage"] = normalized["parent_process_name"]
        elif "ParentImage" in normalized and "parent_process_name" not in normalized:
            normalized["parent_process_name"] = normalized["ParentImage"]

        return normalized

    async def get_applicable_rules(
        self,
        db: AsyncSession,
        tenant_id: Optional[int]
    ) -> List[CompiledSigmaRule]:
        """
        Retrieves compiled rules applicable to this tenant:
        - Rules where TenantId == tenant_id
        - Global rules where TenantId IS NULL
        - Only active rules (IsActive == True)
        """
        # If registry already has rules for this tenant/global, check registry first
        rules = sigma_registry.get_rules_for_tenant(tenant_id)
        if rules:
            return rules

        # Query database and compile active rules into registry
        try:
            query = select(DetectionRule).where(
                DetectionRule.IsActive == True,
                (DetectionRule.TenantId == tenant_id) | (DetectionRule.TenantId == None)
            )
            res = await db.execute(query)
            db_rules = res.scalars().all()

            for r in db_rules:
                if r.RuleContent and ("title:" in r.RuleContent or "detection:" in r.RuleContent):
                    try:
                        compiled = sigma_compiler.compile(
                            yaml_content=r.RuleContent,
                            rule_id=r.Id,
                            metadata={
                                "tenant_id": r.TenantId,
                                "mitre_tactic": r.MitreTactic,
                                "mitre_technique": r.MitreTechnique,
                                "category": r.Category
                            }
                        )
                        sigma_registry.register(compiled)
                    except Exception as ce:
                        logger.debug(f"[StreamingDetector] Compilation skipped for rule #{r.Id}: {ce}")

            return sigma_registry.get_rules_for_tenant(tenant_id)

        except Exception as e:
            logger.error(f"[StreamingDetector] Error loading rules from DB: {e}")
            return sigma_registry.get_rules_for_tenant(tenant_id)

    async def process_kafka_event(
        self,
        db: AsyncSession,
        event: Dict[str, Any],
        raw_agent_id: Optional[str] = None
    ) -> List[Tuple[DetectionAlert, bool]]:
        """
        Main entrypoint for Kafka event evaluation.
        Evaluates supported process events against native Sigma rules and persists matches.
        
        Guarantees:
        - Never raises uncaught exceptions that would crash the consumer.
        - Preserves existing ClickHouse telemetry ingestion.
        - Enforces tenant isolation.
        """
        self.total_events_evaluated += 1

        # 1. Schema Validation
        if not isinstance(event, dict):
            logger.warning("[StreamingDetector] Malformed event: expected dict, got %s", type(event))
            return []

        event_type = event.get("EventType") or event.get("event_type") or ""
        if event_type not in SUPPORTED_EVENT_TYPES:
            # Silently pass unsupported events (handled elsewhere by other consumers/ClickHouse)
            return []

        # 2. Agent Identity Resolution
        agent_id = str(raw_agent_id or event.get("AgentId") or event.get("agent_id") or "").strip()
        if not agent_id or agent_id == "Unknown":
            logger.debug("[StreamingDetector] Skipped event with missing or unknown AgentId")
            return []

        try:
            # 3. Authoritative Tenant Resolution
            declared_tenant = event.get("TenantId") or event.get("tenant_id")
            authoritative_tenant = await self.resolve_authoritative_tenant(db, agent_id, declared_tenant)

            # 4. Field Normalization
            normalized_event = self.normalize_event(event)

            # 5. Applicable Rules Retrieval
            applicable_rules = await self.get_applicable_rules(db, authoritative_tenant)
            if not applicable_rules:
                return []

            # 6. Sigma Evaluation
            matches: List[DetectionResult] = evaluate_all(
                event=normalized_event,
                rules=applicable_rules,
                authoritative_tenant_id=authoritative_tenant
            )

            if not matches:
                return []

            self.total_matches_detected += len(matches)

            # 7. Alert Persistence with Deduplication
            persisted = await alert_persistence_service.persist_matches_batch(
                db=db,
                event=normalized_event,
                matches=matches,
                agent_id=agent_id,
                authoritative_tenant_id=authoritative_tenant
            )

            return persisted

        except Exception as e:
            self.total_errors += 1
            logger.error(f"[StreamingDetector] Error evaluating event for agent {agent_id}: {e}", exc_info=True)
            return []

    async def evaluate_threat_intel_ioc_matches(
        self,
        db: AsyncSession,
        event: Dict[str, Any],
        raw_agent_id: Optional[str] = None
    ) -> List[Tuple[DetectionAlert, bool]]:
        """
        Evaluates event for Threat Intelligence (IOC) matches across network, DNS, web,
        process, and file telemetry, preserving authoritative TenantId and deduplication.
        """
        agent_id = str(raw_agent_id or event.get("AgentId") or event.get("agent_id") or "").strip()
        if not agent_id or agent_id == "Unknown":
            return []

        try:
            declared_tenant = event.get("TenantId") or event.get("tenant_id")
            authoritative_tenant = await self.resolve_authoritative_tenant(db, agent_id, declared_tenant)

            from app.services.threat_intel_pipeline import ti_pipeline
            ioc_matches = ti_pipeline.match_event(event, tenant_id=authoritative_tenant)
            if not ioc_matches:
                return []

            detection_results = []
            for match in ioc_matches:
                detection_results.append(
                    DetectionResult(
                        rule_id=9007,
                        rule_name=f"Malicious {match.threat_classification} Indicator: {match.indicator_value} ({match.indicator_type})",
                        severity=match.severity,
                        category="Command and Control",
                        matched=True,
                        details={"ioc_match": match.to_dict()}
                    )
                )

            persisted = await alert_persistence_service.persist_matches_batch(
                db=db,
                event=event,
                matches=detection_results,
                agent_id=agent_id,
                authoritative_tenant_id=authoritative_tenant
            )
            return persisted

        except Exception as e:
            logger.error(f"[StreamingDetector] Threat Intel evaluation error for agent {agent_id}: {e}", exc_info=True)
            return []


streaming_detection_engine = StreamingDetectionEngine()
