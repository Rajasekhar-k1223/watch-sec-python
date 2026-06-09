import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy import select, func # type: ignore

from ..db.models import EventLog, Agent, AuditLog, AgentSoftware, Policy # type: ignore

logger = logging.getLogger("ComplianceEngine")

@dataclass
class ComplianceCheckResult:
    framework: str
    check_name: str
    status: str  # "Pass", "Fail", "Warning"
    finding: str
    recommendation: str


class ComplianceService:
    """
    [v2.6.0] Executive Compliance Engine: Generates narrative reports for regulators
    and performs automated checks against compliance frameworks (GDPR, HIPAA, SOC2).
    """
    
    # ---------------------------------------------------------------------------
    # Narrative Generation
    # ---------------------------------------------------------------------------
    
    async def generate_executive_summary(self, tenant_id: int, db: AsyncSession) -> Dict[str, Any]:
        """Synthesizes technical security data into a human-readable executive story."""
        
        # 1. Threat Neutralization Stats (24h)
        threat_query = select(EventLog).where(
            EventLog.TenantId == tenant_id,
            EventLog.Timestamp >= datetime.utcnow() - timedelta(days=30),
            EventLog.Severity.in_(["High", "Critical"])
        )
        result = await db.execute(threat_query)
        threats = result.scalars().all()
        total_neutralized = len([t for t in threats if getattr(t, "Status", "") == "Resolved"])
        
        # 2. Fleet Resilience (Cluster Health)
        agent_query = select(Agent).where(Agent.TenantId == tenant_id)
        agent_result = await db.execute(agent_query)
        agents = agent_result.scalars().all()
        online_percent = (len([a for a in agents if a.Status == "Online"]) / len(agents)) * 100 if agents else 0
        
        # 3. Vulnerability Posture
        total_vulns = 0
        if agents:
            vuln_query = select(func.sum(AgentSoftware.VulnerabilityCount)).where(
                AgentSoftware.AgentId.in_([a.AgentId for a in agents])
            )
            vuln_result = await db.execute(vuln_query)
            total_vulns = vuln_result.scalar() or 0
        
        # 4. Narrative Synthesis
        report = {
            "title": "Executive Security & Compliance Narrative",
            "period": "Last 30 Days",
            "generatedAt": datetime.utcnow().isoformat(),
            "metrics": {
                "resilienceScore": f"{round(online_percent, 1)}%",
                "threatsNeutralized": total_neutralized,
                "outstandingVulnerabilities": int(total_vulns)
            },
            "narrative": (
                f"During this period, the Monitorix Autonomous Defense system maintained a fleet resilience of {online_percent:.1f}%. "
                f"The Edge Threat Engine identified and neutralized {total_neutralized} high-severity incidents autonomously. "
                f"Current vulnerability surface area stands at {total_vulns} identified CVEs across {len(agents)} assets."
            ),
            "recommendations": [
                "Schedule a vulnerability patching window for Nginx/Apache clusters.",
                f"Review resolution notes for the {len(threats) - total_neutralized} unresolved critical incidents.",
                "Verify Zero-Trust OIDC settings for the new SOC analyst accounts."
            ]
        }
        
        return report

    # ---------------------------------------------------------------------------
    # Automated Framework Checks
    # ---------------------------------------------------------------------------
    
    async def run_gdpr_checks(self, tenant_id: int, db: AsyncSession) -> List[ComplianceCheckResult]:
        """Runs automated checks mapped to GDPR Articles."""
        results = []
        
        # Check 1: PII Retention (Article 5) - Are we storing events > 90 days?
        old_events_query = select(func.count(EventLog.Id)).where(
            EventLog.TenantId == tenant_id,
            EventLog.Timestamp < datetime.utcnow() - timedelta(days=90)
        )
        res = await db.execute(old_events_query)
        old_count = res.scalar() or 0
        
        if old_count > 0:
            results.append(ComplianceCheckResult(
                "GDPR", "Data Minimization (Art 5)", "Fail",
                f"{old_count} security events found older than 90 days.",
                "Configure automated log rotation or adjust retention policy to < 90 days."
            ))
        else:
            results.append(ComplianceCheckResult(
                "GDPR", "Data Minimization (Art 5)", "Pass",
                "No telemetry data older than 90 days found.", ""
            ))
            
        # Check 2: Screenshot/Visual Privacy Consent
        policy_res = await db.execute(select(Policy).where(Policy.TenantId == tenant_id, Policy.ScreenshotEnabled == True))
        active_screenshot_policies = len(policy_res.scalars().all())
        if active_screenshot_policies > 0:
            results.append(ComplianceCheckResult(
                "GDPR", "Visual Privacy (Art 6)", "Warning",
                f"{active_screenshot_policies} policies have screenshot monitoring enabled.",
                "Ensure explicit employee consent is collected if deploying in the EU."
            ))
            
        return results

    async def run_hipaa_checks(self, tenant_id: int, db: AsyncSession) -> List[ComplianceCheckResult]:
        """Runs automated checks mapped to HIPAA Security Rule."""
        results = []
        
        # Check 1: Audit Controls (164.312(b))
        audit_res = await db.execute(select(func.count(AuditLog.Id)).where(AuditLog.TenantId == tenant_id))
        audit_count = audit_res.scalar() or 0
        if audit_count == 0:
            results.append(ComplianceCheckResult(
                "HIPAA", "Audit Controls (164.312b)", "Fail",
                "No administrative audit logs recorded for this tenant.",
                "Enable system audit logging for all admin actions."
            ))
        else:
            results.append(ComplianceCheckResult(
                "HIPAA", "Audit Controls (164.312b)", "Pass",
                f"Audit logging is active ({audit_count} records).", ""
            ))
            
        # Check 2: EPHI Access Control (Screenshots)
        policy_res = await db.execute(select(Policy).where(Policy.TenantId == tenant_id, Policy.ScreenshotEnabled == True))
        if len(policy_res.scalars().all()) > 0:
            results.append(ComplianceCheckResult(
                "HIPAA", "EPHI Access (164.312a1)", "Warning",
                "Screenshot monitoring is active and may capture EPHI on screen.",
                "Configure application blocking or specific exclusions for EHR software."
            ))
            
        return results

    async def run_soc2_checks(self, tenant_id: int, db: AsyncSession) -> List[ComplianceCheckResult]:
        """Runs automated checks mapped to SOC 2 Trust Services Criteria."""
        results = []
        
        # Check 1: Logical Access (CC6.1) - Unresolved Criticals
        crit_res = await db.execute(
            select(func.count(EventLog.Id)).where(
                EventLog.TenantId == tenant_id,
                EventLog.Severity == "Critical",
                EventLog.Status != "Resolved"
            )
        )
        crit_count = crit_res.scalar() or 0
        
        if crit_count > 0:
            results.append(ComplianceCheckResult(
                "SOC2", "Incident Response (CC7.3)", "Fail",
                f"{crit_count} Critical incidents remain unresolved.",
                "Review and remediate critical security alerts immediately."
            ))
        else:
            results.append(ComplianceCheckResult(
                "SOC2", "Incident Response (CC7.3)", "Pass",
                "No unresolved critical incidents.", ""
            ))
            
        # Check 2: Endpoint Protection (CC6.8)
        agents_res = await db.execute(select(Agent).where(Agent.TenantId == tenant_id))
        agents = agents_res.scalars().all()
        offline = sum(1 for a in agents if a.Status != "Online")
        if agents and (offline / len(agents)) > 0.2:
            results.append(ComplianceCheckResult(
                "SOC2", "Endpoint Security (CC6.8)", "Warning",
                f"{offline} out of {len(agents)} agents are currently offline.",
                "Investigate disconnected agents to ensure continuous endpoint coverage."
            ))
        else:
             results.append(ComplianceCheckResult(
                "SOC2", "Endpoint Security (CC6.8)", "Pass",
                "High availability of endpoint sensors.", ""
            ))
            
        return results

    async def run_all_checks(self, tenant_id: int, db: AsyncSession) -> Dict[str, Any]:
        """Executes all compliance framework checks and calculates an overall score."""
        gdpr = await self.run_gdpr_checks(tenant_id, db)
        hipaa = await self.run_hipaa_checks(tenant_id, db)
        soc2 = await self.run_soc2_checks(tenant_id, db)
        
        all_checks = gdpr + hipaa + soc2
        
        # Calculate Score (Pass = 1, Warning = 0.5, Fail = 0)
        total_points = 0
        for check in all_checks:
            if check.status == "Pass": total_points += 1
            elif check.status == "Warning": total_points += 0.5
            
        max_points = len(all_checks)
        score_percent = (total_points / max_points) * 100 if max_points > 0 else 100
        
        return {
            "overall_score": round(score_percent, 1),
            "total_checks": max_points,
            "passed": sum(1 for c in all_checks if c.status == "Pass"),
            "warnings": sum(1 for c in all_checks if c.status == "Warning"),
            "failures": sum(1 for c in all_checks if c.status == "Fail"),
            "frameworks": {
                "GDPR": [c.__dict__ for c in gdpr],
                "HIPAA": [c.__dict__ for c in hipaa],
                "SOC2": [c.__dict__ for c in soc2]
            }
        }

# Global instance
compliance_engine = ComplianceService()
