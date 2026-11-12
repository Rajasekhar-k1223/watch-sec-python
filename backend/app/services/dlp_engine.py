import re
import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.db.models import DlpRule, DlpPolicy, DlpPolicyRuleLink, DlpViolation, HashBank

class DlpEngine:
    def __init__(self):
        self.rules_cache = {}
        self.policies_cache = []

    async def load_policies(self, db: AsyncSession):
        rules = (await db.execute(select(DlpRule).where(DlpRule.IsActive == True))).scalars().all()
        self.rules_cache.clear()

        for r in rules:
            try:
                self.rules_cache[r.Id] = re.compile(r.Pattern)
            except Exception:
                pass

        self.policies_cache = (await db.execute(select(DlpPolicy).where(DlpPolicy.IsActive == True))).scalars().all()

    def obfuscate_match(self, match_str: str, category: str) -> str:
        if category in ("PII", "PHI", "Financial", "PCI-DSS") and len(match_str) > 4:
            return match_str[:2] + ("*" * (len(match_str) - 4)) + match_str[-2:]
        elif category in ("Secrets", "Secret", "Credential"):
            return "[REDACTED SECRET]"
        return "****"

    def scan_global_pii(self, text_payload: str, country: str = None):
        """Delegates multi-country PII classification to the 25-jurisdiction Compliance Classifier Registry."""
        try:
            from app.compliance.classifiers.registry import pii_classifier_registry
            return pii_classifier_registry.scan_text(text_payload, country_filter=country)
        except Exception:
            return []

    async def evaluate_payload(
        self,
        db: AsyncSession,
        agent_id: str,
        channel: str,
        text_payload: str,
        file_name: str = None,
        file_hash: str = None,
        file_size: int = None,
        process_name: str = None,
        destination: str = None,
        user_upn: str = None,
        override_justification: str = None,
    ):
        if not self.rules_cache:
            await self.load_policies(db)

        action_to_take = "Allow"
        violations_logged = []

        # 1. Check HashBank for pre-classified document fingerprints
        if file_hash:
            try:
                hb_entry = (await db.execute(select(HashBank).where(HashBank.Sha256 == file_hash))).scalars().first()
                if hb_entry and (hb_entry.Reputation in ("Malicious", "Restricted", "Banned") or getattr(hb_entry, "IsRestricted", False)):
                    violation = DlpViolation(
                        AgentId=agent_id,
                        PolicyId=None,
                        RuleId=None,
                        Channel=channel,
                        MatchedContentObfuscated=f"[HashBank Match: Restricted Document] File={file_name or 'N/A'}, Hash={file_hash}",
                        ActionTaken="Blocked"
                    )
                    db.add(violation)
                    await db.commit()
                    return "Block", [violation.Id]
            except Exception:
                pass

        applicable_policies = []
        for policy in self.policies_cache:
            try:
                channels = json.loads(policy.TargetChannelsJson) if policy.TargetChannelsJson else []
            except Exception:
                channels = []
            if channel in channels or "*" in channels:
                applicable_policies.append(policy)

        if not applicable_policies:
            return action_to_take, violations_logged

        for policy in applicable_policies:
            links = (await db.execute(select(DlpPolicyRuleLink).where(DlpPolicyRuleLink.PolicyId == policy.Id))).scalars().all()
            rule_ids = [link.RuleId for link in links]

            for rid in rule_ids:
                if rid in self.rules_cache:
                    pattern = self.rules_cache[rid]
                    matches = pattern.findall(text_payload)

                    if matches:
                        rule_meta = (await db.execute(select(DlpRule).where(DlpRule.Id == rid))).scalars().first()
                        category = rule_meta.Category if rule_meta else "PII"

                        # Handle Authorized Override workflow
                        if override_justification:
                            effective_action = "Overridden"
                            action_to_take = "Allow"
                        else:
                            effective_action = policy.Action
                            if policy.Action == "Block":
                                action_to_take = "Block"
                            elif policy.Action == "Alert" and action_to_take != "Block":
                                action_to_take = "Alert"

                        sample = str(matches[0])
                        obfuscated = self.obfuscate_match(sample, category)
                        forensic_info = f"[{effective_action}] {obfuscated} | File: {file_name or 'N/A'}, Hash: {file_hash or 'N/A'}, Dest: {destination or 'N/A'}, User: {user_upn or 'local'}"
                        if override_justification:
                            forensic_info += f", Override: {override_justification}"

                        violation = DlpViolation(
                            AgentId=agent_id,
                            PolicyId=policy.Id,
                            RuleId=rid,
                            Channel=channel,
                            MatchedContentObfuscated=forensic_info,
                            ActionTaken=effective_action
                        )
                        db.add(violation)
                        violations_logged.append(violation)

                        if effective_action == "Block":
                            try:
                                from app.db.models import SoarActionExecution
                                execution = SoarActionExecution(
                                    PlaybookId=1,
                                    TargetAgentId=agent_id,
                                    ActionType="DLP_Block",
                                    Status="Success",
                                    ExecutedBy="System"
                                )
                                db.add(execution)
                            except Exception as e:
                                print(f"[DataGuard] Error recording SOAR action: {e}")

            # Also evaluate national PII compliance classifiers
            try:
                national_detections = self.scan_global_pii(text_payload)
                high_conf = [d for d in national_detections if d.confidence in ("HIGH", "MEDIUM")]
                if high_conf and not violations_logged:
                    if override_justification:
                        effective_action = "Overridden"
                        action_to_take = "Allow"
                    else:
                        effective_action = policy.Action
                        if policy.Action == "Block":
                            action_to_take = "Block"
                        elif policy.Action == "Alert" and action_to_take != "Block":
                            action_to_take = "Alert"

                    first_det = high_conf[0]
                    forensic_info = f"[{effective_action}] [{first_det.identifier}] {first_det.sample_masked} | File: {file_name or 'N/A'}, Dest: {destination or 'N/A'}"
                    if override_justification:
                        forensic_info += f", Override: {override_justification}"

                    violation = DlpViolation(
                        AgentId=agent_id,
                        PolicyId=policy.Id,
                        RuleId=rule_ids[0] if rule_ids else None,
                        Channel=channel,
                        MatchedContentObfuscated=forensic_info,
                        ActionTaken=effective_action,
                    )
                    db.add(violation)
                    violations_logged.append(violation)
            except Exception:
                pass

        if violations_logged:
            await db.commit()

        return action_to_take, [v.Id for v in violations_logged]

dlp_engine = DlpEngine()
