import re
import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.db.models import DlpRule, DlpPolicy, DlpPolicyRuleLink, DlpViolation

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
        if category == "PII" and len(match_str) > 4:
            return match_str[:2] + ("*" * (len(match_str) - 4)) + match_str[-2:]
        elif category == "Secrets":
            return "[REDACTED SECRET]"
        return "****"

    async def evaluate_payload(self, db: AsyncSession, agent_id: str, channel: str, text_payload: str):
        if not self.rules_cache:
            await self.load_policies(db)

        action_to_take = "Allow"
        violations_logged = []

        applicable_policies = []
        for policy in self.policies_cache:
            channels = json.loads(policy.TargetChannelsJson)
            if channel in channels:
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

                        if policy.Action == "Block":
                            action_to_take = "Block"
                        elif policy.Action == "Alert" and action_to_take != "Block":
                            action_to_take = "Alert"

                        sample = str(matches[0])
                        obfuscated = self.obfuscate_match(sample, rule_meta.Category)

                        violation = DlpViolation(
                            AgentId=agent_id,
                            PolicyId=policy.Id,
                            RuleId=rid,
                            Channel=channel,
                            MatchedContentObfuscated=obfuscated,
                            ActionTaken=policy.Action
                        )
                        db.add(violation)
                        violations_logged.append(violation)

                        if policy.Action == "Block":
                            try:
                                from app.services.dispatcher_service import dispatcher
                                import asyncio
                                event = {
                                    "source": "dlp_engine",
                                    "signal": "DataLossPreventionBlocked",
                                    "severity": "Critical",
                                    "context": {
                                        "agent_id": agent_id,
                                        "channel": channel,
                                        "obfuscated_sample": obfuscated
                                    }
                                }
                                asyncio.create_task(dispatcher.dispatch_siem_webhook(db, agent_id, event))
                                
                                # Spawn a SOAR Execution Record for SOC visibility
                                from app.db.models import SoarActionExecution
                                execution = SoarActionExecution(
                                    PlaybookId=0, # 0 = Built-in DLP Policy
                                    TargetAgentId=agent_id,
                                    ActionType="DLP_Block",
                                    Status="Success",
                                    ExecutedBy="System"
                                )
                                db.add(execution)
                            except Exception as e:
                                print(f"[DLP] Error dispatching SIEM/SOAR signal: {e}")

        if violations_logged:
            await db.commit()

        return action_to_take, [v.Id for v in violations_logged]

dlp_engine = DlpEngine()
