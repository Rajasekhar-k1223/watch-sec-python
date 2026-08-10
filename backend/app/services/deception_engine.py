from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.db.models import DeceptionCampaign, HoneyToken, DeceptionAlert
import random
import string

class DeceptionEngine:

    async def get_tokens_for_agent(self, db: AsyncSession, agent_id: str):
        active_campaigns = (await db.execute(select(DeceptionCampaign).where(DeceptionCampaign.IsActive == True))).scalars().all()
        tokens = []

        for camp in active_campaigns:
            existing = (await db.execute(
                select(HoneyToken).where(HoneyToken.CampaignId == camp.Id, HoneyToken.AgentId == agent_id)
            )).scalars().first()

            if existing:
                tokens.append({
                    "id": existing.Id,
                    "type": camp.Type,
                    "path": existing.TokenPath,
                    "payload": camp.PayloadTemplate
                })
            else:
                random_suffix = ''.join(random.choices(string.digits, k=4))
                if camp.Type == "File":
                    path = f"C:\\Users\\Public\\Documents\\financial_Q3_{random_suffix}.xlsx"
                elif camp.Type == "Credential":
                    path = f"svc_backup_{random_suffix}"
                else:
                    path = f"\\\\WIN-DC-01\\HiddenShare_{random_suffix}"

                new_token = HoneyToken(
                    CampaignId=camp.Id,
                    AgentId=agent_id,
                    TokenPath=path
                )
                db.add(new_token)
                await db.commit()

                tokens.append({
                    "id": new_token.Id,
                    "type": camp.Type,
                    "path": path,
                    "payload": camp.PayloadTemplate
                })

        return tokens

    async def process_trigger(self, db: AsyncSession, payload: dict):
        agent_id = payload.get("agent_id")
        token_path = payload.get("token_path")
        process_id = payload.get("process_id")
        action = payload.get("action")

        token = (await db.execute(
            select(HoneyToken).where(HoneyToken.AgentId == agent_id, HoneyToken.TokenPath == token_path)
        )).scalars().first()

        if not token:
            return False, "Unrecognized token"

        alert = DeceptionAlert(
            TokenId=token.Id,
            AgentId=agent_id,
            ProcessId=process_id,
            Action=action
        )
        db.add(alert)
        await db.commit()

        print(f"[DECEPTION ENGINE] HIGH FIDELITY ALERT! Agent {agent_id} interacted with Honey Token {token_path} via PID {process_id}")
        return True, alert.Id

deception_engine = DeceptionEngine()
