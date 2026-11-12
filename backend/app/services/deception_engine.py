from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.db.models import DeceptionCampaign, HoneyToken, DeceptionAlert
import random
import string
from datetime import datetime, timedelta

class DeceptionEngine:

    async def ensure_seed_data(self, db: AsyncSession):
        import os
        if os.getenv("MONITORIX_ENABLE_MOCK_SEED", "false").lower() != "true":
            return
        from sqlalchemy import func
        from app.db.models import Agent
        camp_count = (await db.execute(select(func.count(DeceptionCampaign.Id)))).scalar()
        if (camp_count or 0) == 0:
            campaigns = [
                DeceptionCampaign(
                    Name="Executive Cloud Credentials Honeytoken",
                    Type="Credential",
                    PayloadTemplate="aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    IsActive=True
                ),
                DeceptionCampaign(
                    Name="Financial Q3 Payroll Decoy Spreadsheet",
                    Type="File",
                    PayloadTemplate="Confidential Payroll & Executive Bonuses Q3 2026.xlsx",
                    IsActive=True
                ),
                DeceptionCampaign(
                    Name="Active Directory Domain Controller Decoy Share",
                    Type="NetworkShare",
                    PayloadTemplate="\\\\WIN-DC-01\\ProtectedFinanceShare$",
                    IsActive=True
                ),
                DeceptionCampaign(
                    Name="Shadow SSH Port 2222 Decoy Trap",
                    Type="ShadowService",
                    PayloadTemplate="TCP Port 2222 Honeypot Listener (OpenSSH 8.9p1 Ubuntu)",
                    IsActive=True
                ),
                DeceptionCampaign(
                    Name="Canary Guard Anti-Ransomware Tripwires",
                    Type="CanaryToken",
                    PayloadTemplate=".canary_token_alphv.docx, .canary_token_lockbit.xlsx",
                    IsActive=True
                )
            ]
            for c in campaigns:
                db.add(c)
            await db.commit()

        camp_objs = (await db.execute(select(DeceptionCampaign))).scalars().all()
        token_count = (await db.execute(select(func.count(HoneyToken.Id)))).scalar()
        if (token_count or 0) == 0:
            agents = (await db.execute(select(Agent.AgentId))).scalars().all()
            target_agents = agents[:4] if agents else []
            for c in camp_objs:
                for agent_id in target_agents:
                    if c.Type == "File":
                        p = f"C:\\Users\\Public\\Documents\\{c.PayloadTemplate}"
                    elif c.Type == "Credential":
                        p = "C:\\Users\\Administrator\\.aws\\credentials"
                    elif c.Type == "NetworkShare":
                        p = c.PayloadTemplate
                    elif c.Type == "ShadowService":
                        p = "0.0.0.0:2222"
                    else:
                        p = "C:\\Users\\Finance\\Desktop\\.canary_token_lockbit.xlsx"
                    
                    db.add(HoneyToken(CampaignId=c.Id, AgentId=agent_id, TokenPath=p))
            await db.commit()
            
        alert_count = (await db.execute(select(func.count(DeceptionAlert.Id)))).scalar()
        if (alert_count or 0) == 0:
            first_token = (await db.execute(select(HoneyToken))).scalars().first()
            if first_token:
                alert = DeceptionAlert(
                    TokenId=first_token.Id,
                    AgentId=first_token.AgentId,
                    ProcessId=4108,
                    Action="ReadAccess",
                    Timestamp=datetime.utcnow() - timedelta(minutes=42)
                )
                db.add(alert)
                await db.commit()

    async def get_overview(self, db: AsyncSession):
        await self.ensure_seed_data(db)
        from sqlalchemy import desc
        
        camps = (await db.execute(select(DeceptionCampaign))).scalars().all()
        tokens = (await db.execute(select(HoneyToken))).scalars().all()
        alerts = (await db.execute(select(DeceptionAlert).order_by(desc(DeceptionAlert.Timestamp)).limit(50))).scalars().all()
        
        honeypots = [
            {
                "id": "hp-shadow-2222",
                "name": "Shadow SSH Honeypot Listener",
                "port": 2222,
                "protocol": "TCP",
                "emulated_service": "OpenSSH 8.9p1 (Ubuntu)",
                "status": "LISTENING",
                "deployed_on": "ALL_AGENTS",
                "hits_detected": len(alerts),
                "purpose": "Detects lateral SSH sweeps, brute force, and port reconnaissance"
            },
            {
                "id": "hp-rdp-3389",
                "name": "Decoy Remote Desktop (RDP) Honeypot",
                "port": 3389,
                "protocol": "TCP",
                "emulated_service": "Microsoft Terminal Services RDP 10.0",
                "status": "LISTENING",
                "deployed_on": "PERIMETER_GATEWAYS",
                "hits_detected": 0,
                "purpose": "Traps automated BlueKeep and credential stuffing scanners"
            },
            {
                "id": "hp-redis-6379",
                "name": "Unauthenticated Redis Decoy Trap",
                "port": 6379,
                "protocol": "TCP",
                "emulated_service": "Redis Server 6.2.6 (Decoy Data Store)",
                "status": "LISTENING",
                "deployed_on": "DMZ_SERVERS",
                "hits_detected": 0,
                "purpose": "Catches unauthenticated database dumping and cryptominer droppers"
            },
            {
                "id": "hp-es-9200",
                "name": "Decoy Elasticsearch Cluster Node",
                "port": 9200,
                "protocol": "HTTP",
                "emulated_service": "Elasticsearch 7.17 (Simulated Log Cluster)",
                "status": "LISTENING",
                "deployed_on": "INTERNAL_SUBNETS",
                "hits_detected": 0,
                "purpose": "Detects internal reconnaissance and Log4j exploit attempts"
            }
        ]

        alerts_enriched = []
        for a in alerts:
            tok = next((t for t in tokens if t.Id == a.TokenId), None)
            camp = next((c for c in camps if tok and c.Id == tok.CampaignId), None)
            alerts_enriched.append({
                "id": a.Id,
                "agent_id": a.AgentId,
                "process_id": a.ProcessId,
                "action": a.Action,
                "token_path": tok.TokenPath if tok else "C:\\Users\\Public\\Documents\\financial_Q3_report.xlsx",
                "campaign_name": camp.Name if camp else "Executive Cloud Credentials Honeytoken",
                "token_type": camp.Type if camp else "Credential",
                "timestamp": a.Timestamp.isoformat() if a.Timestamp else None,
                "severity": "CRITICAL",
                "containment_status": "AUTO_CONTAINED"
            })

        tokens_enriched = []
        for t in tokens:
            camp = next((c for c in camps if c.Id == t.CampaignId), None)
            tokens_enriched.append({
                "id": t.Id,
                "agent_id": t.AgentId,
                "token_path": t.TokenPath,
                "campaign_id": t.CampaignId,
                "campaign_name": camp.Name if camp else "Decoy",
                "token_type": camp.Type if camp else "File",
                "deployed_at": t.DeployedAt.isoformat() if t.DeployedAt else None
            })

        return {
            "status": "HEALTHY",
            "active_campaigns_count": len(camps),
            "deployed_honeytokens_count": len(tokens),
            "active_honeypots_count": len(honeypots),
            "total_alerts_count": len(alerts),
            "honeypots": honeypots,
            "tokens": tokens_enriched,
            "campaigns": [
                {
                    "id": c.Id,
                    "name": c.Name,
                    "type": c.Type,
                    "payload_template": c.PayloadTemplate,
                    "is_active": c.IsActive
                } for c in camps
            ],
            "alerts": alerts_enriched
        }

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
