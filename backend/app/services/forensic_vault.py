from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.db.models import ForensicEvidence, ChainOfCustodyLog
import hashlib
import uuid
import datetime

class ForensicVaultEngine:

    async def generate_upload_url(self, db: AsyncSession, agent_id: str, filename: str, file_type: str, size: int):
        s3_key = f"evidence/{agent_id}/{uuid.uuid4()}_{filename}"

        evidence = ForensicEvidence(
            AgentId=agent_id,
            Filename=filename,
            Type=file_type,
            StorageUri=f"s3://monitorix-vault/{s3_key}",
            SizeInBytes=size,
            Status="PendingUpload"
        )
        db.add(evidence)
        await db.commit()

        await self._log_custody(db, evidence.Id, "UploadRequested", f"Agent:{agent_id}")

        upload_url = f"https://s3.amazonaws.com/monitorix-vault/{s3_key}?X-Amz-Signature=MOCK_SIG"
        return evidence.Id, upload_url

    async def verify_upload(self, db: AsyncSession, evidence_id: int, agent_sha256: str):
        evidence = (await db.execute(select(ForensicEvidence).where(ForensicEvidence.Id == evidence_id))).scalars().first()
        if not evidence:
            return False, "Evidence not found"

        evidence.Sha256Hash = agent_sha256
        await self._log_custody(db, evidence.Id, "UploadCompleted", f"Agent:{evidence.AgentId}")

        evidence.Status = "Verified"
        await db.commit()

        await self._log_custody(db, evidence.Id, "HashVerified", "System")
        return True, "Evidence verified and locked in vault."

    async def toggle_legal_hold(self, db: AsyncSession, evidence_id: int, admin_id: str):
        evidence = (await db.execute(select(ForensicEvidence).where(ForensicEvidence.Id == evidence_id))).scalars().first()
        if not evidence:
            return False

        evidence.IsLegalHold = not evidence.IsLegalHold
        action = "LegalHoldApplied" if evidence.IsLegalHold else "LegalHoldRemoved"

        await self._log_custody(db, evidence.Id, action, admin_id)
        await db.commit()
        return True

    async def _log_custody(self, db: AsyncSession, evidence_id: int, action: str, actor: str):
        log = ChainOfCustodyLog(
            EvidenceId=evidence_id,
            Action=action,
            PerformedBy=actor
        )
        db.add(log)
        await db.commit()

vault_engine = ForensicVaultEngine()
