from sqlalchemy.orm import Session
from app.db.models import ForensicEvidence, ChainOfCustodyLog
import hashlib
import uuid
import datetime

class ForensicVaultEngine:
    
    def generate_upload_url(self, db: Session, agent_id: str, filename: str, file_type: str, size: int):
        """
        Creates a pending evidence record and returns a mocked S3 pre-signed URL.
        """
        # 1. Create DB record in Pending status
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
        db.commit() # Get ID
        
        # 2. Log Chain of Custody
        self._log_custody(db, evidence.Id, "UploadRequested", f"Agent:{agent_id}")
        
        # 3. Mock S3 Pre-signed URL generation
        upload_url = f"https://s3.amazonaws.com/monitorix-vault/{s3_key}?X-Amz-Signature=MOCK_SIG"
        
        return evidence.Id, upload_url

    def verify_upload(self, db: Session, evidence_id: int, agent_sha256: str):
        """
        Called by the agent after it finishes uploading the blob to S3.
        Mocks the background process of the backend downloading the S3 object
        and verifying the hash to ensure Chain of Custody integrity.
        """
        evidence = db.query(ForensicEvidence).filter(ForensicEvidence.Id == evidence_id).first()
        if not evidence:
            return False, "Evidence not found"
            
        evidence.Sha256Hash = agent_sha256
        self._log_custody(db, evidence.Id, "UploadCompleted", f"Agent:{evidence.AgentId}")
        
        # MOCK VERIFICATION: Assume the S3 blob hash matches the agent's reported hash
        # In production, this would trigger a Celery task: `verify_s3_hash.delay(evidence.StorageUri, agent_sha256)`
        evidence.Status = "Verified"
        db.commit()
        
        self._log_custody(db, evidence.Id, "HashVerified", "System")
        
        return True, "Evidence verified and locked in vault."
        
    def toggle_legal_hold(self, db: Session, evidence_id: int, admin_id: str):
        """Applies or removes legal hold, preventing automated deletion."""
        evidence = db.query(ForensicEvidence).filter(ForensicEvidence.Id == evidence_id).first()
        if not evidence:
            return False
            
        evidence.IsLegalHold = not evidence.IsLegalHold
        action = "LegalHoldApplied" if evidence.IsLegalHold else "LegalHoldRemoved"
        
        self._log_custody(db, evidence.Id, action, admin_id)
        db.commit()
        return True

    def _log_custody(self, db: Session, evidence_id: int, action: str, actor: str):
        log = ChainOfCustodyLog(
            EvidenceId=evidence_id,
            Action=action,
            PerformedBy=actor
        )
        db.add(log)
        db.commit()

vault_engine = ForensicVaultEngine()
