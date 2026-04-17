import pandas as pd # type: ignore
import numpy as np # type: ignore
from sklearn.feature_extraction.text import CountVectorizer # type: ignore
from sklearn.naive_bayes import MultinomialNB # type: ignore
from sklearn.pipeline import make_pipeline # type: ignore
import joblib # type: ignore
import os # type: ignore

class SecurityAIService:
    def __init__(self):
        self.model = None
        # [v1.8.37] Forensic Isolation: Move training data to protected vault
        self.data_path = "storage/security_data.csv" 
        os.makedirs("storage", exist_ok=True)
        self._initialize_model()

    def _initialize_model(self):
        # 1. Load Data
        if os.path.exists(self.data_path):
            try:
                df = pd.read_csv(self.data_path)
            except:
                df = pd.DataFrame()
        else:
            # Seed with Security Data
            data = {
                'text': [
                    'Failed password for root from 192.168.1.1', 
                    'sudo: user attempts to execute malicious script', 
                    'USB Drive detected: E:\ (Volume Serial X)',
                    'System shutdown initiated by user',
                    'Network scan detected from external IP',
                    'File deleted: C:\Windows\System32\drivers\etc\hosts'
                ],
                'category': [
                    'Authentication Failure', 'Privilege Escalation', 'DLP Event', 'System Event', 'Network Intrusion', 'File Integrity'
                ]
            }
            df = pd.DataFrame(data)
            df.to_csv(self.data_path, index=False)

        # 2. Train Model
        if not df.empty and 'text' in df.columns and 'category' in df.columns:
            try:
                X = df['text']
                y = df['category']
                
                self.model = make_pipeline(CountVectorizer(), MultinomialNB())
                self.model.fit(X, y)
                print("[AI] Security Anomaly Model Initialized.")
            except Exception as e:
                 print(f"[AI] Model Training Failed: {e}")
        else:
            print("[AI] Warning: Security Dataset empty.")

    def predict(self, text: str):
        if not self.model:
            return {"category": "Unknown", "confidence": "0.00%"}
        
        try:
            prediction = self.model.predict([text])[0]
            probs = self.model.predict_proba([text])[0]
            confidence = np.max(probs) * 100
            
            return {
                "category": prediction,
                "confidence": f"{confidence:.2f}%"
            }
        except Exception as e:
            return {"error": str(e)}

    def analyze_network_risk(self, upload_mb: float, processes: list):
        """Analyzes network activity for potential exfiltration risk."""
        if not processes:
            return {"RiskScore": 0, "RiskLevel": "Normal", "Triggers": []}

        risk_score = 0
        triggers = []
        
        # 1. Critical Exfiltration Processes (Instant High Risk if volume > 20MB)
        critical_suspects = [r"powershell", r"cmd", r"nmap", r"wireshark", r"python", r"curl", r"wget", r"nc", r"netcat"]
        
        # 2. Known Safe Processes (Decrease Risk Score)
        safe_processes = [r"chrome", r"firefox", r"msedge", r"svchost", r"teams", r"zoom", r"dropbox", r"onedrive"]
        
        # 3. Heuristic Scoring
        import re # type: ignore
        has_critical = False
        for pname in processes:
            pname_lower = pname.lower()
            
            # Check Critical
            for pattern in critical_suspects:
                if re.search(pattern, pname_lower):
                    risk_score += 50
                    triggers.append(f"Suspicious Process Detected: {pname}")
                    has_critical = True
                    break
            
            # Check Safe (if not already found critical)
            is_safe = False
            for pattern in safe_processes:
                if re.search(pattern, pname_lower):
                    is_safe = True
                    break
            
            if not is_safe and not has_critical:
                risk_score += 10 # Unknown process weight
        
        # 4. Volume Weighting
        if upload_mb > 500:
            risk_score += 100 # Massive upload
            triggers.append(f"Critical Volume Detected: {upload_mb}MB")
        elif upload_mb > 100:
            risk_score += 40
            triggers.append(f"High Volume Upload: {upload_mb}MB")
        elif upload_mb > 20 and has_critical:
            risk_score += 50 # Small upload but suspicious tool
            triggers.append(f"Suspicious tool used for {upload_mb}MB upload")

        # 5. Determine Risk Level
        risk_level = "Normal"
        if risk_score > 30: risk_level = "Medium"
        if risk_score > 60: risk_level = "High"
        if risk_score >= 100: risk_level = "Critical"
        
        return {
            "RiskScore": min(risk_score, 100),
            "RiskLevel": risk_level,
            "Triggers": list(set(triggers)),
            "Recommendation": "Isolate Host" if risk_level in ["High", "Critical"] else "Monitor"
        }

    def analyze_usb_risk(self, inventory: list):
        """Analyzes a list of files from a USB drive for potential sensitive data leakage."""
        if not inventory:
            return {"RiskScore": 0, "RiskLevel": "Normal", "Triggers": []}

        risk_score = 0
        triggers = []
        
        # 1. Critical Patterns (Instant 100 Score)
        critical_patterns = [r"payroll", r"salary", r"bank_statement", r"source_code", r"db_dump", r"ssn", r"customer_list"]
        
        # 2. General Leak Patterns (Weight: 20 per match)
        leak_patterns = {
            "PII/Financial": [r"tax", r"invoice", r"bank", r"credit_card", r"passport", r"identity"],
            "Business Confidential": [r"confidential", r"internal", r"restricted", r"strategy", r"roadmap", r"client", r"contract"],
            "Technical Assets": [r"config", r"password", r"key", r"backup", r"secret", r"env", r"private"]
        }
        
        # 3. Heuristic Scoring
        import re # type: ignore
        for filepath in inventory:
            filename = filepath.lower()
            
            # Check for CRITICAL triggers first
            for pattern in critical_patterns:
                if re.search(pattern, filename):
                    risk_score = 100
                    triggers.append(f"CRITICAL MATCH (Auto-Isolation): {pattern}")
                    break
            
            if risk_score >= 100: break # No need to check more if already critical

            # General matching logic
            for category, patterns in leak_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, filename):
                        risk_score += 20
                        triggers.append(f"{category} match: {pattern}")
                        break
        
        # 4. Determine Risk Level
        risk_level = "Normal"
        if risk_score > 20: risk_level = "Medium"
        if risk_score > 60: risk_level = "High"
        if risk_score >= 100: risk_level = "Critical"
        
        return {
            "RiskScore": min(risk_score, 100),
            "RiskLevel": risk_level,
            "Triggers": list(set(triggers)),
            "Recommendation": "Isolate Host" if risk_level in ["High", "Critical"] else "Monitor"
        }

    def learn(self, text: str, category: str):
        """[v1.8.37] Anonymized Learning: Scrub PII before committing to training set."""
        from ..core.privacy import BackendPrivacyRedactor
        scrubbed_text = BackendPrivacyRedactor.redact_text(text)
        
        new_data = pd.DataFrame({'text': [scrubbed_text], 'category': [category]})
        
        mode = 'a' if os.path.exists(self.data_path) else 'w'
        header = not os.path.exists(self.data_path)
        
        new_data.to_csv(self.data_path, mode=mode, header=header, index=False)
        
        # [SECURITY] Restrict file permissions (Owner RW only)
        try: os.chmod(self.data_path, 0o600)
        except: pass

        self._initialize_model()
        return True

# Singleton Instance
ai_service = SecurityAIService()
