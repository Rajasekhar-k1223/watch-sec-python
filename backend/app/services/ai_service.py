import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
import joblib
import os

class SecurityAIService:
    def __init__(self):
        self.model = None
        self.data_path = "security_data.csv" 
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

    def learn(self, text: str, category: str):
        new_data = pd.DataFrame({'text': [text], 'category': [category]})
        
        if os.path.exists(self.data_path):
            new_data.to_csv(self.data_path, mode='a', header=False, index=False)
        else:
            new_data.to_csv(self.data_path, index=False)
            
        self._initialize_model()
        return True

# Singleton Instance
ai_service = SecurityAIService()
