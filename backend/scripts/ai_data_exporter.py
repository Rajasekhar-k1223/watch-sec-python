import os
import json
import csv
from datetime import datetime
import re

class AIDataExporter:
    """[v2.7.1] Sovereign AI Dataset & RAG Exporter Utility (CSV Optimized)"""
    
    def __init__(self, csv_path="backend/security_data.csv", output_dir="exports/ai_training"):
        self.csv_path = csv_path
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        
    def _anonymize(self, text):
        """Redacts sensitive patterns (IPs, Usernames) from text."""
        if not text: return ""
        # Redact IPs
        text = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '<IP_REDACTED>', text)
        # Redact common username patterns
        text = re.sub(r'user[:\s]+[a-zA-Z0-9._-]+', 'user: <USER_REDACTED>', text)
        return text

    def export_from_csv(self, limit=10000):
        """Generates Fine-Tuning (JSONL) and RAG (MD) datasets from the security_data.csv."""
        ft_file = os.path.join(self.output_dir, f"fine_tuning_{datetime.now().strftime('%Y%m%d')}.jsonl")
        rag_file = os.path.join(self.output_dir, f"kb_rag_{datetime.now().strftime('%Y%m%d')}.md")
        
        if not os.path.exists(self.csv_path):
            print(f"[ERROR] Security CSV not found at {self.csv_path}")
            return

        try:
            count = 0
            with open(self.csv_path, mode='r', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                
                with open(ft_file, "w") as ft_f, open(rag_file, "w") as rag_f:
                    rag_f.write("# Monitorix Sovereign Security Intelligence Base\n")
                    rag_f.write(f"Generated on: {datetime.now().isoformat()}\n\n")
                    
                    for row in reader:
                        text = row.get('text', '')
                        category = row.get('category', 'General')
                        
                        clean_text = self._anonymize(text)
                        
                        # 1. Fine-Tuning JSONL
                        entry = {
                            "instruction": "Analyze this security event and classify it.",
                            "input": clean_text,
                            "output": f"This event is classified as: {category}. Recommended Action: Perform deep forensic audit of affected subsystem."
                        }
                        ft_f.write(json.dumps(entry) + "\n")
                        
                        # 2. RAG Markdown
                        if count < 500: # Limit RAG file size for readability
                            rag_f.write(f"### Security Pattern: {category}\n")
                            rag_f.write(f"- **Description**: {clean_text}\n")
                            rag_f.write(f"- **Classification**: {category}\n\n")
                        
                        count += 1
                        if count >= limit: break
            
            print(f"[SUCCESS] Exported {count} entries from CSV.")
            print(f"- Fine-Tuning: {ft_file}")
            print(f"- RAG KB: {rag_file}")
            
        except Exception as e:
            print(f"[ERROR] CSV Export failed: {e}")

if __name__ == "__main__":
    exporter = AIDataExporter()
    print("--- Monitorix AI Data Export Utility (Sovereign Dataset) ---")
    exporter.export_from_csv()
    print("-----------------------------------------------------------")
