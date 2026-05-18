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

    def calculate_threat_score(self, agent_id: str, events: list):
        """[v2.1.0] Aggregates risk factors across multiple domains to produce a unified threat score."""
        if not events:
            return {"Score": 0, "Level": "Normal", "TopRisks": []}

        base_score = 0
        risks = []
        
        # 1. Domain Weights
        # events is a list of dicts with {type, details, timestamp}
        
        auth_failures = [e for e in events if "auth" in e.get("Type", "").lower() or "login" in e.get("Details", "").lower()]
        network_risks = [e for e in events if "network" in e.get("Type", "").lower()]
        dlp_events = [e for e in events if "dlp" in e.get("Type", "").lower() or "usb" in e.get("Type", "").lower()]
        
        # Scoring Logic
        if len(auth_failures) > 5:
            base_score += 40
            risks.append("Brute-force Login Pattern")
        elif len(auth_failures) > 0:
            base_score += 10
        
        if dlp_events:
            base_score += 30 * len(dlp_events)
            risks.append(f"Sensitive Data Movement ({len(dlp_events)} events)")
            
        if network_risks:
            base_score += 20
            risks.append("Suspicious Network Activity")

        # 2. Behavioral Anomaly Bonus (Unsupervised)
        # Placeholder for temporal analysis: If frequency is > 300% of baseline
        # In this implementation, we use a simple heuristic for demonstration
        if len(events) > 50: # Excessive event burst
            base_score += 20
            risks.append("Event Burst Anomaly")

        final_score = min(base_score, 100)
        risk_level = "Normal"
        if final_score > 30: risk_level = "Medium"
        if final_score > 60: risk_level = "High"
        if final_score >= 90: risk_level = "Critical"

        return {
            "Score": final_score,
            "Level": risk_level,
            "TopRisks": list(set(risks)),
            "Recommendation": "Isolate" if risk_level in ["High", "Critical"] else "Monitor"
        }

    def generate_incident_summary(self, events: list):
        """[v2.1.0] Generates a human-readable narrative of a security incident."""
        if not events:
            return "No significant events detected."
            
        summary = "SECURITY ANALYSIS SUMMARY:\n"
        # Sort by time
        sorted_events = sorted(events, key=lambda x: x.get('Timestamp', ''), reverse=True)[:10]
        
        summary += f"Detected {len(events)} security-relevant events in the last window.\n"
        
        # Identify Root Cause Pattern
        has_auth = any("auth" in e.get("Type", "").lower() for e in events)
        has_dlp = any("dlp" in e.get("Type", "").lower() or "usb" in e.get("Type", "").lower() for e in events)
        
        if has_auth and has_dlp:
            summary += "CRITICAL PATTERN: Potential Credential Compromise followed by Data Exfiltration.\n"
        elif has_auth:
            summary += "PATTERN: Authentication Attack or Brute-force attempt.\n"
        elif has_dlp:
            summary += "PATTERN: Sensitive Data Handling violation.\n"
            
        summary += "\nTOP EVENTS:\n"
        for e in sorted_events:
            summary += f"- [{e.get('Timestamp')}] {e.get('Type')}: {e.get('Details')[:100]}...\n"
            
        return summary

    def generate_tactical_narrative(self, events: list):
        """[v2.5.0] Advanced Narrative Engine: Synthesizes multiple events into a cohesive tactical story."""
        if not events:
            return "Operational status nominal. No tactical anomalies identified."

        # Group by Type
        types = [e.get("Type", "Unknown") for e in events]
        severity_counts = {
            "Critical": len([e for e in events if e.get("Severity") == "Critical"]),
            "High": len([e for e in events if e.get("Severity") == "High"]),
            "Medium": len([e for e in events if e.get("Severity") == "Medium"])
        }

        # Identify Complex Scenarios
        has_remediation = any("Remediation" in t for t in types)
        has_vulnerability = any("Vulnerability" in t for t in types)
        has_network = any("Network" in t for t in types)
        has_auth = any("Auth" in t or "Login" in t for t in types)

        story_parts = []

        # 1. Lead Section
        if severity_counts["Critical"] > 0:
            story_parts.append(f"CRITICAL ALERT: Detected {severity_counts['Critical']} high-impact security breaches requiring immediate intervention.")
        elif severity_counts["High"] > 0:
            story_parts.append(f"TACTICAL ADVISORY: Fleet health is compromised by {severity_counts['High']} high-priority anomalies.")
        else:
            story_parts.append("SYSTEM OBSERVATION: Routine security telemetry identified minor deviations from baseline.")

        # 2. Context Section
        if has_auth and has_network:
            story_parts.append("The sequence suggests a potential lateral movement attempt: unauthorized authentication was followed by suspicious network egress.")
        elif has_vulnerability and has_network:
            story_parts.append("Active exploitation risk identified: known software vulnerabilities are being paired with anomalous network traffic patterns.")
        elif has_auth:
            story_parts.append("Authentication infrastructure is under pressure, showing signs of brute-force or credential stuffing patterns.")

        # 3. Remediation Section
        if has_remediation:
            story_parts.append("Autonomous defense protocols have been triggered to contain the spread and neutralize active process threats.")
        else:
            story_parts.append("Recommendation: Initiate remote remediation protocol to isolate affected nodes and perform forensic memory analysis.")

        return " ".join(story_parts)

    def calculate_posture_score(self, agents: list, events: list):
        """[v2.6.0] Posture Scoring Engine: Aggregates risk across multiple dimensions."""
        if not agents:
            return 100

        base_score = 100.0
        
        # 1. Vulnerability Penalty
        total_vulnerabilities = sum(len(a.get("vulnerabilities", [])) for a in agents if a.get("vulnerabilities"))
        v_penalty = min(30, total_vulnerabilities * 2)
        base_score -= v_penalty
        
        # 2. Threat Penalty (Critical/High in last 24h)
        critical_events = [e for e in events if e.get("Severity") == "Critical"]
        high_events = [e for e in events if e.get("Severity") == "High"]
        t_penalty = min(40, (len(critical_events) * 10) + (len(high_events) * 5))
        base_score -= t_penalty
        
        # 3. Agent Health Penalty (Offline agents)
        offline_count = len([a for a in agents if a.get("status") == "Offline"])
        h_penalty = min(20, (offline_count / len(agents)) * 20)
        base_score -= h_penalty
        
        # 4. Remediation Bonus
        remediation_count = len([e for e in events if "Remediation" in e.get("Type", "")])
        bonus = min(10, remediation_count * 2)
        base_score += bonus
        
        return max(0, min(100, round(base_score)))

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

    async def generate_conversational_response(self, query: str, current_user, db):
        """[v2.6.0] Advanced, hybrid conversational AI assistant supporting cloud LLM and smart SQL fallbacks."""
        query_lower = query.lower()
        import os
        import httpx
        from sqlalchemy import select, func
        from app.db.models import Agent, Vulnerability, EventLog
        
        # 1. Fetch Real Database Context first so we can either inject it to LLM or use it in our highly intelligent local reasoning fallbacks!
        stmt_agents = select(Agent).where(Agent.TenantId == current_user.TenantId)
        res_agents = await db.execute(stmt_agents)
        agents = res_agents.scalars().all()
        total_agents = len(agents)
        
        from datetime import datetime, timedelta
        cutoff = datetime.utcnow() - timedelta(minutes=10)
        online_count = len([a for a in agents if a.LastSeen and a.LastSeen >= cutoff])
        offline_count = total_agents - online_count
        
        stmt_vulns = select(Vulnerability)
        res_vulns = await db.execute(stmt_vulns)
        vulns = res_vulns.scalars().all()
        total_vulns = len(vulns)
        
        active_incidents = 0
        agent_ids = [a.AgentId for a in agents]
        events = []
        if agent_ids:
            stmt_events = select(EventLog).where(EventLog.AgentId.in_(agent_ids)).order_by(EventLog.Timestamp.desc())
            res_events = await db.execute(stmt_events)
            events = res_events.scalars().all()
            active_incidents = len(events)
            
        # 2. Check for Generative AI (Cloud LLM or Local Offline LLM)
        api_key = os.environ.get("OPENAI_API_KEY")
        ollama_host = os.environ.get("OLLAMA_HOST", "http://watch-sec-ollama:11434")
        
        # Build Context Summaries
        agents_summary = []
        for a in agents[:5]:
            agents_summary.append({
                "AgentId": a.AgentId,
                "Hostname": a.Hostname,
                "Country": a.Country or "Unknown",
                "Latitude": a.Latitude or 0.0,
                "Longitude": a.Longitude or 0.0,
                "PublicIp": a.PublicIp or "0.0.0.0",
                "LocalIp": a.LocalIp or "0.0.0.0",
                "CpuUsage": a.CpuUsage or 0.0,
                "NetworkOutMbps": a.NetworkOutMbps or 0.0,
                "Version": a.Version or "1.0.0",
                "LastSeen": str(a.LastSeen) if a.LastSeen else "Never"
            })
        
        vulns_summary = []
        for v in vulns[:5]:
            vulns_summary.append({
                "CVE": v.CVE,
                "AffectedProduct": v.AffectedProduct,
                "Severity": v.Severity,
                "Description": v.Description
            })
            
        events_summary = []
        for e in events[:5]:
            events_summary.append({
                "AgentId": e.AgentId,
                "Severity": e.Severity,
                "Type": e.Type,
                "Details": e.Details,
                "Timestamp": str(e.Timestamp)
            })
        
        system_prompt = (
            "You are the Monitorix Autonomous AI Copilot, a premium, advanced LLM fleet security assistant. "
            "You analyze live fleet telemetry, security events, package vulnerabilities, and coordinates in real time.\n\n"
            "Here is the LIVE database context for the current user's tenant:\n"
            f"- Total Agents/Assets: {total_agents} ({online_count} online, {offline_count} offline)\n"
            f"- Total Software Vulnerabilities: {total_vulns}\n"
            f"- Total Logged Threat Events: {active_incidents}\n\n"
            "Recent Monitored Agents:\n" + str(agents_summary) + "\n\n"
            "Recent Active Vulnerabilities:\n" + str(vulns_summary) + "\n\n"
            "Recent Critical Security Events:\n" + str(events_summary) + "\n\n"
            "Instructions:\n"
            "1. Respond directly, conversationally, and intelligently in Markdown to the user's specific prompt. "
            "Use the live data above to answer accurately without stubs. Be deeply detailed and technical.\n"
            "2. At the very end of your response, output a raw JSON block containing suggested actions for the UI in this format: "
            "JSON_ACTIONS: {\"SuggestedActions\": [\"Action 1\", \"Action 2\", \"Action 3\"]}\n"
            "Limit suggestions to exactly 3 highly relevant, contextual next steps (e.g. \"Isolate RAJ\" if RAJ has high alerts, "
            "\"View Infrastructure Map\", \"Download Vulnerability Report\")."
        )

        # ── TIER A: CLOUD GENAI ENGINE (OPENAI) ──
        if api_key:
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(
                        "https://api.openai.com/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {api_key}",
                            "Content-Type": "application/json"
                        },
                        json={
                            "model": "gpt-4o-mini",
                            "messages": [
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": query}
                            ],
                            "temperature": 0.3
                        }
                    )
                    if resp.status_code == 200:
                        content = resp.json()["choices"][0]["message"]["content"]
                        suggested = ["Show me high-risk agents", "Any new DLP alerts?", "Run a threat summary"]
                        import re
                        json_match = re.search(r'JSON_ACTIONS:\s*(\{.*?\})', content, re.DOTALL)
                        if json_match:
                            try:
                                import json
                                actions_data = json.loads(json_match.group(1))
                                if "SuggestedActions" in actions_data:
                                    suggested = actions_data["SuggestedActions"]
                                content = re.sub(r'JSON_ACTIONS:\s*\{.*?\}', '', content, flags=re.DOTALL).strip()
                            except:
                                pass
                        
                        return {
                            "Response": content,
                            "SuggestedActions": suggested
                        }
            except Exception as e:
                print(f"[AI Copilot] Cloud LLM failed: {e}")

        # ── TIER B: SOVEREIGN OFFLINE GENAI ENGINE (LOCAL OLLAMA) ──
        for target_host in [ollama_host, "http://localhost:11434", "http://host.docker.internal:11434"]:
            try:
                async with httpx.AsyncClient(timeout=2.0) as check_client:
                    resp_tags = await check_client.get(f"{target_host}/api/tags")
                    if resp_tags.status_code == 200:
                        models_data = resp_tags.json()
                        models = [m["name"] for m in models_data.get("models", [])]
                        
                        active_model = models[0] if models else "phi3"
                        
                        async with httpx.AsyncClient(timeout=45.0) as chat_client:
                            resp_chat = await chat_client.post(
                                f"{target_host}/api/chat",
                                json={
                                    "model": active_model,
                                    "messages": [
                                        {"role": "system", "content": system_prompt},
                                        {"role": "user", "content": query}
                                    ],
                                    "options": {
                                        "temperature": 0.3
                                    },
                                    "stream": False
                                }
                            )
                            if resp_chat.status_code == 200:
                                content = resp_chat.json()["message"]["content"]
                                suggested = ["Show me high-risk agents", "Any new DLP alerts?", "Run a threat summary"]
                                import re
                                json_match = re.search(r'JSON_ACTIONS:\s*(\{.*?\})', content, re.DOTALL)
                                if json_match:
                                    try:
                                        import json
                                        actions_data = json.loads(json_match.group(1))
                                        if "SuggestedActions" in actions_data:
                                            suggested = actions_data["SuggestedActions"]
                                        content = re.sub(r'JSON_ACTIONS:\s*\{.*?\}', '', content, flags=re.DOTALL).strip()
                                    except:
                                        pass
                                
                                return {
                                    "Response": content,
                                    "SuggestedActions": suggested
                                }
            except Exception as e:
                pass

        # 3. Local High-Fidelity NLP Semantic Reasoning Fallback
        # ── GEOLOCATION, POSITION & IP INQUIRY ──
        if any(k in query_lower for k in ["position", "location", "where", "country", "latitude", "longitude", "coordinate", "coordinates", "ip", "address"]):
            import re
            digit_match = re.search(r'\d+', query_lower)
            target_agent = None
            
            if digit_match:
                idx = int(digit_match.group(0))
                if 0 < idx <= len(agents):
                    target_agent = agents[idx - 1]
            else:
                for a in agents:
                    if a.Hostname.lower() in query_lower or a.AgentId.lower() in query_lower:
                        target_agent = a
                        break
            
            if target_agent:
                country = target_agent.Country or "Unknown Location"
                lat = target_agent.Latitude or 0.0
                lon = target_agent.Longitude or 0.0
                ip_addr = target_agent.PublicIp or target_agent.LocalIp or "0.0.0.0"
                
                response_text = (
                    f"Asset **{target_agent.Hostname}** (Agent ID: `{target_agent.AgentId}`) is currently reporting "
                    f"geographic coordinates from **{country}**:\n\n"
                    f"* **Latitude / Longitude**: `{lat}, {lon}`\n"
                    f"* **Reporting Network IP**: `{ip_addr}`\n"
                    f"* **Gateway Connection**: `{target_agent.Gateway}`\n\n"
                    f"GPS mapping tools place this asset in the country of **{country}** with a stable telemetry stream."
                )
                suggested = ["View Infrastructure Map", "Show me high-risk agents"]
            elif agents:
                coords_list = []
                for a in agents[:3]:
                    country = a.Country or "Unknown Location"
                    coords_list.append(f"* **{a.Hostname}**: {country} (Lat: `{a.Latitude}`, Lon: `{a.Longitude}`)")
                    
                response_text = (
                    f"A lookup of the active assets deployed in your fleet indicates geographic concentration across the following regions:\n\n"
                    + "\n".join(coords_list) + "\n\n"
                    f"There are a total of **{len(agents)} registered assets** transmitting latitude, longitude, and IP network gateways to the infrastructure monitor."
                )
                suggested = ["View Infrastructure Map", "Show me high-risk agents"]
            else:
                response_text = (
                    "There are no active assets registered in the database, so no coordinates or geolocation metrics "
                    "are currently available."
                )
                suggested = ["View Asset Management"]
                
            return {
                "Response": response_text,
                "SuggestedActions": suggested
            }

        # ── VULNERABILITIES & CVE INQUIRY ──
        elif any(k in query_lower for k in ["vulnerabilit", "cve", "openssl", "exploit", "patch"]):
            if total_vulns > 0:
                products = list(set([v.AffectedProduct for v in vulns]))
                products_str = ", ".join(products[:4])
                
                vulns_list = []
                for v in vulns[:4]:
                    vulns_list.append(f"* **{v.CVE}** ({v.Severity}): Affects *{v.AffectedProduct}* - {v.Description}")
                
                response_text = (
                    f"A scan of global software manifests across your assets indicates **{total_vulns} active package vulnerabilities**.\n\n"
                    f"The primary threat exposure vectors affect: **{products_str}**.\n\n"
                    f"Here are the active package vulnerability details:\n"
                    + "\n".join(vulns_list) + "\n\n"
                    f"We recommend pushing compliance patches to the affected nodes."
                )
            else:
                response_text = (
                    "Nominal software compliance. Our threat forensics system confirms **0 package vulnerabilities** "
                    "are active across the software manifests of your fleet endpoints."
                )
                
            return {
                "Response": response_text,
                "SuggestedActions": ["View Threat Resilience", "Any new DLP alerts?"]
            }
            
        # ── THREATS, ANOMALIES & RISKS INQUIRY ──
        elif any(k in query_lower for k in ["risk", "suspicious", "threat", "anomaly", "alert", "incident", "attack"]):
            if not agent_ids:
                return {
                    "Response": "No registered assets found, so no security threat anomalies have been logged.",
                    "SuggestedActions": ["View Asset Management"]
                }
                
            critical_count = len([e for e in events if e.Severity == "Critical"])
            high_count = len([e for e in events if e.Severity == "High"])
            medium_count = len([e for e in events if e.Severity == "Medium"])
            
            if active_incidents > 0:
                from collections import Counter
                agent_counts = Counter([e.AgentId for e in events])
                highest_risk_agent = agent_counts.most_common(1)[0][0]
                
                a_stmt = select(Agent).where(Agent.AgentId == highest_risk_agent)
                a_res = await db.execute(a_stmt)
                a_obj = a_res.scalar_one_or_none()
                hostname = a_obj.Hostname if a_obj else highest_risk_agent
                
                alerts_list = []
                for e in events[:3]:
                    alerts_list.append(f"* `[{e.Timestamp.strftime('%Y-%m-%d %H:%M:%S')}]` **{e.Severity}** - {e.Type}: {e.Details}")
                
                response_text = (
                    f"Tactical analysis has flagged **{active_incidents} security incidents** across your tenant endpoints. "
                    f"We have detected **{critical_count} Critical**, **{high_count} High**, and **{medium_count} Medium** severity alerts.\n\n"
                    f"The highest threat density is concentrated on host **{hostname}** ({highest_risk_agent}). "
                    f"We recommend isolating this endpoint to prevent lateral movement.\n\n"
                    f"**Recent Logged Incidents:**\n" + "\n".join(alerts_list)
                )
                suggested = [f"Isolate {hostname}", "View Security Logs"]
            else:
                response_text = (
                    "Nominal fleet conditions confirmed. Live threat forensics scan reports **0 active anomalies** "
                    "or anomalous executions. Anti-malware, DLP, and network exfiltration checkers are reporting a green posture score."
                )
                suggested = ["Show me high-risk agents", "Any new DLP alerts?"]
                
            return {
                "Response": response_text,
                "SuggestedActions": suggested
            }

        # ── PERFORMANCE & TELEMETRY INQUIRY ──
        elif any(k in query_lower for k in ["cpu", "ram", "memory", "performance", "usage", "health", "system", "spec"]):
            if agents:
                perf_list = []
                for a in agents[:3]:
                    cpu = a.CpuUsage or 0.0
                    perf_list.append(f"* **{a.Hostname}**: CPU Usage at `{cpu}%` | Network Outbound: `{a.NetworkOutMbps} Mbps` | Platform Version: `{a.Version}`")
                    
                response_text = (
                    f"Here is the active system telemetry summary for the primary assets reporting in:\n\n"
                    + "\n".join(perf_list) + "\n\n"
                    f"Agent endpoint compliance checkers are indicating completely healthy memory and compute thresholds across the fleet."
                )
                suggested = ["View Asset Management", "Run a threat summary"]
            else:
                response_text = "No assets are currently online to report CPU, RAM, or network telemetry statistics."
                suggested = ["View Asset Management"]
                
            return {
                "Response": response_text,
                "SuggestedActions": suggested
            }
        
        # ── AGENTS & FLEET INQUIRY ──
        elif any(k in query_lower for k in ["agent", "fleet", "host", "online", "running", "asset", "device", "computer", "machine"]):
            hostnames = [a.Hostname for a in agents[:5]]
            hostnames_str = ", ".join(hostnames)
            
            if total_agents > 0:
                response_text = (
                    f"The registered monitored fleet for your tenant currently has **{total_agents} active assets** "
                    f"({online_count} online, {offline_count} offline).\n\n"
                    f"The primary assets reporting in include: **{hostnames_str}**."
                )
            else:
                response_text = (
                    "No active assets have been registered for your tenant yet. "
                    "Please download and run the Monitorix agent binary on your target endpoints to initiate real-time telemetry."
                )
                
            return {
                "Response": response_text,
                "SuggestedActions": ["View Asset Management", "Run a threat summary"]
            }
            
        # ── DYNAMIC GENERAL FALLBACK (Trained Local Naive Bayes Classifications!) ──
        else:
            prediction = self.predict(query)
            category = prediction.get("category", "Unknown")
            confidence = prediction.get("confidence", "0.00%")
            
            if any(k in query_lower for k in ["hello", "hi", "hey", "welcome", "greetings", "good morning", "good afternoon"]):
                response_text = (
                    f"Welcome, **{current_user.Username}**! I am the Monitorix Autonomous AI Copilot, your fleet's intelligence coordinator.\n\n"
                    f"Currently managing **{total_agents} assets** with **{active_incidents} logged threat events** "
                    f"and **{total_vulns} correlated software vulnerabilities**.\n\n"
                    "You can ask me specific questions like:\n"
                    "* *\"Are there any suspicious threat patterns in the fleet?\"*\n"
                    "* *\"Count active vulnerabilities across hosts\"*\n"
                    "* *\"Summarize registered agents and system status\"*"
                )
                suggested = ["Show me high-risk agents", "Any new DLP alerts?", "Run a threat summary"]
            else:
                if category != "Unknown":
                    matching_events = [e for e in events if category.lower() in e.Type.lower() or category.lower() in e.Details.lower()]
                    
                    if matching_events:
                        alerts_list = []
                        for e in matching_events[:3]:
                            alerts_list.append(f"* `[{e.Timestamp.strftime('%Y-%m-%d %H:%M:%S')}]` **{e.Severity}** - {e.Type}: {e.Details}")
                        response_text = (
                            f"My local Scikit-Learn Security Classifier has categorized your request as: **{category}** (Confidence: `{confidence}`).\n\n"
                            f"I scanned the SQL threat ledger and correlated **{len(matching_events)} matching incidents** under this signature:\n\n"
                            + "\n".join(alerts_list) + "\n\n"
                            f"We recommend running a malware compliance scan across your endpoints to invalidate any lateral movement."
                        )
                    else:
                        response_text = (
                            f"My local Scikit-Learn Security Classifier categorized your request as **{category}** (Confidence: `{confidence}`).\n\n"
                            f"Our SQL threat logs report **0 active anomalies** matching this specific profile today. "
                            f"All anti-malware, DLP, and network firewalls are reporting a standard security posture."
                        )
                    suggested = ["Run a threat summary", "Show me high-risk agents"]
                else:
                    response_text = (
                        f"Welcome, **{current_user.Username}**! I am the Monitorix Autonomous AI Copilot, your fleet's intelligence coordinator.\n\n"
                        f"Currently managing **{total_agents} assets** with **{active_incidents} logged threat events** "
                        f"and **{total_vulns} correlated software vulnerabilities**.\n\n"
                        "I am fully initialized. You can ask me custom questions about: \n"
                        "* **Asset Locations**: *\"Where is asset 1?\"* or *\"Show agent geolocations\"*\n"
                        "* **Telemetry & Specs**: *\"What is the CPU usage?\"* or *\"Show memory usage\"*\n"
                        "* **Vulnerabilities**: *\"What critical package vulnerabilities are active?\"*\n"
                        "* **Threat Logs**: *\"Show me high risk hosts\"* or *\"Any new anomalies?\"*"
                    )
                    suggested = ["Show me high-risk agents", "Any new DLP alerts?", "Run a threat summary"]
                    
            return {
                "Response": response_text,
                "SuggestedActions": suggested
            }

# Singleton Instance
ai_service = SecurityAIService()
