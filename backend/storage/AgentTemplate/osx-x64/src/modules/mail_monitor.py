import platform
import threading
import time
import datetime
import logging
import os
import sys
import tempfile
import base64
import requests
import glob
import subprocess

# --- Strategy Interface ---
class MailMonitorStrategy:
    def __init__(self, api_url, agent_id, api_key):
        self.api_url = api_url
        self.agent_id = agent_id
        self.api_key = api_key
        self.running = False
        self.logger = logging.getLogger(self.__class__.__name__)
        # Check for emails in last 10 mins on startup
        self.last_check = datetime.datetime.now() - datetime.timedelta(minutes=10)
        self.sent_ids = set() # Track processed IDs to avoid dupes

    def start(self):
        self.running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        self.logger.info(f"{self.__class__.__name__} Started.")

    def stop(self):
        self.running = False
        self.logger.info(f"{self.__class__.__name__} Stopping.")

    def _loop(self):
        raise NotImplementedError

    def _send_to_backend(self, sender, recipient, subject, body_preview, attachments_data):
        payload = {
            "AgentId": self.agent_id,
            "TenantApiKey": self.api_key,
            "Sender": sender,
            "Recipient": recipient,
            "Subject": subject,
            "BodyPreview": body_preview,
            "HasAttachments": len(attachments_data) > 0,
            "AttachmentNames": ", ".join([a["FileName"] for a in attachments_data]),
            "Timestamp": datetime.datetime.utcnow().isoformat(),
            "Attachments": attachments_data
        }
        
        try:
            # Use specific endpoint if exists, else generic events
            # Original code used /api/mail
            res = requests.post(f"{self.api_url}/api/mail", json=payload, verify=False)
            if res.status_code == 200:
                print(f"[{self.__class__.__name__}] Sent email '{subject}' to backend.")
            else:
                print(f"[{self.__class__.__name__}] Backend rejected: {res.status_code}")
        except Exception as e:
            print(f"[{self.__class__.__name__}] Backend Upload Error: {e}")

# --- Windows Strategy (Outlook COM) ---
class WindowsOutlookStrategy(MailMonitorStrategy):
    def _loop(self):
        try:
            import pythoncom
            import win32com.client
        except ImportError:
            print("[WindowsOutlookStrategy] win32com not found. Mail monitoring disabled.")
            return

        pythoncom.CoInitialize()
        outlook = None
        try:
             outlook = win32com.client.Dispatch("Outlook.Application")
             namespace = outlook.GetNamespace("MAPI")
        except Exception as e:
             print(f"[WindowsOutlookStrategy] Failed to connect to Outlook: {e}")
             return

        print("[WindowsOutlookStrategy] Connected to Outlook.")
        
        while self.running:
            try:
                namespace = outlook.GetNamespace("MAPI")
                # Iterate all stores to find Sent folders
                sent_folders = []
                for store in namespace.Stores:
                    try:
                        root = store.GetRootFolder()
                        for f in root.Folders:
                            if "sent" in f.Name.lower():
                                sent_folders.append(f)
                    except: pass
                
                # Fallback to default
                if not sent_folders:
                    try: sent_folders.append(namespace.GetDefaultFolder(5))
                    except: pass
                
                for folder in sent_folders:
                    try:
                        items = folder.Items
                        items.Sort("[SentOn]", True)
                        
                        # Check top 5
                        for item in list(items)[:5]:
                            try:
                                sent_time = item.SentOn
                                if sent_time.tzinfo: sent_time = sent_time.replace(tzinfo=None)
                                
                                # Use EntryID to prevent duplicates
                                mid = item.EntryID
                                if mid in self.sent_ids: continue

                                if sent_time > self.last_check:
                                    self._process_item(item)
                                    self.sent_ids.add(mid)
                            except: pass
                    except: pass

                self.last_check = datetime.datetime.now()
            except Exception as e:
                print(f"[WindowsOutlookStrategy] Loop Error: {e}")
            
            time.sleep(5)
        
        pythoncom.CoUninitialize()

    def _process_item(self, item):
        try:
             subject = item.Subject
             sender = "Me" # In Sent folder, sender is usually the user
             try: sender = item.SenderEmailAddress
             except: pass
             
             recipients = "; ".join([r.Address for r in item.Recipients])
             body = item.Body[:500] if item.Body else ""
             
             # Attachments
             atts = []
             if item.Attachments.Count > 0:
                 temp_dir = tempfile.gettempdir()
                 for att in item.Attachments:
                     try:
                         fname = att.FileName
                         tpath = os.path.join(temp_dir, f"mx_{int(time.time())}_{fname}")
                         att.SaveAsFile(tpath)
                         
                         with open(tpath, "rb") as f:
                             content = base64.b64encode(f.read()).decode()
                         
                         atts.append({
                             "FileName": fname,
                             "ContentType": "application/octet-stream",
                             "Content": content,
                             "Size": os.path.getsize(tpath)
                         })
                         os.remove(tpath)
                     except: pass
             
             print(f"[WindowsOutlookStrategy] New Email: {subject}")
             self._send_to_backend(sender, recipients, subject, body, atts)
        except Exception as e:
             print(f"Error processing Outlook item: {e}")

# --- Linux Strategy (Thunderbird) ---
class LinuxThunderbirdStrategy(MailMonitorStrategy):
    def _loop(self):
        import mailbox
        import email.utils
        
        home = os.path.expanduser("~")
        
        while self.running:
            # Re-discover paths periodically (valid for new profiles)
            paths = glob.glob(os.path.join(home, ".thunderbird", "*.default*", "Mail", "*", "Sent"))
            paths += glob.glob(os.path.join(home, ".thunderbird", "*.default*", "ImapMail", "*", "Sent"))
            paths += glob.glob(os.path.join(home, ".mozilla", "thunderbird", "*.default*", "Mail", "*", "Sent")) # Alternate path

            if not paths:
                 # readable log only once per minute to avoid spam
                 if int(time.time()) % 60 == 0:
                     print(f"[LinuxThunderbirdStrategy] Searching... No Sent folders found yet.")
            
            for path in paths:
                try:
                    # Check modification time
                    mtime = os.path.getmtime(path)
                    check_time = self.last_check.timestamp()
                    
                    if mtime > check_time:
                        self._process_mbox(path)
                except Exception as e:
                    pass
            
            # Update check time only if we successfully scanned? 
            # Actually, simpler to just update it.
            self.last_check = datetime.datetime.now()
            time.sleep(10)

    def _process_mbox(self, path):
        import mailbox
        import email.utils
        
        try:
            # mbox is standard format
            box = mailbox.mbox(path, create=False)
            
            # Improve perf: Only check last few keys
            keys = box.keys()
            for k in list(keys)[-5:]:
                try:
                    msg = box[k]
                    # Unique ID: Message-ID header or hash of Date+Subject
                    msg_id = msg.get('Message-ID', str(k))
                    if msg_id in self.sent_ids: continue

                    date_tuple = email.utils.parsedate_tz(msg['Date'])
                    if date_tuple:
                        dt = datetime.datetime.fromtimestamp(email.utils.mktime_tz(date_tuple))
                        if dt.tzinfo: dt = dt.replace(tzinfo=None)
                        
                        if dt > self.last_check:
                             self._process_email_msg(msg)
                             self.sent_ids.add(msg_id)
                except: pass
            box.close()
        except: pass

    def _process_email_msg(self, msg):
        sender = msg['From']
        recipient = msg['To']
        subject = msg['Subject']
        
        body = ""
        atts = []
        
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get('Content-Disposition'))
                
                # Body
                if ctype == 'text/plain' and 'attachment' not in cdispo:
                    try: body = part.get_payload(decode=True).decode(errors='ignore')
                    except: pass
                
                # Attachment
                if 'attachment' in cdispo:
                    try:
                        fname = part.get_filename() or "unknown"
                        payload = part.get_payload(decode=True)
                        b64 = base64.b64encode(payload).decode()
                        atts.append({
                            "FileName": fname,
                            "ContentType": ctype,
                            "Content": b64,
                            "Size": len(payload)
                        })
                    except: pass
        else:
            try: body = msg.get_payload(decode=True).decode(errors='ignore')
            except: pass

        print(f"[LinuxThunderbirdStrategy] New Email: {subject}")
        self._send_to_backend(sender, recipient, subject, body[:500], atts)


# --- macOS Strategy (Apple Mail) ---
class MacAppleMailStrategy(MailMonitorStrategy):
    def _loop(self):
        print(f"[MacAppleMailStrategy] Starting Apple Mail monitor")
        
        while self.running:
            try:
                # AppleScript to get recent sent messages
                # Returns: ID|Subject|Sender|To|Date
                script = '''
                tell application "Mail"
                    set output to ""
                    set cutoff to (current date) - 10 * minutes
                    
                    repeat with acc in accounts
                        try
                            set sentBox to mailbox "Sent" of acc
                            set msgs to (every message of sentBox whose date sent > cutoff)
                            repeat with msg in msgs
                                set output to output & (id of msg) & "|||" & (subject of msg) & "|||" & (sender of msg) & "|||" & (address of first recipient of msg) & "|||" & (content of msg) & "###"
                            end repeat
                        end try
                    end repeat
                    return output
                end tell
                '''
                
                # Automation permission required!
                proc = subprocess.run(['osascript', '-e', script], capture_output=True, text=True)
                
                if proc.returncode == 0 and proc.stdout.strip():
                    raw_data = proc.stdout.strip()
                    # Split by message delimiter
                    messages = raw_data.split("###")
                    for m in messages:
                        if not m.strip(): continue
                        parts = m.split("|||")
                        if len(parts) >= 4:
                            mid = parts[0]
                            if mid in self.sent_ids: continue
                            
                            subj = parts[1]
                            sender = parts[2]
                            recipient = parts[3]
                            body = parts[4][:500] if len(parts) > 4 else ""
                            
                            print(f"[MacAppleMailStrategy] New Email: {subj}")
                            self._send_to_backend(sender, recipient, subj, body, [])
                            self.sent_ids.add(mid)
            except Exception as e:
                # print(f"[Mac] Error (Check Permissions): {e}")
                pass
            
            time.sleep(15) # Slower poll for AppleScript

# --- Facade ---
class MailMonitor:
    def __init__(self, backend_url, agent_id, api_key):
        self.strategy = None
        os_type = platform.system()
        
        if os_type == "Windows":
            self.strategy = WindowsOutlookStrategy(backend_url, agent_id, api_key)
        elif os_type == "Linux":
            self.strategy = LinuxThunderbirdStrategy(backend_url, agent_id, api_key)
        elif os_type == "Darwin":
            self.strategy = MacAppleMailStrategy(backend_url, agent_id, api_key)
        else:
            print(f"[MailMonitor] Unsupported Platform: {os_type}")

    @property
    def running(self):
        return self.strategy.running if self.strategy else False

    def start(self):
        if self.strategy:
            self.strategy.start()
        else:
            pass 

    def stop(self):
        if self.strategy:
            self.strategy.stop()
