
import win32com.client
import pythoncom
import time
import requests
import datetime
import logging
import base64
import os
import tempfile
from threading import Thread

class MailMonitor:
    def __init__(self, api_url, agent_id, api_key):
        self.api_url = api_url
        self.agent_id = agent_id
        self.api_key = api_key
        self.running = False
        # Check for emails sent in the last 10 minutes (to catch recent tests)
        self.last_check = datetime.datetime.now() - datetime.timedelta(minutes=10)
        self.logger = logging.getLogger("MailMonitor")

    def start(self):
        self.running = True
        t = Thread(target=self._monitor_loop, daemon=True)
        t.start()
        self.logger.info("Mail Monitor Started (Outlook Integration)")

    def stop(self):
        self.running = False

    def _monitor_loop(self):
        # Initialize COM for this thread
        pythoncom.CoInitialize()
        
        outlook = None
        try:
            # Dispatch "Outlook.Application"
            outlook = win32com.client.Dispatch("Outlook.Application")
            namespace = outlook.GetNamespace("MAPI")
            sent_folder = namespace.GetDefaultFolder(5) # 5 = olFolderSentMail
            
            # Debug: Prove connection works
            print(f"[MailMonitor] Connected to Outlook. Folder: {sent_folder.Name}")
            print(f"[MailMonitor] Total Items in Sent Items: {sent_folder.Items.Count}")
            
        except Exception as e:
            self.logger.error(f"Failed to connect to Outlook: {e}")
            print(f"[MailMonitor] FATAL: Outlook Connection Failed! Error: {e}")
            self.logger.warning("Mail Monitor is DISABLED (Outlook not found or permission denied).")
            return

        self.logger.info(f"Connected to Outlook.")
        print(f"[MailMonitor] Monitoring loop working. Scanning ALL accounts...")

        while self.running:
            try:
                # Outlook MAPI Namespace
                # We must re-fetch folders in case of connection drop or new items
                stores = namespace.Stores
                
                all_sent_folders = []
                for store in stores:
                    try:
                        # Attempt to find "Sent Items" or "Sent" for each store
                        # Default ID for SentMail is 5
                        # But GetDefaultFolder(5) is store-specific
                        root = store.GetRootFolder()
                        # print(f"[MailMonitor] Checking Account: {store.DisplayName}")
                        
                        # Strategy 1: Try standard GetDefaultFolder on the store (if possible logic exists, usually per namespace)
                        # Actually GetDefaultFolder is on Namespace, but we can iterate folders.
                        # Easier: Just look for folder named "Sent Items" or "Sent"
                        
                        found = False
                        for folder in root.Folders:
                            if "sent" in folder.Name.lower():
                                all_sent_folders.append(folder)
                                found = True
                                # print(f"[MailMonitor]   Found Sent Folder: {folder.Name}")
                                break # Assume one sent folder per account
                    except:
                        pass

                # If no folders found via iteration, try default as fallback
                if not all_sent_folders:
                     try:
                         all_sent_folders.append(namespace.GetDefaultFolder(5))
                     except: pass

                # Check each folder
                for folder in all_sent_folders:
                    try:
                        items = folder.Items
                        items.Sort("[SentOn]", True)
                        
                        for item in list(items)[:3]: # Check top 3 of each account
                            try:
                                sent_time = item.SentOn
                                if sent_time.tzinfo: sent_time = sent_time.replace(tzinfo=None)
                                
                                if sent_time > self.last_check:
                                    print(f"[MailMonitor] NEW EMAIL DETECTED in {folder.Name}! Subject: {item.Subject}")
                                    self._process_email(item)
                            except: pass
                    except: pass

                self.last_check = datetime.datetime.now()
            except Exception as e:
                self.logger.error(f"Error checking mail: {e}")
                # print(f"[MailMonitor] Loop Error: {e}")
            
            time.sleep(5) # Poll faster (5s)

        pythoncom.CoUninitialize()

    def _process_email(self, item):
        try:
            subject = item.Subject
            sender = item.SenderName # Or SenderEmailAddress
            try:
                # Outlook security usage might block SenderEmailAddress
                sender_email = item.SenderEmailAddress
            except:
                sender_email = sender

            recipients = []
            for r in item.Recipients:
                recipients.append(r.Address)
            
            recipient_str = "; ".join(recipients)
            
            body_preview = item.Body[:500] if item.Body else ""
            
            # --- ATTACHMENT PROCESSING ---
            attachments_data = [] # List of dicts for API
            attachment_names = [] # List of strings for display
            has_attachments = False
            
            if item.Attachments.Count > 0:
                has_attachments = True
                temp_dir = tempfile.gettempdir()
                
                for att in item.Attachments:
                    try:
                        fname = att.FileName
                        attachment_names.append(fname)
                        
                        # We must save to disk first to get content from OLE automation
                        temp_path = os.path.join(temp_dir, f"watchsec_{int(time.time())}_{fname}")
                        att.SaveAsFile(temp_path)
                        
                        with open(temp_path, "rb") as f:
                            file_bytes = f.read()
                            
                        # Encode base64
                        b64_content = base64.b64encode(file_bytes).decode("utf-8")
                        
                        attachments_data.append({
                            "FileName": fname,
                            "ContentType": "application/octet-stream", # Generic for now
                            "Content": b64_content,
                            "Size": len(file_bytes)
                        })
                        
                        # Cleanup
                        os.remove(temp_path)
                    except Exception as att_err:
                        self.logger.error(f"Failed to process attachment {att.FileName}: {att_err}")

            attachment_str = ", ".join(attachment_names)

            self.logger.info(f"Intercepted Email: '{subject}' to {recipient_str}")
            print(f"[MailMonitor] >> PROCESSING EMAIL: '{subject}' -> {recipient_str}")
            print(f"[MailMonitor]    Attachment Count (Outlook): {item.Attachments.Count}")
            print(f"[MailMonitor]    Captured Attachments: {len(attachments_data)}")
            if has_attachments:
                print(f"[MailMonitor]    Attachments Names: {attachment_str}")

            # Send to Backend
            payload = {
                "AgentId": self.agent_id,
                "TenantApiKey": self.api_key,
                "Sender": sender_email,
                "Recipient": recipient_str,
                "Subject": subject,
                "BodyPreview": body_preview,
                "HasAttachments": has_attachments,
                "AttachmentNames": attachment_str,
                "Timestamp": datetime.datetime.utcnow().isoformat(),
                "Attachments": attachments_data
            }
            
            url = f"{self.api_url}/api/mail" # Using /api/mail as fixed
            try:
                res = requests.post(url, json=payload)
                if res.status_code == 200:
                    self.logger.info("Email logged to backend successfully.")
                    print(f"[MailMonitor] >> SUCCESS: Email uploaded to Backend.")
                else:
                    self.logger.error(f"Backend rejected email log: {res.status_code}")
                    print(f"[MailMonitor] !! ERROR: Backend rejected upload (Status: {res.status_code})")
            except Exception as req_err:
                 self.logger.error(f"Failed to upload email log: {req_err}")
                 print(f"[MailMonitor] !! ERROR: Upload failed: {req_err}")

        except Exception as e:
            self.logger.error(f"Failed to process email item: {e}")
            print(f"[MailMonitor] !! ERROR: Processing failed: {e}")
