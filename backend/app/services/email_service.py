import os # type: ignore
import smtplib # type: ignore
from email.mime.text import MIMEText # type: ignore
from email.mime.multipart import MIMEMultipart # type: ignore
import aiosmtplib # type: ignore
import time # type: ignore
import uuid # type: ignore
import socket # type: ignore
from email.utils import formatdate, make_msgid # type: ignore

# Load .env explicitly so SMTP settings are always available
try:
    from dotenv import load_dotenv # type: ignore
    load_dotenv("/app/.env", override=True)
except Exception:
    pass  # dotenv not available or file not found — fall through to env vars

class EmailService:
    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST", "smtp.monitorix.co.in")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_pass = os.getenv("SMTP_PASS", "")
        self.from_email = os.getenv("SMTP_FROM", os.getenv("SMTP_USER", ""))
        self.enabled = bool(self.smtp_user and self.smtp_pass)
        if self.enabled:
            print(f"[EmailService] SMTP ready: {self.smtp_user} @ {self.smtp_host}:{self.smtp_port}")
        else:
            print(f"[EmailService] WARNING: SMTP credentials not set — emails will be logged only!")

    async def send_email(self, to_email: str, subject: str, html_content: str, attachment_path: str = None, cc_emails: list = None):
        if not self.enabled:
            print(f"[EmailService] Mock Send to {to_email} (CC: {cc_emails}): {subject} (Attachment: {attachment_path})")
            return True

        # --- DMARC Alignment ---
        # The 'From' domain MUST match the domain in the DMARC record (monitorix.co.in)
        # Using a mismatched domain (e.g. @watch-sec.com) with p=quarantine will send to junk.
        dmarc_domain = "monitorix.co.in"
        from_email = self.from_email # type: ignore
        # Enforce alignment: if the from email domain doesn't match DMARC domain, use info@
        if "@" not in from_email or from_email.split("@")[-1].lower() != dmarc_domain:
            from_email = f"info@{dmarc_domain}" # type: ignore
            print(f"[EmailService] WARNING: SMTP_FROM domain mismatch. Forcing DMARC-aligned From: {from_email}")

        # Create the top-level container
        message = MIMEMultipart("mixed")
        display_name = "Monitorix Security Reports"
        message["From"] = f"{display_name} <{from_email}>"
        message["To"] = to_email
        if cc_emails:
            message["Cc"] = ", ".join(cc_emails)

        message["Subject"] = subject
        message["Date"] = formatdate(localtime=True)

        # Use DMARC-aligned domain for Message-ID
        message["Message-ID"] = make_msgid(domain=dmarc_domain)

        # Sender (RFC 5321 envelope sender) must also be DMARC-aligned
        message["Sender"] = from_email

        message["X-Mailer"] = "Monitorix Reporting Service v2"

        # --- Anti-Spam & Deliverability Headers ---
        message["Reply-To"] = from_email
        message["Precedence"] = "bulk"
        message["Auto-Submitted"] = "auto-generated"

        # Priority / Importance (tells Outlook this is not urgent spam)
        message["X-Priority"] = "3 (Normal)"
        message["Importance"] = "Normal"

        # Outlook-specific: suppress out-of-office auto-replies
        message["X-Auto-Response-Suppress"] = "OOF, AutoReply"

        # List-Unsubscribe (mandatory for bulk mail, helps classification)
        dashboard_url = os.getenv("MONITORIX_BASE_URL", "https://monitorix.co.in")
        message["List-Unsubscribe"] = f"<{dashboard_url}/reports>, <mailto:{from_email}?subject=unsubscribe>"
        message["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"

        # Create the alternative container for text/html
        alt_part = MIMEMultipart("alternative")
        text_content = (
            f"Monitorix Security Report: {subject}\n\n"
            f"Your security report is ready. You can download the attachment "
            f"or view it on your dashboard: {dashboard_url}/reports"
        )
        alt_part.attach(MIMEText(text_content, "plain"))
        alt_part.attach(MIMEText(html_content, "html"))

        # Attach the content part to the mixed container
        message.attach(alt_part)

        if attachment_path and os.path.exists(attachment_path):
            from email.mime.base import MIMEBase # type: ignore
            from email import encoders # type: ignore
            
            with open(attachment_path, "rb") as f:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition",
                    f"attachment; filename={os.path.basename(attachment_path)}",
                )
                message.attach(part)

        recipients = [to_email]
        if cc_emails:
            recipients.extend(cc_emails)

        use_tls = (self.smtp_port == 465)
        start_tls = (self.smtp_port == 587)

        print(f"[EmailService] Attempting to send '{subject}' to {to_email} via {self.smtp_host}:{self.smtp_port} "
              f"({'SSL' if use_tls else 'STARTTLS' if start_tls else 'Plain'})")

        # Bypass SSL hostname validation for internal Docker network connections
        import ssl # type: ignore
        tls_context = ssl.create_default_context()
        if self.smtp_host == "mailserver":
            tls_context.check_hostname = False
            tls_context.verify_mode = ssl.CERT_NONE
        
        try:
            await aiosmtplib.send(
                message,
                recipients=recipients,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_pass,
                use_tls=use_tls,
                start_tls=start_tls,
                tls_context=tls_context
            )
            print(f"[EmailService] ✅ Sent to {to_email} (Total recipients: {len(recipients)}) "
                  f"| From: {from_email} | Message-ID: {message['Message-ID']}")
            return True
        except Exception as e:
            print(f"[EmailService] ❌ ERROR sending to {to_email} (Server: {self.smtp_host}:{self.smtp_port}, User: {self.smtp_user}): {e}")
            return False

email_service = EmailService()
