import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import aiosmtplib

class EmailService:
    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_pass = os.getenv("SMTP_PASS", "")
        self.from_email = os.getenv("SMTP_FROM", "noreply@watch-sec.com")
        self.enabled = bool(self.smtp_user and self.smtp_pass)

    async def send_email(self, to_email: str, subject: str, html_content: str):
        if not self.enabled:
            # Mock / Log only
            print(f"[EmailService] Mock Send to {to_email}: {subject}")
            return True

        message = MIMEMultipart()
        message["From"] = self.from_email
        message["To"] = to_email
        message["Subject"] = subject
        message.attach(MIMEText(html_content, "html"))

        try:
            await aiosmtplib.send(
                message,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_pass,
                start_tls=True
            )
            return True
        except Exception as e:
            print(f"[EmailService] Error sending email: {e}")
            return False

email_service = EmailService()
