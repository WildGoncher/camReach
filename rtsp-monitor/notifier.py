"""
Secure Email Notification Service for Camera Monitor
"""

import os
import re
import ssl
import smtplib
import asyncio
import logging
from typing import Optional
from email.message import EmailMessage
from email.utils import parseaddr
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)


class EmailNotifier:
    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST")
        self.smtp_port = int(os.getenv("SMTP_PORT", 465))
        self.smtp_user = os.getenv("SMTP_USER")
        self.smtp_pass = os.getenv("SMTP_PASS")
        self.email_to = os.getenv("EMAIL_TO") or os.getenv("SMTP_USER", "")
        self.email_from = os.getenv("EMAIL_FROM") or os.getenv("SMTP_USER", "")
        self.subject_prefix = os.getenv("EMAIL_SUBJECT_PREFIX", "[CameraMonitor]")
        self.send_html = os.getenv("EMAIL_HTML_ENABLED", "true").lower() == "true"
        self._validate_config()

    def _validate_config(self):
        if not all([self.smtp_host, self.smtp_user, self.smtp_pass, self.email_to]):
            logger.warning(
                "⚠️ Email notifier: SMTP config incomplete. Notifications disabled."
            )
            return
        _, addr = parseaddr(self.email_from)
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", addr):
            logger.error(f"❌ Invalid FROM email format: {self.email_from}")
            raise ValueError(f"Invalid FROM email: {self.email_from}")

    def _sanitize_header(self, value: str) -> str:
        if not value:
            return ""
        value = value.replace("\r", "").replace("\n", "")
        return value[:200]

    def _get_email_body_html(
        self, camera_label: str, status: str, error_detail: str
    ) -> str:
        status_color = "#2ecc71" if status.lower() == "online" else "#e74c3c"
        status_text = "работает" if status.lower() == "online" else "не работает"
        details_html = (
            f"<p><strong>Детали:</strong> {error_detail}</p>" if error_detail else ""
        )
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <p style="font-size: 1.2em;">
                Статус камеры изменился: 
                <strong style="color: {status_color};">{status_text}</strong>
            </p>
            <p><strong>Камера:</strong><br>{camera_label}</p>
            {details_html}
            <hr style="border: none; border-top: 1px solid #ccc; margin: 20px 0;">
            <p style="font-size: 0.9em; color: #666;">
                Мониторинг камер<br>
                Данное письмо сгенерировано автоматически.<br>
                Просьба не отвечать на него.
            </p>
        </body>
        </html>
        """

    def _get_email_body(self, camera_label: str, status: str, error_detail: str) -> str:
        status_map = {"online": "работает", "offline": "не работает"}
        status_text = status_map.get(status.lower(), status)
        header = f"Статус камеры изменился: {status_text}"
        info_block = f"Камера: {camera_label}"
        details_block = f"Детали: {error_detail}" if error_detail else ""
        footer = "\n".join(
            [
                "",
                "─" * 40,
                "Мониторинг камер",
                "Данное письмо сгенерировано автоматически.",
                "Просьба не отвечать на него.",
            ]
        )
        parts = [header, "", info_block]
        if details_block:
            parts.append(details_block)
        parts.append(footer)
        return "\n".join(parts)

    async def send_camera_alert(
        self, camera_label: str, status: str, error_detail: str = ""
    ):
        if not all([self.smtp_host, self.smtp_user, self.smtp_pass, self.email_to]):
            return
        safe_camera = self._sanitize_header(camera_label)
        safe_status = self._sanitize_header(status)
        safe_error = error_detail[:500] if error_detail else ""
        subject = f"{self.subject_prefix} {safe_camera}: {safe_status.upper()}"
        text_body = self._get_email_body(safe_camera, safe_status, safe_error)
        html_body = (
            self._get_email_body_html(safe_camera, safe_status, safe_error)
            if self.send_html
            else None
        )
        try:
            loop = asyncio.get_event_loop()
            await asyncio.wait_for(
                loop.run_in_executor(
                    None, self._send_email_sync, subject, text_body, html_body
                ),
                timeout=30.0,
            )
            logger.info(f"✅ Email sent: {subject}")
        except asyncio.TimeoutError:
            logger.error("❌ Email sending timeout (30s limit)")
        except smtplib.SMTPAuthenticationError:
            logger.error(
                "❌ SMTP Auth failed. Check SMTP_USER/SMTP_PASS (use App Password)"
            )
        except smtplib.SMTPException as e:
            logger.error(f"❌ SMTP error: {type(e).__name__}: {e}")
        except Exception as e:
            logger.error(f"❌ Email failed unexpectedly: {type(e).__name__}: {e}")

    def _send_email_sync(
        self, subject: str, text_body: str, html_body: Optional[str] = None
    ):
        ssl_context = ssl.create_default_context()
        if html_body:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.email_from
            msg["To"] = self.email_to
            msg.attach(MIMEText(text_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))
        else:
            msg = EmailMessage()
            msg.set_content(text_body)
            msg["Subject"] = subject
            msg["From"] = self.email_from
            msg["To"] = self.email_to
        if self.smtp_port == 465:
            with smtplib.SMTP_SSL(
                self.smtp_host, self.smtp_port, context=ssl_context, timeout=10
            ) as server:
                server.login(self.smtp_user, self.smtp_pass)
                server.send_message(msg)
        else:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                server.starttls(context=ssl_context)
                server.login(self.smtp_user, self.smtp_pass)
                server.send_message(msg)
