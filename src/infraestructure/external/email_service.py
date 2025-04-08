# ===========================================================================================================================
# Define un servicio de envío de correos electrónicos utilizando SMTP con Gmail y plantillas HTML renderizadas con Jinja2.
# Importaciones:
#   * smtplib: Permite enviar correos usando el protocolo SMTP.
#   * MIMEText, MIMEMultipart: Permiten construir correos electrónicos con formato HTML y texto.
#   * settings: Contiene las configuraciones del email (credenciales y remitente).
#   * logging: Para registrar errores y eventos.
#   * jinja2: Permite renderizar plantillas HTML dinámicamente.
#   * Path: Para manejar rutas de archivos (ubicación de plantillas).
# ===========================================================================================================================

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Optional, Any, Union
import logging
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
from premailer import transform
from datetime import datetime
import ssl
import aiosmtplib
from pydantic import EmailStr

from src.config import settings
from src.interfaces.services.email_service import IEmailService
from src.core.domain.exceptions import EmailSendingError
from src.core.logging import logging

#  Se inicializan los datos del servidor SMTP (Gmail en este caso) y se configura el motor de plantillas Jinja2 apuntando al directorio templates/emails
class SMTPEmailService(IEmailService):
    """Implementación concreta del servicio de email usando SMTP"""
    
    def __init__(self):
        # Configuración SMTP
        self.smtp_server = settings.SMTP_SERVER
        self.smtp_port = settings.SMTP_PORT
        self.timeout = 10
        self.ssl_context = ssl.create_default_context()
        self._logger = logging.getLogger(__name__)
        
        # Configuración de plantillas
        self._setup_templates()
        
        # Conexión persistente
        self._connection = None

    def _setup_templates(self):
        """Configura el entorno de plantillas Jinja2"""
        templates_path = Path(__file__).resolve().parents[3] / "templates" / "emails"
        self.templates_env = Environment(
            loader=FileSystemLoader(templates_path),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )

    async def initialize(self):
        """Establece conexión persistente con el servidor SMTP"""
        try:
            self._connection = aiosmtplib.SMTP(
                hostname=self.smtp_server,
                port=self.smtp_port,
                timeout=self.timeout,
                use_tls=True
            )
            await self._connection.connect()
            await self._connection.login(
                settings.EMAIL_USER,
                settings.EMAIL_PASSWORD.get_secret_value()
            )
            self._logger.info("✅ Conexión SMTP establecida")
        except Exception as e:
            self._logger.error(f"🚨 Error conectando a SMTP: {str(e)}")
            raise EmailSendingError("Failed to initialize SMTP connection")

    async def close(self):
        """Cierra la conexión SMTP"""
        if self._connection:
            try:
                await self._connection.quit()
                self._logger.info("🔌 Conexión SMTP cerrada")
            except Exception as e:
                self._logger.warning(f"⚠️ Error cerrando conexión SMTP: {str(e)}")

    async def _render_template(self, template_name: str, context: Dict[str, Any]) -> str:
        """Renderiza plantilla HTML con contexto"""
        try:
            template = self.templates_env.get_template(f"{template_name}.html")
            return await self._inline_css(template.render({
                **context,
                "app_name": settings.APP_NAME,
                "current_year": datetime.now().year,
                "support_email": getattr(settings, "SUPPORT_EMAIL", "support@example.com"),
                "frontend_url": settings.FRONTEND_URL
            }))
        except Exception as e:
            self._logger.error(f"Error renderizando plantilla: {str(e)}", exc_info=True)
            raise EmailSendingError("Template rendering failed")

    async def _inline_css(self, html_content: str) -> str:
        """Optimiza CSS para clientes de email"""
        try:
            return transform(
                html_content,
                base_url=f"file://{Path(__file__).parents[3]}/templates/emails/",
                disable_validation=True,
                preserve_internal_links=True
            )
        except Exception as e:
            self._logger.warning(f"CSS inlining failed: {str(e)}")
            return html_content

    async def send_email(
        self,
        to_email: Union[EmailStr, str],
        subject: str,
        template_name: str,
        context: Dict[str, str],
        *,
        cc: Optional[Union[EmailStr, str]] = None,
        bcc: Optional[Union[EmailStr, str]] = None
    ) -> bool:
        """
        Envía un email usando plantillas Jinja2
        
        Args:
            to_email: Email del destinatario
            subject: Asunto del email
            template_name: Nombre de la plantilla (sin extensión)
            context: Variables para la plantilla
            cc: Email para copia (opcional)
            bcc: Email para copia oculta (opcional)
            
        Returns:
            bool: True si el envío fue exitoso
            
        Raises:
            EmailSendingError: Si ocurre un error crítico
        """
        try:
            # 1. Renderizar plantilla
            html_content = await self._render_template(template_name, context)
            
            # 2. Configurar mensaje
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{settings.EMAIL_FROM_NAME} <{settings.EMAIL_FROM}>"
            msg['To'] = to_email
            msg['Subject'] = subject
            
            if cc:
                msg['Cc'] = cc
            if bcc:
                msg['Bcc'] = bcc
                
            msg.attach(MIMEText(html_content, 'html', 'utf-8'))
            
            # 3. Enviar email
            if not self._connection:
                await self.initialize()
                
            recipients = [to_email]
            if cc:
                recipients.append(cc)
            if bcc:
                recipients.append(bcc)
                
            await self._connection.send_message(
                msg,
                sender=settings.EMAIL_FROM,
                recipients=recipients
            )
            
            self._logger.info(f"✉️ Email enviado a {to_email} | Asunto: {subject}")
            return True
            
        except Exception as e:
            self._logger.error(f"❌ Error enviando email a {to_email}: {str(e)}", exc_info=True)
            raise EmailSendingError(f"Failed to send email: {str(e)}")

    async def send_raw_email(
        self,
        to_email: Union[EmailStr, str],
        subject: str,
        html_content: str,
        *,
        cc: Optional[Union[EmailStr, str]] = None,
        bcc: Optional[Union[EmailStr, str]] = None
    ) -> bool:
        """Envía un email con contenido HTML directo"""
        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{settings.EMAIL_FROM_NAME} <{settings.EMAIL_FROM}>"
            msg['To'] = to_email
            msg['Subject'] = subject
            
            if cc:
                msg['Cc'] = cc
            if bcc:
                msg['Bcc'] = bcc
                
            msg.attach(MIMEText(await self._inline_css(html_content), 'html', 'utf-8'))
            
            if not self._connection:
                await self.initialize()
                
            recipients = [to_email]
            if cc:
                recipients.append(cc)
            if bcc:
                recipients.append(bcc)
                
            await self._connection.send_message(
                msg,
                sender=settings.EMAIL_FROM,
                recipients=recipients
            )
            
            return True
            
        except Exception as e:
            self._logger.error(f"Error enviando raw email: {str(e)}", exc_info=True)
            raise EmailSendingError(f"Failed to send raw email: {str(e)}")

    async def check_health(self) -> bool:
        """Verifica que el servicio esté operativo"""
        try:
            if not self._connection:
                await self.initialize()
            return await self._connection.noop()
        except Exception as e:
            self._logger.error(f"Health check failed: {str(e)}")
            return False