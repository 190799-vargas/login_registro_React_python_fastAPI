# ===============================================================================================================================
# Email Service Interface
# Interfaz bien definida:
#   * Dos métodos principales: send_email (con plantillas) y send_raw_email (con HTML directo)
#   * Soporte para CC y BCC, Tipado fuerte con EmailStr de Pydantic
# Documentación completa:
#   * Docstrings detallados con tipos y descripciones, Documentación de parámetros opcionales, Especificación de excepciones
# Excepción personalizada:
#   * EmailSendingError para manejar errores específicos
# Extensible:
#   * Fácil de implementar con diferentes proveedores (SendGrid, Mailgun, SMTP, etc.), Permite múltiples estrategias de envío
# Patrón de diseño:
#   * Sigue el principio de inversión de dependencias (DIP), Abstract Base Class (ABC) para garantizar implementación completa
# ===============================================================================================================================

from abc import ABC, abstractmethod
from typing import Optional, Dict
from pydantic import BaseModel, EmailStr

class IEmailService(ABC):
    """
    Interfaz abstracta para el servicio de envío de emails.
    Define el contrato que deben implementar todos los servicios de email concretos.
    """

    @abstractmethod
    async def send_email(
        self,
        to_email: EmailStr,
        subject: str,
        template_name: str,
        context: Dict[str, str],
        *,
        cc: Optional[EmailStr] = None,
        bcc: Optional[EmailStr] = None
    ) -> bool:
        """
        Método abstracto para enviar un email con plantilla.

        Args:
            to_email (EmailStr): Dirección de email del destinatario.
            subject (str): Asunto del email.
            template_name (str): Nombre de la plantilla a utilizar.
            context (Dict[str, str]): Variables para renderizar la plantilla.
            cc (Optional[EmailStr]): Dirección de email para copia (opcional).
            bcc (Optional[EmailStr]): Dirección de email para copia oculta (opcional).

        Returns:
            bool: True si el email se envió correctamente, False en caso contrario.

        Raises:
            EmailSendingError: Si ocurre un error durante el envío.
        """
        pass

    @abstractmethod
    async def send_raw_email(
        self,
        to_email: EmailStr,
        subject: str,
        html_content: str,
        *,
        cc: Optional[EmailStr] = None,
        bcc: Optional[EmailStr] = None
    ) -> bool:
        """
        Método abstracto para enviar un email con contenido HTML directo.

        Args:
            to_email (EmailStr): Dirección de email del destinatario.
            subject (str): Asunto del email.
            html_content (str): Contenido HTML del email.
            cc (Optional[EmailStr]): Dirección de email para copia (opcional).
            bcc (Optional[EmailStr]): Dirección de email para copia oculta (opcional).

        Returns:
            bool: True si el email se envió correctamente, False en caso contrario.
        """
        pass


class EmailSendingError(Exception):
    """Excepción personalizada para errores en el envío de emails"""
    
    def __init__(self, message: str = "Error al enviar el email"):
        self.message = message
        super().__init__(self.message)
