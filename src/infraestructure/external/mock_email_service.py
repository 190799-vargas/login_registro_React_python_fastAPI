# backend/src/infrastructure/external/mock_email_service.py
import logging
from typing import Dict, Optional, Union
from pydantic import EmailStr
from src.interfaces.services.email_service import IEmailService

class MockEmailService(IEmailService):
    """Implementación mock para desarrollo que registra emails en logs"""
    
    def __init__(self):
        self._logger = logging.getLogger(__name__)
        self._initialized = False

    async def initialize(self):
        """Simula inicialización del servicio"""
        self._logger.info("🛜 Mock Email Service inicializado")
        self._initialized = True
        return True

    async def close(self):
        """Simula cierre del servicio"""
        self._logger.info("🛜 Mock Email Service cerrado")
        self._initialized = False

    async def check_health(self) -> bool:
        """Verifica estado del servicio"""
        return self._initialized

    async def send_email(self, to_email: str, subject: str, template_name: str, context: Dict[str, str]) -> bool:
        if not self._initialized:
            raise RuntimeError("Servicio no inicializado")
        
        self._logger.info(
            f"\n📨 [MOCK] Email a: {to_email}\n"
            f"📌 Asunto: {subject}\n"
            f"📝 Plantilla: {template_name}\n"
            f"📋 Contexto: {context}"
        )
        return True