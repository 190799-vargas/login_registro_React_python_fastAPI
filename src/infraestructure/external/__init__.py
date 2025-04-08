from typing import Optional
from src.config import settings
from src.interfaces.services.email_service import IEmailService
from .email_service import SMTPEmailService
from .mock_email_service import MockEmailService

_email_service: Optional[IEmailService] = None

async def get_email_service() -> IEmailService:
    """
    Factory function que devuelve e inicializa el servicio de email configurado.
    Implementa el patrón singleton para reutilizar la misma instancia.
    
    Returns:
        IEmailService: Instancia del servicio de email inicializado
    """
    global _email_service
    
    if _email_service is None:
        if settings.ENVIRONMENT == "production":
            _email_service = SMTPEmailService()
        else:
            _email_service = MockEmailService()
        
        # Inicializa el servicio si tiene el método
        if hasattr(_email_service, 'initialize'):
            await _email_service.initialize()
    
    return _email_service

async def close_email_service():
    """Cierra la conexión del servicio de email si está activa"""
    global _email_service
    
    if _email_service is not None and hasattr(_email_service, 'close'):
        await _email_service.close()
        _email_service = None