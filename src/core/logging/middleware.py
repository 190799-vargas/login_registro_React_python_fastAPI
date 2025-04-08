# ========================================
# Registra todas las requests/responses
# Mide tiempos de ejecución
# Captura errores no controlados
# ========================================

import time
import logging
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware para logging de requests/responses"""
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()

        # Log de request
        logger.info(
            "Incoming request",
            extra={
                "path": request.url.path,
                "method": request.method,
                "ip": request.client.host if request.client else None
            }
        )

        try:
            response = await call_next(request)
        except Exception as e:
            logger.error(
                "Request failed",
                exc_info=True,
                extra={
                    "path": request.url.path,
                    "method": request.method,
                    "error": str(e)
                }
            )
            raise

        # Log de response
        process_time = time.time() - start_time
        logger.info(
            "Request completed",
            extra={
                "path": request.url.path,
                "method": request.method,
                "status": response.status_code,
                "duration": f"{process_time:.4f}s"
            }
        )

        return response