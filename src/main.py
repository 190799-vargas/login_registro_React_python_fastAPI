# ===========================================================================================================
# Configuración Inicial:
#   * Logging personalizado, Manejo de lifespan para conexiones a DB, Variables de entorno desde settings
#
# Aplicación FastAPI:
#   * Metadata para documentación (Swagger/Redoc), Middleware CORS configurable, Setup de autenticación JWT
#
# Rutas Principales:
#   * Módulo de autenticación (auth.router), Módulo de usuarios (users.router), Health check endpoint
#
# Manejo de Errores:
#   * Logger para errores no controlados, Respuestas JSON estandarizadas
#
# Servidor de Desarrollo:
#   * Uvicorn integrado, Configuración desde variables
# ===========================================================================================================

import logging
from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from src.infraestructure.database.mongodb import MongoDB
from src.config import settings
from src.routes import auth, users
from src.core.security import setup_jwt
from src.core.logging import configure_loggin, add_logging_middleware
from src.infraestructure.external import get_email_service, close_email_service
from src.interfaces.services.email_service import IEmailService
from src.core.domain.exceptions import (
    DomainException,
    InvalidCredentialsError,
    PermissionDeniedError,
    UserNotFoundError,
    EmailAlreadyExistsError,
)

# Configuración inicial
configure_loggin(
    log_as_json=settings.LOG_AS_JSON,
    log_level=settings.LOG_LEVEL
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Maneja eventos de inicio y cierre de la aplicación"""
    
    startup_ok = False
    # Conexión a MongoDB al iniciar
    try:
        logger.info("Conectando a MongoDB...")
        await MongoDB.initialize()
        logger.info("Conexión a MongoDB establecida")

        # Inicializar servicio de email
        logger.info(f" Inicializando servicio de email ({settings.EMAIL_PROVIDER})...")
        email_service = await get_email_service()
        logger.info(f"✅ Servicio de email listo")

        startup_ok = True
        yield

    except Exception as e:
        logger.error(f"Error conectando a MongoDB: {str(e)}", exc_info=True)
        raise

    finally:
        # Solo cerrar conexiones si el inicio fue exitoso
        if startup_ok:
            try:
                logger.info("🔌 Cerrando conexiones...")
                await MongoDB.close_connection()
                await close_email_service()
                logger.info("👋 Conexiones cerradas correctamente")
            except Exception as e:
                logger.error(f"⚠️ Error cerrando conexiones: {str(e)}")

# Crear aplicación FastAPI
app = FastAPI(
    title="API de Autenticación",
    description="Sistema de gestión de usuarios y autenticación",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Añade middleware de logging
add_logging_middleware(app)

# Configurar JWT
setup_jwt(app)

# Incluir rutas
app.include_router(auth.router)
app.include_router(users.router)

# Healt Check
@app.get("/health", tags=["Health"])
async def health_check(email_service: IEmailService = Depends(get_email_service)):
    """
    Verifica el estado de los servicios esenciales:
    - Base de datos
    - Servicio de email
    """
    services_status = {
        "database": await MongoDB.check_connection(),
        "email": await email_service.check_health() if hasattr(email_service, 'check_health') else True
    }
    
    status_code = 200 if all(services_status.values()) else 503
    app_status = "OK" if all(services_status.values()) else "Degradado"
    
    return JSONResponse(
        status_code=status_code,
        content={
            "status": app_status,
            "services": services_status,
            "version": app.version,
            "environment": settings.ENVIRONMENT
        }
    )
# Manejo de errores específicos
@app.exception_handler(InvalidCredentialsError)
async def invalid_credentials_exception_handler(request: Request, exc: InvalidCredentialsError):
    logger.warning(f"Credenciales inválidas: {str(exc)}")
    return JSONResponse(
        status_code=401,
        content={"error": "Invalid credentials"}
    )

@app.exception_handler(PermissionDeniedError)
async def permission_denied_exception_handler(request: Request, exc: PermissionDeniedError):
    logger.warning(f"Permiso denegado: {str(exc)}")
    return JSONResponse(
        status_code=403,
        content={"error": "Permission denied"}
    )

@app.exception_handler(UserNotFoundError)
async def user_not_found_exception_handler(request: Request, exc: UserNotFoundError):
    logger.warning(f"Usuario no encontrado: {str(exc)}")
    return JSONResponse(
        status_code=404,
        content={"error": "User not found"}
    )

@app.exception_handler(EmailAlreadyExistsError)
async def email_already_exists_exception_handler(request: Request, exc: EmailAlreadyExistsError):
    logger.warning(f"Email ya registrado: {str(exc)}")
    return JSONResponse(
        status_code=409,
        content={"error": "Email already exists"}
    )

# Manejo de errores globales
@app.exception_handler(DomainException)
async def global_exception_handler(request: Request, exc: DomainException):
    logger.warning(
        f"Error de dominio: {str(exc)}",
        extra={"type": exc.error_type, "code": exc.error_code}
    )
    return JSONResponse(
        status_code=exc.http_status,
        content={
            "error": exc.message,
            "code": exc.error_code,
            "type": exc.error_type.value
        }
    )
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    logger.info(f"Error HTTP: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning(f"Error de validación: {str(exc)}")
    return JSONResponse(
        status_code=422,
        content={
            "error": "Validation Error",
            "details": exc.errors()
        },
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(
        f"Error no controlado en {request.method} {request.url}",
        exc_info=True,
        extra={
            "path": request.url.path,
            "method": request.method,
            "error": str(exc)
        }
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "request_id": request.state.request_id
        }
    )

# servidor de Desarrollo
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
        log_level="info"
    )