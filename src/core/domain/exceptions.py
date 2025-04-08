# =============================================================================================================================
# DomainException - Clase base para todas las excepciones del dominio con código HTTP asociado
# PermissionDeniedError - Se lanza cuando un usuario intenta realizar una acción para la que no tiene permisos suficientes
# UserNotFoundError - Se lanza cuando se intenta acceder a un usuario que no existe en el sistema
# Ambas heredan de la clase base Exception y permiten personalizar el mensaje de error,
#   aunque tienen valores por defecto ("Permission denied" y "User not found" respectivamente).
# Estas excepciones son luego capturadas en los endpoints de FastAPI y convertidas en respuestas HTTP apropiadas
#    (403 Forbidden y 404 Not Found respectivamente) como se ve en el código de los routers.
# Todas heredan de DomainException y permiten personalizar el mensaje de error,
# pero tienen valores por defecto apropiados para cada caso.
# Estas excepciones son capturadas en los endpoints y convertidas en respuestas HTTP apropiadas.
# =============================================================================================================================

from fastapi import status
from typing import Optional
from enum import Enum

class ErrorType(str, Enum):
    """Tipos de errores para categorización"""
    AUTH = "authentication_error"
    VALIDATION = "validation_error"
    NOT_FOUND = "not_found_error"
    PERMISSION = "permission_error"
    EMAIL = "email_error"
    TOKEN = "token_error"
    DATABASE = "database_error"
    EXTERNAL = "external_service_error"


class DomainException(Exception):
    """
    Clase base para excepciones del dominio con soporte para:
    - Códigos HTTP automáticos
    - Categorización de errores
    - Metadata adicional
    """
    http_status: int = status.HTTP_400_BAD_REQUEST
    error_type: ErrorType = ErrorType.VALIDATION

    def __init__(
        self,
        message: str = "Domain error occurred",
        error_code: Optional[str] = None,
        details: Optional[dict] = None,
        original_error: Optional[Exception] = None
    ):
        """
        Args:
            message: Mensaje descriptivo del error
            error_code: Código único para identificación
            details: Información adicional estructurada
            original_error: Excepción original (para debugging)
        """
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.original_error = original_error
        super().__init__(self.message)

    def __str__(self):
        base_str = f"[{self.error_type.value}] {self.message}"
        if self.error_code:
            base_str += f" (code: {self.error_code})"
        if self.original_error:
            base_str += f" [Original: {type(self.original_error).__name__}: {str(self.original_error)}]"
        return base_str

# ==================================================================
# Excepciones de Autenticación y Autorización
# ==================================================================
class InvalidCredentialsError(DomainException):
    """Credenciales inválidas (email/contraseña incorrectos)"""
    http_status = status.HTTP_401_UNAUTHORIZED
    error_type = ErrorType.AUTH

    def __init__(self, message: str = "Invalid credentials"):
        super().__init__(message, "auth-001")

class PermissionDeniedError(DomainException):
    """Acceso denegado por falta de permisos"""
    http_status = status.HTTP_403_FORBIDDEN
    error_type = ErrorType.PERMISSION

    def __init__(
        self,
        message: str = "Permission denied",
        required_roles: Optional[list] = None,
        user_roles: Optional[list] = None
    ):
        details = {}
        if required_roles:
            details["required_roles"] = required_roles
        if user_roles:
            details["user_roles"] = user_roles
            
        super().__init__(
            message,
            "auth-002",
            details=details
        )

# ==================================================================
# Excepciones de Usuario
# ==================================================================
class UserNotFoundError(DomainException):
    """Usuario no encontrado en el sistema"""
    http_status = status.HTTP_404_NOT_FOUND
    error_type = ErrorType.NOT_FOUND

    def __init__(self, message: str = "User not found"):
        super().__init__(message, "user-001")

class InvalidUserDataError(DomainException):
    """Datos de usuario inválidos"""
    http_status = status.HTTP_422_UNPROCESSABLE_ENTITY
    error_type = ErrorType.VALIDATION

    def __init__(
        self,
        message: str = "Invalid user data",
        validation_errors: Optional[dict] = None
    ):
        super().__init__(
            message,
            "user-002",
            details={"validation_errors": validation_errors or {}}
        )

class EmailAlreadyExistsError(DomainException):
    """Email ya registrado en el sistema"""
    http_status = status.HTTP_409_CONFLICT
    error_type = ErrorType.VALIDATION

    def __init__(self, message: str = "Email already registered"):
        super().__init__(message, "user-003")

class EmailNotVerifiedError(DomainException):
    """Intento de acceso con email no verificado"""
    http_status = status.HTTP_403_FORBIDDEN
    error_type = ErrorType.AUTH

    def __init__(self, message: str = "Email not verified"):
        super().__init__(message, "auth-003")

# ==================================================================
# Excepciones de Token
# ==================================================================
class InvalidTokenError(DomainException):
    """Token inválido o expirado"""
    http_status = status.HTTP_401_UNAUTHORIZED
    error_type = ErrorType.TOKEN

    def __init__(
        self,
        message: str = "Invalid or expired token",
        token_type: Optional[str] = None
    ):
        details = {"token_type": token_type} if token_type else {}
        super().__init__(message, "token-001", details=details)

# ==================================================================
# Excepciones de Email
# ==================================================================
class EmailSendingError(DomainException):
    """Fallo en el envío de email"""
    http_status = status.HTTP_502_BAD_GATEWAY
    error_type = ErrorType.EMAIL

    def __init__(
        self,
        message: str = "Failed to send email",
        service: Optional[str] = None,
        template: Optional[str] = None,
        original_error: Optional[Exception] = None
    ):
        details = {
            "service": service,
            "template": template
        }
        super().__init__(
            message,
            "email-001",
            details={k: v for k, v in details.items() if v is not None},
            original_error=original_error
        )

# ==================================================================
# Excepciones de Base de Datos (Ejemplo adicional)
# ==================================================================
class DatabaseError(DomainException):
    """Error en operación de base de datos"""
    http_status = status.HTTP_503_SERVICE_UNAVAILABLE
    error_type = ErrorType.DATABASE

    def __init__(
        self,
        message: str = "Database operation failed",
        operation: Optional[str] = None,
        original_error: Optional[Exception] = None
    ):
        super().__init__(
            message,
            "db-001",
            details={"operation": operation} if operation else {},
            original_error=original_error
        )

class InvalidOperationError(DomainException):
    """Operación inválida en la base de datos"""
    http_status = status.HTTP_400_BAD_REQUEST
    error_type = ErrorType.DATABASE

    def __init__(self, message: str = "Invalid database operation"):
        super().__init__(message, "db-002")
