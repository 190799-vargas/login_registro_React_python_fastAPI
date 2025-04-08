# =============================================================================
# Hereda de BaseSettings (de Pydantic) para manejar configuraciones
# Define todas las variables de entorno necesarias con sus tipos
# Soporte para Google y GitHub
# SecretStr oculta el valor en logs y representaciones
# Usa Optional para que sean opcionales
# Singleton que carga automáticamente las configuraciones al importarse
# =============================================================================

from pydantic import BaseSettings, SecretStr # para validación automática y Tipos especiales como SecretStr para datos sensibles
from typing import Optional
from pydantic import Field
from enum import Enum

class EmailProvider(str, Enum):
    CONSOLE = "console"
    SMTP = "smtp"
    SENDGRID = "sendgrid"
    MAILGUN = "mailgun"

class Settings(BaseSettings):
    # Configuración MongoDB
    MONGODB_URI: str = "mongodb://localhost:27017/auth_login"

    # Configuración JWT
    JWT_SECRET_KEY: SecretStr
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_ISSUER: str = "Mi App"
    
    # Tiempo de expiración para tokens de verificación de email (24 horas por defecto)
    JWT_VERIFY_EMAIL_EXPIRE_HOURS: int = 24

    # Tiempo de expiración para tokens de reseteo de contraseña (1 hora por defecto)
    JWT_RESET_PASSWORD_EXPIRE_HOURS: int = 1

    # Configuración OAuth (Google)
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[SecretStr] = None
    GOOGLE_REDIRECT_URI: Optional[str] = None

    # Configuración OAuth (GitHub)
    GITHUB_CLIENT_ID: Optional[str] = None
    GITHUB_CLIENT_SECRET: Optional[SecretStr] = None
    GITHUB_REDIRECT_URI: Optional[str] = None

    # Email Configuración
    EMAIL_PROVIDER: EmailProvider = EmailProvider.CONSOLE
    EMAIL_USER: str = None
    EMAIL_PASSWORD: SecretStr
    EMAIL_FROM: str = "noreply@gmail.com"
    EMAIL_FROM_NAME: str = "Auth Service"
    SMTP_SERVER: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    APP_NAME: str = "Mi App"

    # Configuración SendGrid
    SENDGRID_API_KEY: Optional[SecretStr] = None
    SENDGRID_VERIFICATION_TEMPLATE_ID: Optional[str] = None
    SENDGRID_PASSWORD_RESET_TEMPLATE_ID: Optional[str] = None
    
    # Configuración Mailgun
    MAILGUN_API_KEY: Optional[SecretStr] = None
    MAILGUN_DOMAIN: Optional[str] = None

    # Nueva configuración para seguridad de contraseñas
    MIN_PASSWORD_LENGTH: int = Field(8, description="Longitud mínima permitida para contraseñas")
    PASSWORD_REQUIRE_UPPERCASE: bool = True  # Opcional: para validaciones avanzadas
    PASSWORD_REQUIRE_SYMBOLS: bool = True   # Opcional
    PASSWORD_HASH_ROUNDS: int = 12 # Password Hashing
    
    # Logging
    LOG_LEVEL: str = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    LOG_AS_JSON: bool = False  # True en producción
    
    # Configuración de la App
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    DEBUG: bool = False
    ENVIRONMENT: str = "dev"
    CORS_ALLOWED_ORIGINS: list = ["*"]
    FRONTEND_URL: str = "http://localhost:3000"



    # Busca automáticamente en archivo .env, Codificación del archivo,  Distingue mayúsculas/minúsculas
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True

# Instancia singleton de configuración
settings = Settings()

# =============================================================================
# Cómo funciona:

# 1. Jerarquía de carga:
    # 1. Valores por defecto (definidos en el código)
    # 2. Archivo .env (en el mismo directorio)
    # 3. Variables de entorno del sistema operativo

# 2. Para datos sensibles:
    # 1. SecretStr oculta el valor en logs y representaciones
    # 2. Acceso al valor real con settings.JWT_SECRET_KEY.get_secret_value()

# ============================================================================