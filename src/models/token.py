from datetime import datetime, timedelta
from pydantic import BaseModel, Field, validator
from jose import jwt
from typing import Optional
from src.config import settings
from enum import Enum
import uuid

class TokenType(str, Enum):
    """Tipos de tokens soportados por el sistema"""
    ACCESS = "access"
    REFRESH = "refresh"
    VERIFICATION = "verification"
    PASSWORD_RESET = "password_reset"
    OAUTH_STATE = "oauth_state" # para proteccion CSRF en OAuth

class TokenBase(BaseModel):
    """Estructura base para todos los tokens"""
    sub: str = Field(..., description="Subject (user ID o email)")
    type: TokenType = Field(..., description="Tipo de token")
    iat: datetime = Field(default_factory=datetime.now, description="Is used at")
    exp: datetime = Field(..., description="Expiration time")
    jti: str = Field(default_factory=lambda: str(uuid.uuid4()), description="JWT ID")
    scopes: list[str] = Field(default=["authenticated"], description="permisos")

    @validator('exp', pre=True)
    def set_expiration(cls, v, values):
        """Calcula la fecha de expiración basada en el tipo de token"""
        if v is None:
            token_type = values.get('type')
            if token_type == TokenType.ACCESS:
                delta = timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
            
            elif token_type == TokenType.REFRESH:
                delta = timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
            
            elif token_type in (TokenType.VERIFICATION, TokenType.PASSWORD_RESET):
                delta = timedelta(hours=24)
            
            else:
                delta = timedelta(minutes=15)
            return datetime.now() + delta
        return v
    
class TokenCreate(BaseModel):
    """Datos necesarios para crear un nuevo token"""
    user_id: str
    type: TokenType = TokenType.ACCESS
    custon_expires: Optional[timedelta] = None
    scope: list[str] = ["authenticated"]

class TokenPayload(TokenBase):
    """Payload decodificado de un JWT"""
    exp: int #Timestamp UNIX
    iat: int #Timestamp UNIX

class TokenResponse(BaseModel):
    """Respuesta estándar para endpoints de autenticación"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

def create_jwt_token(data: dict) -> str:
    """Crear un JWT firmado con la configuracion de la app"""
    return jwt.encode(
        data,
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithm=settings.JWT_ALGORITHM
    )

def verify_jwt_token(token: str) -> TokenPayload:
    """Verifica y decodifica un token JWT"""
    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithms=[settings.JWT_ALGORITHM],
        options={
            "verify_aud": False,
            "verify_iss": False,
            "require_sub": True,
            "verify_exp": True
        }
    )
    return TokenPayload(**payload)

def generate_token_pair(user_id: str) -> TokenResponse:
    """Genera par de tokens (access + refresh)"""
    access_payload = TokenBase(
        sub=user_id,
        type=TokenType.ACCESS
    ).dict()

    refresh_payload = TokenBase(
        sub=user_id,
        type=TokenType.REFRESH
    ).dict()

    return TokenResponse(
        access_token=create_jwt_token(access_payload),
        refresh_token=create_jwt_token(refresh_payload),
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

def generate_oauth_state_token() -> str:
    """Genera token seguro para protección CSRF en OAuth"""
    state_payload = TokenBase(
        sub="oauth_state",
        type=TokenType.OAUTH_STATE,
        scopes=["oauth"]
    ).dict()
    
    return create_jwt_token(state_payload)