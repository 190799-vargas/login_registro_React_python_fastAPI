# =========================================================================================================
# Entidades puras del dominio:
#   * Sin dependencias de infraestructura, Modelan el negocio (no la base de datos o APIs)
# Tipado fuerte:
#   * Uso de enums (UserRole, AuthProvider), Campos opcionales bien definidos, Validaciones integradas
# Compatibilidad con MongoDB:
#   * PyObjectId para IDs, Configuración para alias _id, Serializadores para ObjectId
# Seguridad:
#   * Campos sensibles como hashed_password, Entidades para flujos seguros (verificación, reset)
# Documentación:
#   * Ejemplos integrados, Esquemas OpenAPI-ready
# Diferencias con models/user.py:
#   1. UserEntity vs UserInDB:
#       * UserEntity es agnóstica de infraestructura
#       * UserInDB incluye detalles de persistencia
#   2. Propósito:
#       * Entidades: Lógica de negocio central
#       * Modelos: Intercambio de datos (APIs, DB)
# =========================================================================================================

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field
from bson import ObjectId

from src.core.domain.enums import UserRole, AuthProvider

class PyObjectId(ObjectId):
    """Wrapper para ObjectId de MongoDB compatible con Pydantic"""
    @classmethod
    def __get_validators__(cls):
        yield cls.validate
    
    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)
    
    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")

class UserEntity(BaseModel):
    """Entidad principal de usuario del dominio"""
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    email: EmailStr
    hashed_password: str
    full_name: Optional[str] = None
    roles: List[UserRole] = [UserRole.USER]
    provider: AuthProvider = AuthProvider.LOCAL
    provider_id: Optional[str] = None
    email_verified: bool = False
    disabled: bool = False
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    avatar_url: Optional[str] = None

    class Config:
        allow_population_by_field_name = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "_id": "507f1f77bcf86cd799439011",
                "email": "user@example.com",
                "hashed_password": "$2b$12$...",
                "roles": ["user"],
                "provider": "local"
            }
        }

class AuthTokenEntity(BaseModel):
    """Entidad para tokens de autenticación"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: PyObjectId

class EmailVerificationEntity(BaseModel):
    """Entidad para verificación de emails"""
    email: EmailStr
    token: str
    expires_at: datetime
    user_id: PyObjectId

class PasswordResetEntity(BaseModel):
    """Entidad para reseteo de contraseñas"""
    email: EmailStr
    token: str
    expires_at: datetime
    user_id: PyObjectId

class OAuthStateEntity(BaseModel):
    """Entidad para estado de Oauth (CSRF protection)"""
    state: set
    redirect_url: str
    expires_at: datetime
