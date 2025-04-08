from datetime import datetime, timezone
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field, validator
from bson import ObjectId

from src.core.domain.enums import UserRole, AuthProvider
from src.core.domain.entities import UserEntity
from src.core.domain.value_objects import Email, Password
from src.config import settings

# =======================
# Configuración Base
# =======================
class PyObjectId(ObjectId):
    """Wrapper para ObjectId de MongoDB compatible con Pydantic"""
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("ObjectId invalido")
        return ObjectId(v)
    
    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")

# Modelo Base
class UserBase(BaseModel):
    """Campos base compartidos por todos los modelos"""
    email: EmailStr = Field(..., example="user@example.com", description="Email válido del usuario")
    full_name: Optional[str] = Field(None, max_length=100, description="Nombre completo")
    disabled: bool = Field(False,  description="Indica si el usuario está desactivado")
    roles: List[UserRole] = Field([UserRole.USER], description="Roles asignados")

# Para creación de usuarios on conversión a Entidad
class UserCreate(UserBase):
    """Modelo para creación de usuarios (registro)"""
    password: str = Field(..., min_length=8, description="Contraseña en texto plano (será hasheada)")
    provider: AuthProvider = Field(AuthProvider.LOCAL, description="Método de autenticación") #Enum AuthProvider
    email_verified: bool = Field(False, description="Indica si el email fue verificado")

    @validator('password')
    def validate_password(cls, v):
        """Valida complejidad de la contraseña"""
        if len(v) < settings.MIN_PASSWORD_LENGTH:
            raise ValueError(f"La Contraseña debe contener al menos {settings.MIN_PASSWORD_LENGTH} caracteres")
        
        if settings.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in v):
            raise ValueError("La contraseña debe contener al menos una mayúscula")
    
        if settings.PASSWORD_REQUIRE_SYMBOLS and v.isalnum():
            raise ValueError("La contraseña debe contener al menos un símbolo")
        return v
    def to_entity(self) -> UserEntity:
        """convierte a UserEntity"""
        return UserEntity(
            email=Email(value=self.email),
            hashed_password=Password.create(self.password).hash,
            full_name=self.full_name,
            roles=self.roles,
            provider=self.provider,
            email_verified=self.email_verified
        )
    
# Para actualización
class UserUpdate(BaseModel):
    """Modelo para actualización de usuarios"""
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None
    roles: Optional[List[UserRole]] = None

    @validator('email')
    def validate_email_unique(cls, v, values, **kwargs):
        """Valida unicidad del email (debe implementarse en el repositorio)"""
        # La validación real se hace en el servicio/repositorio
        return v

# Modelo de base de datos
class UserInDB(UserBase):
    """Modelo completo para usuarios en la base de datos"""
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    provider: AuthProvider
    email_verified: bool
    hashed_password: str = Field(..., alias="password")
    created_at: datetime = Field(default_factory=datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=datetime.now(timezone.utc))
    last_login: Optional[datetime] = None # Ultimo inicio de sesion
    provider_id: Optional[str] = None # ID del proveedor OAuth
    avatar_url: Optional[str] = None  # URL de imagen de perfil

    class Config:
        allow_population_by_field_name = True
        json_encoders = {ObjectId: str}
    
    @classmethod
    def from_entity(cls, entity: UserEntity) -> 'UserInDB':
        """Crea UserInDB desde UserEntity"""
        return cls(
            _id=entity.id,
            email=entity.email.value,
            full_name=entity.full_name,
            roles=entity.roles,
            disabled=entity.disabled,
            provider=entity.provider,
            email_verified=entity.email.verified,
            password=entity.hashed_password,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
            last_login=entity.last_login,
            provider_id=entity.provider_id,
            avatar_url=entity.avatar_url
        )
# Respuesta API
class UserResponse(UserBase):
    """Modelo seguro para respuestas API (sin datos sensibles)"""
    id: str = Field(..., alias="_id")
    provider: AuthProvider
    email_verified: bool
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] # Ultimo inicio de sesion
    avatar_url: Optional[str] = None

    class Config:
        json_encoders = {ObjectId: str}

class UserPublicProfile(UserResponse):
    """Modelo para perfiles públicos"""
    provider_id: Optional[str] = None  # Solo visible para el propio usuario/admins

# Modelos para autenticación
class UserLogin(BaseModel):
    """Modelo para inicio de sesión"""
    email: EmailStr
    password: str

class UserOAuthCreate(BaseModel):
    """Modelo para registro via OAuth"""
    email: EmailStr
    provider: AuthProvider # Enum AuthProvider
    provider_id: str
    access_token: str
    refresh_token: Optional[str]
    full_name: Optional[str]
    avatar_url: Optional[str]

class UserPasswordReset(BaseModel):
    """Modelo para reset de contraseña"""
    token: str
    new_password: str

    @validator('new_password')
    def validate_password(cls, v):
        if len(v) < settings.MIN_PASSWORD_LENGTH:
            raise ValueError(f"La Contraseña debe contener al menos {settings.MIN_PASSWORD_LENGTH} caracteres")
        
        if settings.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in v):
            raise ValueError("La contraseña debe contener al menos una mayúscula")
    
        if settings.PASSWORD_REQUIRE_SYMBOLS and v.isalnum():
            raise ValueError("La contraseña debe contener al menos un símbolo")
        return v
    
# Funciones Auxiliares
def user_to_response(entity: UserEntity) -> UserResponse:
    """Convierte UserEntity a UserResponse (versión mejorada)"""
    return UserResponse(
        _id=str(entity.id),
        email=entity.email.value,
        full_name=entity.full_name,
        roles=entity.roles,
        disabled=entity.disabled,
        provider=entity.provider,
        email_verified=entity.email.verified,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        last_login=entity.last_login,
        avatar_url=entity.avatar_url
    )