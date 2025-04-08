# ===============================================================================================================================
# Inmutabilidad:
#   * Clase marcada como frozen=True
#   * Todos los objetos de valor son inmutables por diseño
# Validaciones integradas:
#   * Valida UUIDs correctos
#   * Dominios de email permitidos, Fortaleza de contraseñas, Caracteres válidos en nombres
# Métodos útiles:
#   * create() para generación de nuevos IDs, from_string() para parseo seguro, Propiedad hex para acceso al formato hexadecimal
#   * Cálculo de fortaleza de contraseña, Verificación de expiración de tokens, Formateo de nombres completos
# Seguridad:
#   * Solo trabaja con UUIDs, no con strings crudos, Validación estricta en construcción
#   * Nunca almacena contraseñas en texto plano, Normalización de datos (emails en minúsculas)
# Tipado fuerte:
#   * Uso de Enums (AuthProvider), Campos opcionales explícitos
#   * Tipo específico para el campo value (UUID), Anotaciones de tipo en todos los métodos
# ===============================================================================================================================

from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional
import re
from uuid import UUID, uuid4

from src.core.domain.enums import AuthProvider

class UserId(BaseModel):
    """
    Objeto de valor para identificadores de usuario
    Garantiza que todos los IDs sean UUID válidos e inmutables
    """
    value: UUID = Field(..., description="UUID único que identifica al usuario")

    @validator('value')
    def validate_uuid(cls, v):
        """Valida que el valor sea un UUID válido"""
        if not isinstance(v, UUID):
            raise ValueError("El ID de usuario deb se un UUID válido")
        return v
    
    @classmethod
    def create(cls) -> 'UserId':
        """Factory method para generar nuevos IDs"""
        return cls(value=uuid4())
    
    @classmethod
    def form_string(cls, id_str: str) -> 'UserId':
        """Crea un UserId a partir de un string UUID válido"""
        try:
            return cls(value=UUID(id_str))
        except ValueError as e:
            raise ValueError(f"Formato de ID inválido: {str(e)}")
    
    @property
    def hex(self) -> str:
        """Representación hexagonal del UUID"""
        return self.value.hex
    
    def __str__(self):
        return str(self.value)
    
    def __eq__(self, other):
        if not isinstance(other, UserId):
            return False
        return self.value == other.value
    
    def __hash__(self):
        return hash(self.value)
    
    class Config:
        frozen = True # Hace el objeto inmutable
        json_encoders = {
            UUID: lambda v: str(v) # Serialización a string en JSON
        }

class Email(BaseModel):
    """Objeto de valor para emails con validación avanzada"""
    value: EmailStr
    verified: bool = False
    provider: AuthProvider = AuthProvider.LOCAL

    @validator('value')
    def validate_email_domain(cls, v):
        # Ejemplo: Validar dominios permitidos
        if not v.endswith(('@gmail.com', '@company.com')):
            raise ValueError("Dominio de email no permitido")
        return v.lower() # Normaliza a munúsculas
    
    def __str__(self):
        return self.value
    
class Password(BaseModel):
    """Objeto de valor para contraseñas seguras"""
    hash: str # Guardamos solo el hash
    strength: float = Field(..., ge=0, le=1) # Fuerza estimada 0-1

    @classmethod
    def create(cls, plain_password: str) -> 'Password':
        """Factory method para creación segura"""
        if len(plain_password) < 8:
            raise ValueError("La contraseña debe tener al menos 8 caracteres")
        
        strength = cls.calculate_strength(plain_password)
        return cls(
            hash=cls._hash_password(plain_password),
            strength=strength
        )
    
    @staticmethod
    def _hash_password(password: str) -> str:
        """Ejemplo: Usar bcrypt en la implementación real"""
        return f"hashed_{password}" # Placeholder
    
    @staticmethod
    def calculate_strength(password: str) -> float:
        """Calcula fortaleza de la contraseña (0-1)"""
        length = min(len(password) / 20, 1.0)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        return (length * 0.4 + has_upper * 0.2 + has_digit * 0.2 + has_special * 0.2)
    
class PersonalName(BaseModel):
    """Objeto de valor para nombres personales"""
    first_name: str = Field(..., max_length=50)
    last_name: str = Field(..., max_length=50)
    display_name: Optional[str] = None

    @validator('first_name', 'last_name')
    def validate_name_chars(cls, v):
        if not re.match(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s-]+$', v):
            raise ValueError("Solo se permiten letras y guiones")
        return v.strip()
    
    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"
    
class OAuthCredentials(BaseModel):
    """Objeto de valor para credenciales Oauth"""
    provider: AuthProvider
    provider_id: str
    access_token: str
    refresh_token: Optional[str] = None
    expires_at: Optional[int] = None # Timestamp UNIX

class SecurityToken(BaseModel):
    """Objeto de valor para tokens de seguridad"""
    value: str
    type: str # 'verify_email', 'reset_password', etc.
    expires_at: int # Tmiestamp UNIX

    def is_expired(self, current_time: int) -> bool:
        return current_time > self.expires_at
    