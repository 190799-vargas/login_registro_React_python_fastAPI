# ===========================================================================================
# Cobertura completa de los flujos de autenticación:
#   1. Registro local,
#   2. Login con email/contraseña,
#   3. OAuth (Google, GitHub), Verificación de email, Reset de contraseña, Refresh de tokens
# Type hints detallados:
#   1. Retornos con Tuple para manejar tanto éxito como errores
#   2. Uso de modelos Pydantic (UserCreate, UserResponse, etc.)
#   3. Enums para proveedores OAuth
# Seguridad integrada:
#   1. Métodos para invalidación de tokens
#   2. Verificación en dos pasos
# Independencia de implementación:
#   1. Fácil cambiar entre JWT, OAuth2, etc.
#   2. Compatible con diferentes backends (Firebase, Auth0, etc.)
# ===========================================================================================

from abc import ABC, abstractmethod
from typing import Optional, Tuple
from datetime import datetime, timezone

from src.models.user import (
    UserCreate,
    UserLogin,
    UserOAuthCreate,
    UserResponse,
    UserPasswordReset
)
from src.core.domain.entities import UserEntity, AuthTokenEntity
from src.core.domain.value_objects import Email, Password, UserId
from src.core.domain.enums import AuthProvider

class IAuthService(ABC):
    """Interfaz abstracta para el servicio de autenticacion"""

    @abstractmethod
    async def register_user(self, user_data: UserCreate) -> Tuple[Optional[UserEntity], Optional[AuthTokenEntity], str]:
        """
        Registra un nuevo usuario
        
        Returns:
            Tuple[UserEntity | None, AuthTokenEntity | None, str]:
            (entidad usuario, tokens, mensaje de error)
        """
        pass

    @abstractmethod
    async def login_user(self, credentials: UserLogin) -> Tuple[Optional[UserEntity], Optional[AuthTokenEntity], str]:
        """
        Autentica un usuario existente
        
        Returns:
            Tuple[UserEntity | None, AuthTokenEntity | None, str]:
            (entidad usuario, tokens, mensaje error)
        """
        pass

    @abstractmethod
    async def oauth_login(self, provider: AuthProvider, oauth_data: UserOAuthCreate) -> Tuple[Optional[UserEntity], Optional[AuthTokenEntity], str]:
        """
        Autentica/registra un usuario via Oauth (Google, GitHub, etc.)
        Returns:
            Tuple[UserEntity | None, AuthTokenEntity | None, str]:
            (entidad usuario, tokens, mensaje error)
        """
        pass

    @abstractmethod
    async def verify_email(self, token: str) -> bool:
        """Verifica la dirección de email de un usuario usando JWT"""
        pass

    @abstractmethod
    async def request_password_reset(self, email: str) -> bool:
        """Solicita el reseteo de contraseña"""
        pass

    @abstractmethod
    async def reset_password(self, reset_data: UserPasswordReset) -> bool:
        """Cambia la contraseña usando un token válido"""
        pass

    @abstractmethod
    async def refresh_token(self, user_id: UserId, refresh_token: str) -> Tuple[Optional[AuthTokenEntity], str]:
        """
        Genera un nuevo token de acceso
        Returns:
            Tuple[str | None, str | None]: (nuevo token, nuevo refresh token)
        """
        pass

    @abstractmethod
    async def logout_user(self, user_id: str, token: str) -> bool:
        """Invalida los tokens del usuario"""
        pass

    @abstractmethod
    async def get_current_user(self, token: str) -> Optional[UserResponse]:
        """Obtiene el usuario actual apartir del token"""
        pass

    @abstractmethod
    async def get_authenticated_user(self, token: str) -> Optional[UserEntity]:
        """Obtiene la entidad User desde un token válido"""
        pass

    # ---- Métodos de Compatibilidad ----
    @abstractmethod
    async def register_user(self, user_data: UserCreate) -> Tuple[Optional[UserResponse], str]:
        """Versión legacy que retorna UserResponse"""
        pass

    @abstractmethod
    async def login_user(self, credentials: UserLogin) -> Tuple[Optional[UserResponse], str, Optional[str]]:
        """Versión legacy que retorna UserResponse"""
        pass