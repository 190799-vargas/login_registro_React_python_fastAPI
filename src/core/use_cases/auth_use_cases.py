# ======================================================================================================================
# Casos de uso principales:
#   * Registro con email/contraseña, Login tradicional, Login con OAuth ,Refresco de tokens, Verificación de email
# Dependencias:
#   * UserRepository para persistencia, JWTManager para tokens, Value objects (Email, Password, UserId)
#Excepciones de dominio:
#   * Errores específicos para cada flujo
# ======================================================================================================================

from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from src.core.domain.entities import UserEntity, AuthTokenEntity
from src.core.domain.value_objects import Email, Password, UserId
from src.core.domain.enums import AuthProvider, UserRole
from src.interfaces.repositories.user_repository import IUserRepository
from src.interfaces.services.auth_service import IAuthService
from src.core.security import JWTManager
from src.core.domain.exceptions import (
    InvalidCredentialsError,
    EmailAlreadyExistsError,
    UserNotFoundError,
    InvalidTokenError
)
from src.interfaces.repositories.email_verification_repository import IEmailVerificationRepository
from src.core.domain.entities import EmailVerificationEntity

class RegisterUserUseCase:
    """Caso de uso para registro de nuevos usuarios"""

    def __init__(self, user_repo: IUserRepository, jwt_manager: JWTManager):
        self._user_repo = user_repo
        self._jwt = jwt_manager

    async def execute(self, email: Email, password: Password, full_name: str) -> Tuple[UserEntity, AuthTokenEntity]:
        """
        Ejecuta el registro de usuario
        
        Args:
            email: Email validado
            password: Password validado
            full_name: Nombre completo
            
        Returns:
            Tuple[UserEntity, AuthTokenEntity]: Entidad de usuario y tokens
            
        Raises:
            EmailAlreadyExistsError: Si el email ya está registrado
        """
        # Verificar unicidad del email
        if await self._user_repo.get_by_email(email):
            raise EmailAlreadyExistsError()
        
        # Crear entidad User
        user = UserEntity(
            email=email,
            hashed_password=password.hash,
            full_name=full_name,
            roles=[UserRole.USER],
            provider=AuthProvider.LOCAL
        )
        
        # Persistir
        saved_user = await self._user_repo.save(user)

        # Generar tokens
        tokens = self._jwt.generate_tokens(saved_user.id)

        return saved_user, tokens
    
class LoginUserUseCase:
    """Caso de uso para autenticación de usuarios"""

    def __init__(self, user_repo: IUserRepository, jwt_manager: JWTManager):
        self._user_repo = user_repo
        self._jwt = jwt_manager

    async def execute(self, email: Email, password: str) -> Tuple[UserEntity, AuthTokenEntity]:
        """
        Ejecuta el login de usuario
        
        Args:
            email: Email validado
            password: Contraseña en texto plano
            
        Returns:
            Tuple[UserEntity, AuthTokenEntity]: Entidad de usuario y tokens
            
        Raises:
            InvalidCredentialsError: Si las credenciales son incorrectas
            UserNotFoundError: Si el usuario no existe
        """
        user  = await self._user_repo.get_by_email(email)
        if not user:
            raise UserNotFoundError()
        
        if not Password.verify(password, user.hashed_password):
            raise InvalidCredentialsError()
        
        # Actualizar último login
        user.last_login = datetime.now(timezone.utc)
        updated_user = await self._user_repo.save(user)

        # Genera tokens
        tokens = self._jwt.generate_tokens(user.id)

        return updated_user, tokens
    
class OAuthLoginUseCase:
    """Caso de uso para autenticación OAuth (Google, GitHub, etc.)"""

    def __init__(self, user_repo: IUserRepository, jwt_manager: JWTManager):
        self._user_repo = user_repo
        self._jwt = jwt_manager

    async def execute(
            self,
            provider: AuthProvider,
            provider_id: str,
            email: Email,
            access_token: str,
            full_name: Optional[str] = None
        ) -> Tuple[UserEntity, AuthTokenEntity]:
        """
        Ejecuta login/registro via OAuth
        
        Args:
            provider: Proveedor OAuth (Google, GitHub)
            provider_id: ID único del proveedor
            email: Email validado
            access_token: Token de acceso OAuth
            full_name: Nombre completo (opcional)
            
        Returns:
            Tuple[UserEntity, AuthTokenEntity]: Entidad de usuario y tokens
        """
        user = await self._user_repo.get_by_provider_id(provider, provider_id)

        if not user:
            # Crear nuevo usuario si no existe
            user = UserEntity(
                email=email,
                provider=provider,
                provider_id=provider_id,
                full_name=full_name or "",
                roles=[UserRole.USER],
                email_verified=True,
                hashed_password="oauth_no_password" # Placeholder seguro
            )
            user = await self._user_repo.save(user)

        # Generar Tokens JWT
        tokens = self._jwt.generate_tokens(user.id)

        return user, tokens

class RefreshTokenUseCase:
    """Caso de uso para refresco de tokens JWT"""

    def __init__(self, jwt_manager: JWTManager):
        self._jwt = jwt_manager

    def execute(self, refresh_token: str) -> AuthTokenEntity:
        """
        Genera nuevos tokens a partir de un refresh token válido
        
        Args:
            refresh_token: Token de refresco
            
        Returns:
            AuthTokenEntity: Nuevos tokens de acceso
            
        Raises:
            InvalidTokenError: Si el token es inválido
        """
        payload = self._jwt.verify_token(refresh_token)
        if not payload or payload.get("type") != "refresh":
            raise InvalidTokenError()
        
        return self._jwt.generate_tokens(UserId(payload["sub"]))
    
class VerifyEmailUseCase:
    """Caso de uso para verificación de emails"""

    def __init__(self, user_repo: IUserRepository, email_ver_repo:IEmailVerificationRepository, jwt_manager: JWTManager):
        self._user_repo = user_repo
        self._email_ver_repo = email_ver_repo
        self._jwt = jwt_manager

    async def execute(self, token: str) -> bool:
        """
        Verifica un email usando token JWT
        
        Args:
            token: Token de verificación
            
        Returns:
            bool: True si la verificación fue exitosa
            
        Raises:
            InvalidTokenError: Si el token es inválido
            UserNotFoundError: Si el usuario no existe
        """
        payload = self._jwt.verify_token(token)
        if not payload or payload.get("type") != "verify_email":
            raise InvalidTokenError()
        
        user_id = UserId(payload["sub"])
        user = await self._user_repo.get_by_id(user_id)
        if not user:
            raise UserNotFoundError()
        
        user.email_verified = True
        await self._user_repo.save(user)

        # Elimina el token usado
        await self._email_ver_repo.delete_token(user_id)

        return True

class SaveEmailVerificationUseCase:
    """Guarda el token de verificación generado para un usuario"""

    def __init__(self, email_verification_repo: IEmailVerificationRepository):
        self._email_verification_repo = email_verification_repo

    async def execute(self, entity: EmailVerificationEntity) -> bool:
        return await self._email_verification_repo.save_verification(entity)


class VerifyEmailWithTokenUseCase:
    """Verifica el email del usuario mediante token"""

    def __init__(self, email_verification_repo: IEmailVerificationRepository):
        self._email_verification_repo = email_verification_repo

    async def execute(self, entity: EmailVerificationEntity) -> bool:
        return await self._email_verification_repo.verify_email(entity)
