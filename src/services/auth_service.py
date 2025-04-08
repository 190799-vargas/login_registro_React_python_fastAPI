import logging
from datetime import datetime, timezone
from typing import Optional, Tuple

from src.core.domain.entities import UserEntity, AuthTokenEntity
from src.core.domain.value_objects import Email, Password, UserId
from src.core.domain.enums import AuthProvider, UserRole
from src.core.domain.exceptions import(
    InvalidCredentialsError,
    EmailAlreadyExistsError,
    UserNotFoundError,
    InvalidTokenError
)
from src.interfaces.repositories.user_repository import IUserRepository
from src.interfaces.services.auth_service import IAuthService
from src.core.security import JWTManager
from src.core.utils.utils import generate_random_string
from src.config import settings
from src.models.user import UserCreate, UserLogin, UserOAuthCreate, UserPasswordReset, UserResponse
from src.interfaces.services.email_service import IEmailService
from src.core.logging import logging

class AuthService(IAuthService):
    """Implementación concreta del servicio de autenticación"""

    def __init__(
            self,
            user_repository: IUserRepository,
            jwt_manager: JWTManager,
            email_service: Optional['IEmailService'] = None
    ):
        self._user_repo = user_repository
        self._jwt = jwt_manager
        self._email_service = email_service
        self._logger = logging.getLogger(__name__)

    async def register(self, user_data: 'UserCreate') -> Tuple[Optional[UserEntity], Optional[AuthTokenEntity], str]:
        """Registro de nuevo usuario con email/contraseña"""

        try:
            email = Email(value=user_data.email.lower())
            password = Password.create(user_data.password)

            # Verificar email único
            if await self._user_repo.get_by_email(email):
                raise EmailAlreadyExistsError()
            
            # Crear entidad User
            user = UserEntity(
                email=email,
                hashed_password=password.hash,
                full_name=user_data.full_name,
                roles=[UserRole.USER],
                provider=AuthProvider.LOCAL,
                email_verified=False
            )

            # Guardar usuario
            saved_user = await self._user_repo.save(user)

            # Generar tokens
            tokens = self._jwt.generate_tokens(saved_user.id)

            # Enviar email de verificación (si hay servicio configurado)
            if self._email_service:
                verification_token = self._jwt.create_verification_token(saved_user.id)
                await self._send_verification_email(saved_user, verification_token)

            return saved_user, tokens, ""
        
        except EmailAlreadyExistsError:
            return None, None, "Email ya registrado"
        except Exception as e:
            self._logger.error(f"Error en registro: {str(e)}")
            return None, None, "Error en el registro"
        
    async def login(self, credentials: 'UserLogin') -> Tuple[Optional[UserEntity], Optional[AuthTokenEntity], str]:
        """Autenticación tradicional con email/contraseña"""

        try:
            email = Email(value=credentials.email.lower())
            user = await self._user_repo.get_by_email(email)

            if not user:
                raise InvalidCredentialsError()
            
            if not Password.verify(credentials.password, user.hashed_password):
                raise InvalidCredentialsError()
            
            # Actualizar último login
            user.last_login = datetime.now(timezone.utc)
            await self._user_repo.save(user)

            # Generar tokens
            tokens = self._jwt.generate_tokens(user.id)

            return user, tokens, ""
        
        except InvalidCredentialsError:
            return None, None, "Credenciales inválidas"
        except Exception as e:
            self._logger.error(f"Error en login: {str(e)}")
            return None, None, "Error en el login"
        
    async def oauth_login(self, provider: AuthProvider, oauth_data: 'UserOAuthCreate') -> Tuple[Optional[UserEntity], Optional[AuthTokenEntity], str]:
        """Autenticación con proveedores OAuth"""
        
        try:
            email = Email(value=oauth_data.email.lower())
            user = await self._user_repo.get_by_provider_id(provider, oauth_data.provider_id)
        
            if not user:
                # Crear nuevo usuario para OAuth
                user = UserEntity(
                    email=email,
                    provider=provider,
                    provider_id=oauth_data.provider_id,
                    full_name=oauth_data.full_name or "",
                    roles=[UserRole.USER],
                    email_verified=True,
                    hashed_password=f"oauth_{generate_random_string(32)}",  # Placeholder seguro
                    avatar_url=oauth_data.avatar_url
                )
                user = await self._user_repo.save(user)

                # Generate tokens
            tokens = self._jwt.generate_tokens(user.id)

            return user, tokens, ""

        except Exception as e:
            self._logger.error(f"OAuth login failed: {str(e)}")
            return None, None, "OAuth authentication failed"

    async def verify_email(self, token: str) -> bool:
        """Verify user email using JWT token"""
        try:
            payload = self._jwt.verify_token(token)
            if not payload or payload.get('type') != 'verify_email':
                return InvalidTokenError()

            user_id = UserId(payload['sub'])
            user = await self._user_repo.get_by_id(user_id)
            if not user:
                return False

            user.email_verified = True
            await self._user_repo.save(user)
            return True

        except Exception as e:
            self._logger.error(f"Email verification failed: {str(e)}")
            return False

    async def request_password_reset(self, email: Email) -> bool:
        """Initiate password reset process"""
        try:
            user = await self._user_repo.get_by_email(email)
            if not user:
                return True  # Don't reveal if user doesn't exist

            if self._email_service:
                token = self._jwt.create_password_reset_token(user.id)
                reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"
                await self._email_service.send_email(
                    to_email=str(user.email.value),
                    subject="Password Reset Request",
                    template_name="password_reset",
                    context={"reset_url": reset_url}
                )
            return True

        except Exception as e:
            self._logger.error(f"Password reset request failed: {str(e)}")
            return False

    async def reset_password(self, reset_data: 'UserPasswordReset') -> bool:
        """Complete password reset process"""
        try:
            payload = self._jwt.verify_token(reset_data.token)
            if not payload or payload.get('type') != 'reset_password':
                return False

            user_id = UserId(payload['sub'])
            user = await self._user_repo.get_by_id(user_id)
            if not user:
                return False

            # Update password
            new_password = Password.create(reset_data.new_password)
            user.hashed_password = new_password.hash
            await self._user_repo.save(user)

            return True

        except Exception as e:
            self._logger.error(f"Password reset failed: {str(e)}")
            return False

    async def refresh_token(self, refresh_token: str) -> Optional[AuthTokenEntity]:
        """Generate new access token using refresh token"""
        try:
            payload = self._jwt.verify_token(refresh_token)
            if not payload or payload.get('type') != 'refresh':
                return None

            return self._jwt.generate_tokens(UserId(payload['sub']))

        except Exception as e:
            self._logger.error(f"Token refresh failed: {str(e)}")
            return None

    async def get_authenticated_user(self, token: str) -> Optional[UserEntity]:
        """Get authenticated user from JWT token"""
        try:
            payload = self._jwt.verify_token(token)
            if not payload or payload.get('type') != 'access':
                return None

            user_id = UserId(payload['sub'])
            return await self._user_repo.get_by_id(user_id)

        except Exception as e:
            self._logger.error(f"Failed to get authenticated user: {str(e)}")
            return None

    async def _send_verification_email(self, user: UserEntity) -> None:
        """Send email verification message"""
        if not self._email_service:
            return

        token = self._jwt.create_verification_token(user.id)
        verification_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
        
        await self._email_service.send_email(
            to_email=str(user.email.value),
            subject="Verify Your Email",
            template_name="verification",
            context={"verification_url": verification_url}
        )

    # Legacy methods for backward compatibility
    async def register_user(self, user_data: 'UserCreate') -> Tuple[Optional['UserResponse'], str]:
        user, _, error = await self.register(user_data)
        return UserResponse(**user.dict()) if user else None, error

    async def login_user(self, credentials: 'UserLogin') -> Tuple[Optional['UserResponse'], str, Optional[str]]:
        user, tokens, error = await self.login(credentials)
        return (UserResponse(**user.dict()) if user else None,
                error,
                tokens.access_token if tokens else None)
