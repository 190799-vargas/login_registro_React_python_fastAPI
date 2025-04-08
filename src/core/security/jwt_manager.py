import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Union
from jose import jwt, JWTError

from src.config import settings
from src.core.domain.value_objects import UserId
from src.core.domain.entities import AuthTokenEntity
from src.models.token import TokenType
from src.core.domain.exceptions import InvalidTokenError

logger = logging.getLogger(__name__)

class JWTManager:
    """Gestión centralizada de tokens JWT"""

    def __init__(self):
        self.secret_key = settings.JWT_SECRET_KEY.get_secret_value()
        self.algorithm = settings.JWT_ALGORITHM
        self.access_expire = timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
        self.refresh_expire = timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
        self._verify_expire = timedelta(hours=settings.JWT_VERIFY_EMAIL_EXPIRE_HOURS)
        self._reset_expire = timedelta(hours=settings.JWT_RESET_PASSWORD_EXPIRE_HOURS)

    def generate_tokens(self, user_id: UserId) -> Tuple[Optional[AuthTokenEntity], Optional[str]]:
        """Genera access y refresh tokens con manejo de errores"""

        try:
            access_token, error = self._create_token(
                user_id,
                TokenType.ACCESS,
                self.access_expire
            )
            if error:
                return None, error
            
            refresh_token = self._create_token(
                user_id,
                TokenType.REFRESH,
                self.refresh_expire
            )
            if error:
                return None, error

            return AuthTokenEntity(
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="bearer",
                expires_in=self.access_expire.total_seconds()
            ), None
        
        except Exception as e:
            logger.error(f"Token generation failed: {str(e)}")
            return None, "Failed to generate tokens"
    
    def _create_token(self, user_id: UserId, token_type: TokenType, expires_delta: timedelta) -> Tuple[Optional[str], Optional[str]]:
        """Crea un token JWT"""

        try:
            payload = {
                "sub": str(user_id),
                "type": token_type.value,
                "exp": datetime.now(timezone.utc) + expires_delta,
                "iat": datetime.now(timezone.ut),
                "iss": settings.JWT_ISSUER
            }
            token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
            return token, None
        
        except Exception as e:
            logger.error(f"Token creation failed: {str(e)}")
            return None, "Failed to create token"
        
    def verify_token(self, token: str, expected_type: Optional[TokenType] = None) -> Tuple[Optional[dict], Optional[str]]:
        """Verifica y decodifica un token JWT con validaciones adicionales"""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={
                    "verify_aud": False,
                    "verify_iss": True,
                    "require_sub": True,
                    "verify_exp": True,
                    "verify_iat": True
                },
                issuer=settings.JWT_ISSUER
            )

            if expected_type and payload.get("type") != expected_type.value:
                raise InvalidTokenError("Invalid token type")

            return payload, None
            
        except JWTError as e:
            logger.warning(f"Token verification failed: {str(e)}")
            return None, "Invalid token"
        except InvalidTokenError as e:
            logger.warning(f"Token validation failed: {str(e)}")
            return None, str(e)
        except Exception as e:
            logger.error(f"Unexpected token verification error: {str(e)}")
            return None, "Token verification error"

    def create_verification_token(self, user_id: UserId) -> Tuple[Optional[str], Optional[str]]:
        """Crea token para verificación de email con manejo de errores"""
        return self._create_token(
            user_id,
            TokenType.VERIFY_EMAIL,
            self._verify_expire
        )

    def create_password_reset_token(self, user_id: UserId) -> Tuple[Optional[str], Optional[str]]:
        """Crea token para reseteo de contraseña con manejo de errores"""
        return self._create_token(
            user_id,
            TokenType.RESET_PASSWORD,
            self._reset_expire
        )

    def get_user_id_from_token(self, token: str) -> Tuple[Optional[UserId], Optional[str]]:
        """Obtiene el ID de usuario de un token válido"""
        payload, error = self.verify_token(token)
        if error:
            return None, error
            
        try:
            return UserId(payload["sub"]), None
        except Exception as e:
            logger.error(f"Failed to extract user ID from token: {str(e)}")
            return None, "Invalid user ID in token"
        