from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from src.services.user_service import IUserService
from src.core.use_cases.auth_use_cases import VerifyEmailWithTokenUseCase
from src.infraestructure.database.email_verification_repository import MongoEmailVerificationRepository
from src.infraestructure.database.repositories import UserRepository
from src.services.auth_service import AuthService  # Import AuthService
from src.models.user import UserResponse  # Import UserResponse
from src.core.security.jwt_manager import JWTManager
from src.config import settings
from src.infraestructure.database.mongodb import MongoDB

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def get_user_service():
    repo = UserRepository()
    return IUserService(repo)

def get_user_repository():
    repo = UserRepository()
    return IUserService(repo)

def get_auth_service():
    user_repo = UserRepository()
    jwt_manager = JWTManager(secret_key=settings.JWT_SECRET_KEY)
    return AuthService(user_repo, jwt_manager)

def get_current_user(
        token: str = Depends(oauth2_scheme),
        auth_service: AuthService = Depends(get_auth_service)) -> UserResponse:
    """Obtiene el usuario actual desde el token JWT"""
    user = auth_service.get_authenticated_user(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

async def get_verify_email_use_case() -> VerifyEmailWithTokenUseCase:
    db = await MongoDB.get_db()
    repo = MongoEmailVerificationRepository(db)
    return VerifyEmailWithTokenUseCase(repo)