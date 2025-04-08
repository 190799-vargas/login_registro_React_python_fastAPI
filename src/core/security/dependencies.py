from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError

from src.core.security.jwt_manager import JWTManager
from src.models.user import UserResponse
from src.interfaces.repositories.user_repository import IUserRepository
from src.api.dependencies import get_user_repository
from src.core.use_cases.user_use_cases import UpdateUserRolesUseCase

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

async def get_current_user(
        token: str = Depends(oauth2_scheme),
        jwt_manager: JWTManager = Depends(JWTManager),
        user_repo: IUserRepository = Depends(get_user_repository)
    ) -> UserResponse:

    """Dependencia para obtener usuario actual desde JWT"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt_manager.verify_token(token)
        if payload is None or payload.get("type") != "access":
            raise credentials_exception
        
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        
        user = await user_repo.get_by_id(user_id)
        if user is None:
            raise credentials_exception
        
        return UserResponse(**user.dict())
    except JWTError:
        raise credentials_exception
    
async def get_update_roles_uc(
        user_repo: IUserRepository = Depends(get_user_repository)
        
    ) -> 'UpdateUserRolesUseCase':
    """Dependencia para obtener el caso de uso de actualización de roles"""
    return UpdateUserRolesUseCase(user_repo)  # Asumiendo que UpdateUserRolesUseCase está definido en otro lugar
    