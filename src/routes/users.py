# =================================================================================================
# Endpoints Completos:
#   Gestión de perfiles (lectura/actualización),Listado paginado de usuarios
#   Administración de roles, Desactivación de cuentas, Reset de contraseña
# Control de Accesos:
#   Protección por roles (admin/user), Validación de ownership, Manejo de errores específicos
# Paginación y Filtros:
#   Búsqueda por texto, Filtrado por roles, Parámetros limit/offset
# Seguridad:
#   Validación de datos de entrada, Protección contra auto-desactivación, Tokens JWT requeridos
# ================================================================================================

from fastapi import APIRouter, Depends, status, Query, Request
from fastapi.responses import JSONResponse
from typing import List, Optional
from pydantic import UUID4
from src.models.user import (
    UserResponse,
    UserUpdate,
    UserPublicProfile,
    UserPasswordReset
)
from src.core.domain.enums import UserRole
from src.api.dependencies import get_current_user, get_user_service
from src.interfaces.services.user_service import IUserService
from src.core.domain.exceptions import (
    DomainException,
    PermissionDeniedError,
    UserNotFoundError,
    InvalidTokenError,
    InvalidOperationError
)

router = APIRouter(prefix="/users", tags=["Users"])

# Manejador global de excepciones de dominio
async def handle_domain_exception(request: Request, exc: DomainException):
    return JSONResponse(
        status_code=exc.http_status,
        content={
            "error": exc.error_type.value,
            "message": exc.message,
            "code": exc.error_code,
            "details": exc.details
        }
    )

# Registrar el manejador para todas las excepciones de dominio
router.add_exception_handler(DomainException, handle_domain_exception)

@router.get("/me", response_model=UserResponse)
async def get_my_profile(
    current_user: UserResponse = Depends(get_current_user)
):
    """Obtiene el perfil del usuario autenticado"""
    return current_user

@router.put("/me", response_model=UserResponse)
async def update_my_profile(
    update_data: UserUpdate,
    current_user: UserResponse = Depends(get_current_user),
    user_service: IUserService = Depends(get_user_service)
):
    """Actualiza el perfil del usuario autenticado"""
    try:
        updated_user = await user_service.update_user(
            user_id=current_user.id,
            requester_id=current_user.id,
            update_data=update_data
        )
        return updated_user
    except Exception as e:
        raise e  # Las excepciones de dominio serán manejadas por el handler

@router.get("/{user_id}", response_model=UserPublicProfile)
async def get_user_profile(
    user_id: UUID4,
    current_user: UserResponse = Depends(get_current_user),
    user_service: IUserService = Depends(get_user_service)
):
    """Obtiene el perfil público de un usuario"""
    try:
        user = await user_service.get_user_profile(
            user_id=user_id,
            requester_id=current_user.id
        )
        return user
    except Exception as e:
        raise e

@router.get("/", response_model=List[UserPublicProfile])
async def list_users(
    current_user: UserResponse = Depends(get_current_user),
    user_service: IUserService = Depends(get_user_service),
    search: Optional[str] = Query(None, min_length=2, max_length=50),
    roles: Optional[List[UserRole]] = Query(None),
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0)
):
    """Lista usuarios con paginación y filtros (solo admin)"""
    try:
        users, total = await user_service.list_users(
            requester_id=current_user.id,
            search_query=search,
            roles=roles,
            limit=limit,
            offset=offset
        )
        return users
    except Exception as e:
        raise e

@router.put("/{user_id}/roles", response_model=UserPublicProfile)
async def update_user_roles(
    user_id: UUID4,
    roles: List[UserRole],
    current_user: UserResponse = Depends(get_current_user),
    user_service: IUserService = Depends(get_user_service)
):
    """Actualiza roles de usuario (solo admin)"""
    try:
        updated_user = await user_service.update_user_roles(
            user_id=user_id,
            requester_id=current_user.id,
            new_roles=roles
        )
        return updated_user
    except Exception as e:
        raise e

@router.post("/{user_id}/deactivate", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_user(
    user_id: UUID4,
    current_user: UserResponse = Depends(get_current_user),
    user_service: IUserService = Depends(get_user_service)
):
    """Desactiva un usuario (solo admin)"""
    try:
        success = await user_service.deactivate_user(
            user_id=user_id,
            requester_id=current_user.id
        )
        if not success:
            raise InvalidOperationError("Deactivation failed")
    except Exception as e:
        raise e

@router.post("/reset-password", response_model=bool)
async def reset_password(
    reset_data: UserPasswordReset,
    user_service: IUserService = Depends(get_user_service)
):
    """Restablece la contraseña usando token válido"""
    try:
        success = await user_service.reset_password(reset_data)
        if not success:
            raise InvalidTokenError("Invalid or expired token")
        return success
    except Exception as e:
        raise e