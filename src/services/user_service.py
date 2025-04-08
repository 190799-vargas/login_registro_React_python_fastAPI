import logging
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Union
from uuid import UUID

from src.core.domain.entities import UserEntity
from src.core.domain.value_objects import  UserId
from src.core.domain.enums import UserRole
from src.core.domain.exceptions import (
    PermissionDeniedError,
    UserNotFoundError,
    InvalidOperationError
)
from src.interfaces.repositories.user_repository import IUserRepository
from src.interfaces.services.user_service import IUserService
from src.core.security.password_utils import PasswordHasher
from src.core.security.jwt_manager import JWTManager
from src.models.token import TokenType
from src.models.user import (
    UserResponse,
    UserUpdate,
    UserPublicProfile,
    UserPasswordReset
)
from src.core.logging import logging

class UserService(IUserService):
    """Implementación concreta del servicio de gestion de usuario"""

    def __init__(
            self,
            user_repository: IUserRepository,
            password_hasher: PasswordHasher,
            jwt_manager: JWTManager
        ):
        self._repo = user_repository
        self._hasher = password_hasher
        self._jwt = jwt_manager
        self._logger = logging.getLogger(__name__)

    async def get_user_profile(
            self,
            user_id: UUID,
            requester_id: UUID
        ) -> Tuple[Optional[UserEntity], str]:
        """Obtiene el perfil público de un usuario con validación de permisos"""
        try:
            # Validación de UUIDs
            if not self._validate_uuids(user_id, requester_id):
                return None, "Invalid user identifiers"

            # Verificar permisos
            can_view, error = await self._verify_permission(
                target_user_id=user_id,
                requester_id=requester_id,
                allow_self=True
            )
            if not can_view:
                return None, error or "Permission denied"

            # Obtener usuario
            user = await self._repo.get_by_id(UserId(user_id))
            if not user:
                return None, "User not found"

            return UserPublicProfile(**user.dict()), ""
            
        except Exception as e:
            self._logger.error(f"Error getting user profile: {str(e)}", exc_info=True)
            return None, "Failed to get user profile"

    async def update_user_profile(
        self,
        user_id: UUID,
        requester_id: UUID,
        update_data: UserUpdate
    ) -> Tuple[Optional[UserPublicProfile], str]:
        """Obtiene el perfil público de un usuario con validación de permisos"""
        
        try:
            # Validación de UUIDs
            if not self._validate_uuids(user_id, requester_id):
                return None, "Invalid user identifiers"

            # Verificar permisos
            can_update, error = await self._verify_permission(
                target_user_id=user_id,
                requester_id=requester_id,
                allow_self=True
            )
            if not can_update:
                return None, error or "Permission denied"

            # Validar campos actualizables
            valid_fields = {'username', 'bio', 'avatar_url'}
            update_dict = {
                k: v for k, v in update_data.dict(exclude_unset=True).items()
                if k in valid_fields
            }
            
            if not update_dict:
                return None, "No valid fields to update"

            # Verificar unicidad de username si se está actualizando
            if 'username' in update_dict:
                if await self._repo.username_exists(update_dict['username'], exclude_user_id=user_id):
                    return None, "Username already taken"

            # Obtener y actualizar usuario
            user = await self._repo.get_by_id(UserId(user_id))
            if not user:
                return None, "User not found"

            for field, value in update_dict.items():
                setattr(user, field, value)

            updated_user = await self._repo.save(user)
            return UserResponse(**updated_user.dict()), ""
            
        except Exception as e:
            self._logger.error(f"Error updating user: {str(e)}", exc_info=True)
            return None, "Failed to update user"

    async def list_users(
        self,
        requester_id: UUID,
        search_query: Optional[str] = None,
        roles: Optional[List[UserRole]] = None,
        limit: int = 10,
        offset: int = 0
    ) -> Tuple[List[UserPublicProfile], int, str]:
        """Lista usuarios con paginación y validación de parámetros"""
        try:
            # Validar parámetros
            if not self._validate_uuids(requester_id):
                return [], 0, "Invalid user identifier"
                
            if limit > 100 or limit < 1:
                return [], 0, "Limit must be between 1 and 100"
            if offset < 0:
                return [], 0, "Offset cannot be negative"

            # Verificar permisos de admin
            is_admin, error = await self._verify_admin(requester_id)
            if not is_admin:
                return [], 0, error or "Admin access required"

            # Obtener lista paginada
            users, total = await self._repo.list(
                search=search_query,
                roles=roles,
                limit=limit,
                offset=offset
            )
            
            return [UserPublicProfile(**user.dict()) for user in users], total, ""
            
        except Exception as e:
            self._logger.error(f"Error listing users: {str(e)}", exc_info=True)
            return [], 0, "Failed to list users"

    async def update_user_roles(
        self,
        user_id: UUID,
        requester_id: UUID,
        new_roles: List[UserRole]
    ) -> Tuple[Optional[UserPublicProfile], str]:
        """Actualiza roles de usuario con validación mejorada"""
        try:
            # Validación de UUIDs
            if not self._validate_uuids(user_id, requester_id):
                return None, "Invalid user identifiers"

            # Verificar permisos de admin
            is_admin, error = await self._verify_admin(requester_id)
            if not is_admin:
                return None, error or "Admin access required"

            # Validar roles
            if not new_roles or not all(isinstance(role, UserRole) for role in new_roles):
                return None, "Invalid roles provided"

            # Obtener y actualizar usuario
            user = await self._repo.get_by_id(UserId(user_id))
            if not user:
                return None, "User not found"

            user.roles = new_roles
            updated_user = await self._repo.save(user)
            return UserPublicProfile(**updated_user.dict()), ""
            
        except Exception as e:
            self._logger.error(f"Error updating roles: {str(e)}", exc_info=True)
            return None, "Failed to update roles"

    async def change_user_status(
        self,
        user_id: UUID,
        requester_id: UUID,
        is_active: bool
    ) -> Tuple[bool, str]:
        """Activa/desactiva un usuario con validaciones de seguridad"""
        try:
            # Validación de UUIDs
            if not self._validate_uuids(user_id, requester_id):
                return False, "Invalid user identifiers"

            # No permitir auto-desactivación si es el último admin
            if not is_active and user_id == requester_id:
                is_last_admin = await self._is_last_active_admin(requester_id)
                if is_last_admin:
                    return False, "Cannot deactivate last active admin"

            # Verificar permisos
            required_roles = [UserRole.ADMIN] if is_active else None
            allow_self = not is_active  # Permitir auto-desactivación

            has_permission, error = await self._verify_permission(
                target_user_id=user_id,
                requester_id=requester_id,
                required_roles=required_roles,
                allow_self=allow_self
            )
            if not has_permission:
                return False, error or "Permission denied"

            # Cambiar estado
            success = await self._repo.update_status(UserId(user_id), is_active)
            if not success:
                return False, "User not found"

            return True, ""
            
        except Exception as e:
            self._logger.error(f"Error changing user status: {str(e)}", exc_info=True)
            return False, "Failed to change user status"

    async def reset_password(
        self,
        reset_data: UserPasswordReset
    ) -> Tuple[bool, str]:
        """Restablece la contraseña con validaciones mejoradas"""
        try:
            # Validar fortaleza de la nueva contraseña
            if len(reset_data.new_password) < 8:
                return False, "Password must be at least 8 characters"

            # Verificar token
            user_id = await self._validate_password_reset_token(reset_data.token)
            if not user_id:
                return False, "Invalid or expired token"

            # Hash de la nueva contraseña
            hashed_password, error = self._hasher.hash(reset_data.new_password)
            if error:
                return False, error

            # Actualizar contraseña
            success = await self._repo.update_password(user_id, hashed_password)
            if not success:
                return False, "User not found"
                
            return True, ""
            
        except Exception as e:
            self._logger.error(f"Error resetting password: {str(e)}", exc_info=True)
            return False, "Failed to reset password"

    # ======================
    # Métodos de seguridad
    # ======================

    async def _verify_permission(
        self,
        target_user_id: UUID,
        requester_id: UUID,
        required_roles: Optional[List[UserRole]] = None,
        allow_self: bool = False
    ) -> Tuple[bool, str]:
        """Verifica permisos del usuario con validaciones mejoradas"""
        try:
            # El usuario puede actuar sobre sí mismo si allow_self=True
            if allow_self and target_user_id == requester_id:
                return True, ""

            # Obtener información del solicitante
            requester = await self._repo.get_by_id(UserId(requester_id))
            if not requester:
                return False, "Requester not found"

            # Verificar roles requeridos
            if required_roles:
                has_role = any(role in requester.roles for role in required_roles)
                if not has_role:
                    return False, "Insufficient privileges"

            return True, ""
            
        except Exception as e:
            self._logger.error(f"Permission verification error: {str(e)}", exc_info=True)
            return False, "Permission verification failed"

    async def _verify_admin(
        self,
        requester_id: UUID
    ) -> Tuple[bool, str]:
        """Verifica si el usuario es administrador"""
        return await self._verify_permission(
            target_user_id=requester_id,
            requester_id=requester_id,
            required_roles=[UserRole.ADMIN]
        )

    async def _is_last_active_admin(
        self,
        user_id: UUID
    ) -> Tuple[bool, str]:
        """Verifica si el usuario es el último admin activo"""
        try:
            active_admins = await self._repo.count_active_admins()
            is_admin = await self._repo.has_role(UserId(user_id), UserRole.ADMIN)
            return active_admins <= 1 and is_admin, ""
        except Exception as e:
            self._logger.error(f"Last admin check failed: {str(e)}", exc_info=True)
            return False, "Failed to verify last admin status"

    async def _validate_password_reset_token(
        self,
        token: str
    ) -> Optional[UserId]:
        """Valida token de reseteo de contraseña de manera robusta"""
        try:
            payload, error = self._jwt.verify_token(token, TokenType.RESET_PASSWORD)
            if error or not payload:
                return None
                
            user_id = UserId(payload.get("sub"))
            if not user_id:
                return None
                
            # Verificar que el usuario existe
            user_exists = await self._repo.exists(user_id)
            return user_id if user_exists else None
            
        except Exception as e:
            self._logger.error(f"Token validation error: {str(e)}", exc_info=True)
            return None

    # ======================
    # Métodos auxiliares
    # ======================

    def _validate_uuids(self, *uuids: UUID) -> bool:
        """Valida que los UUIDs sean válidos"""
        try:
            return all(isinstance(u, UUID) and u.version is not None for u in uuids)
        except (ValueError, AttributeError):
            return False

    # ======================
    # Métodos legacy
    # ======================

    async def update_user(
        self,
        user_id: UUID,
        requester_id: UUID,
        update_data: UserUpdate
    ) -> UserResponse:
        """Método legacy para compatibilidad"""
        user, error = await self.update_user_profile(user_id, requester_id, update_data)
        if error:
            raise UserNotFoundError() if "not found" in error.lower() else PermissionDeniedError(error)
        return user

    async def deactivate_user(
        self,
        user_id: UUID,
        requester_id: UUID
    ) -> bool:
        """Método legacy para compatibilidad"""
        success, error = await self.change_user_status(user_id, requester_id, False)
        if error:
            raise UserNotFoundError() if "not found" in error.lower() else PermissionDeniedError(error)
        return success
            
