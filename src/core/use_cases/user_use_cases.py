# ===================================================================================================================================================================
# Gestión completa de usuarios:
#   * Obtención de perfiles, Actualización de información, dministración de roles, Listado paginado, Desactivación de cuentas
# Control de permisos:
#   * Validación de roles (ADMIN para operaciones sensibles), Protección contra auto-desactivación, Lógica de ownership (cada usuario solo puede editar su perfil)
# Validaciones:
#   * Datos requeridos, Formatos correctos, Existencia de usuarios
# Paginación y filtros:
#   * Búsqueda por texto, Filtrado por roles, Límite y offset para paginación
# ===================================================================================================================================================================

from typing import List, Optional, Tuple

from src.core.domain.entities import UserEntity
from src.core.domain.value_objects import UserId, Email
from src.core.domain.enums import UserRole
from src.interfaces.repositories.user_repository import IUserRepository
from src.core.domain.exceptions import (
    UserNotFoundError,
    PermissionDeniedError,
    InvalidUserDataError
)

class GetUserProfileUseCase:
    """Caso de uso para obtener perfil de usuario"""

    def __init__(self, user_repo: IUserRepository):
        self._user_repo = user_repo

    async def execute(self, user_id: UserId, requester_id: UserId) -> UserEntity:
        """
        Obtiene el perfil de un usuario

        Args:
            user_id: ID del usuario a consultar
            requester_id: ID del usuario que hace la solicitud
            
        Returns:
            UserEntity: Entidad del usuario
            
        Raises:
            UserNotFoundError: Si el usuario no existe
            PermissionDeniedError: Si no tiene permisos
        """
        # Verificar que el usuario existe
        user = await self._user_repo.get_by_id(user_id)
        if not user:
            raise UserNotFoundError()
        
        # Logica de permisos (ejemplo básico)
        if user_id != requester_id and UserRole.ADMIN not in user.roles:
            raise PermissionDeniedError()
        
        return user
    
class UpdateUserProfileUseCase:
    """Caso de uso para actualizar perfil de usuario"""

    def __init__(self, user_repo: IUserRepository):
        self._user_repo = user_repo

    async def execute(
            self,
            user_id: UserId,
            requester_id: UserId,
            full_name: Optional[str] = None,
            avatar_url: Optional[str] = None
        ) -> UserEntity:
        """
        Actualiza el perfil de un usuario
        
        Args:
            user_id: ID del usuario a actualizar
            requester_id: ID del usuario que hace la solicitud
            full_name: Nuevo nombre completo (opcional)
            avatar_url: Nueva URL de avatar (opcional)
            
        Returns:
            UserEntity: Entidad actualizada
            
        Raises:
            UserNotFoundError: Si el usuario no existe
            PermissionDeniedError: Si no tiene permisos
            InvalidUserDataError: Si los datos son inválidos
        """
        # Verificar permisos
        if user_id != requester_id:
            raise PermissionDeniedError()
        
        # Obtener usuario existente
        user = await self._user_repo.get_by_id(user_id)
        if not user:
            raise UserNotFoundError()
        
        # Aplicar cambios
        updates = {}
        if full_name is not None:
            if len(full_name) < 2 or len(full_name) > 100:
                raise InvalidUserDataError("Nombre inválido")
            updates["full_name"] = full_name

            if avatar_url is not None:
                # Aquí podrías añadir validaciones de URL
                updates["avatar_url"] = avatar_url

            # Guardar cambios
            updated_user = await self._user_repo.update(user_id, updates)
            return updated_user

class UpdateUserRolesUseCase:
    """Caso de uso para actualizar roles de usuario (solo admin)"""

    def __init__(self, user_repo: IUserRepository):
        self._user_repo = user_repo
    
    async def execute(
        self,
        user_id: UserId,
        requester_id: UserId,
        new_roles: List[UserRole]
        ) -> UserEntity:
        """
        Actualiza los roles de un usuario
        
        Args:
            user_id: ID del usuario a modificar
            requester_id: ID del administrador que hace la solicitud
            new_roles: Lista de nuevos roles
            
        Returns:
            UserEntity: Entidad actualizada
            
        Raises:
            UserNotFoundError: Si el usuario no existe
            PermissionDeniedError: Si no es administrador
            InvalidUserDataError: Si los roles son inválidos
        """
        # Verificar que el requester es admin
        requester = await self._user_repo.get_by_id(requester_id)
        if not requester or UserRole.ADMIN not in requester.roles:
            raise PermissionDeniedError()
        
        # Verificar que el usuario objetivo existe
        user = await self._user_repo.get_by_id(user_id)
        if not user:
            raise UserNotFoundError()
        
        # validar roles
        if not new_roles:
            raise InvalidUserDataError("Se requiere al menos un rol")
        
        # Actualizar roles
        updated_user = await self._user_repo.update(user_id, {"roles": new_roles})
        return updated_user
    
class ListUsersUseCase:
    """Caso de uso para listar usuarios con filtros"""

    def __init__(self, user_repo: IUserRepository):
        self._user_repo = user_repo

    async def execute(
        self,
        requester_id: UserId,
        search_query: Optional[str] = None,
        roles: Optional[List[UserRole]] = None,
        limit: int = 10,
        offset: int = 0
    ) -> Tuple[List[UserEntity], int]:
        """
        Lista usuarios con paginación y filtros
        
        Args:
            requester_id: ID del usuario que hace la solicitud
            search_query: Texto para búsqueda (opcional)
            roles: Roles para filtrar (opcional)
            limit: Límite de resultados
            offset: Desplazamiento
            
        Returns:
            Tuple[List[UserEntity], int]: (usuarios, total)
            
        Raises:
            PermissionDeniedError: Si no es administrador
        """
        # Verificar que el requester es admin
        requester = await self._user_repo.get_by_id(requester_id)
        if not requester or UserRole.ADMIN not in requester.roles:
            raise PermissionDeniedError()
        
        # Obtener usuarios paginados
        users = await self._user_repo.search(
            query=search_query,
            roles=roles,
            limit=limit,
            skip=offset
        )
        
        # Obtener conteo total
        total = await self._user_repo.count()
        
        return users, total

class DeactivateUserUseCase:
    """Caso de uso para desactivar usuarios"""
    
    def __init__(self, user_repo: IUserRepository):
        self._user_repo = user_repo

    async def execute(self, user_id: UserId, requester_id: UserId) -> bool:
        """
        Desactiva un usuario (soft delete)
        
        Args:
            user_id: ID del usuario a desactivar
            requester_id: ID del administrador
            
        Returns:
            bool: True si fue exitoso
            
        Raises:
            UserNotFoundError: Si el usuario no existe
            PermissionDeniedError: Si no es administrador
        """
        # Verificar que el requester es admin
        requester = await self._user_repo.get_by_id(requester_id)
        if not requester or UserRole.ADMIN not in requester.roles:
            raise PermissionDeniedError()
        
        # Verificar que el usuario existe
        user = await self._user_repo.get_by_id(user_id)
        if not user:
            raise UserNotFoundError()
        
        # No permitir desactivarse a sí mismo
        if user_id == requester_id:
            raise PermissionDeniedError("No puedes desactivarte a ti mismo")
        
        # Realizar desactivación
        return await self._user_repo.delete(user_id)