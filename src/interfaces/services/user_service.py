# ==============================================================================
# # Cobertura completa de operaciones de usuario:
#   1. Gestión de perfiles (obtener, actualizar)
#   2. Gestión de roles (solo admin)
#   3. Operaciones bulk (listar usuarios)
#   4. Activación/desactivación de cuentas
#   5. Reset de contraseña
# Type hints detallados:
#   1. Retornos con Tuple para manejar tanto éxito como errores
#   2. Uso de modelos Pydantic (UserUpdate, UserPublicProfile, etc.)
#   3. Enums para roles de usuario
# Seguridad integrada:
#   1. Verificación de permisos
#   2. Validación de ownership
#   3. Protección de datos sensibles
# Independencia de implementación:
#   1. Compatible con diferentes backends (MongoDB, PostgreSQL, etc.)
# ==============================================================================

from abc import ABC, abstractmethod
from typing import List, Optional, Tuple, Union
from uuid import UUID
from pydantic import UUID4

from src.models.user import (
    UserResponse,
    UserUpdate,
    UserPublicProfile,
    UserPasswordReset
)
from src.core.domain.enums import UserRole

class IUserService(ABC):
    """Interfaz abstracta para el servicio de gestión de usuarios"""
    
    @abstractmethod
    async def get_user_profile(
            self,
            user_id: UUID4,
            requester_id: UUID4
        ) -> Tuple[Optional[UserPublicProfile], str]:
        """
        Obtiene el perfil público de un usuario
        Args:
            user_id: ID del usuario a consultar
            requester_id: ID del usuario que realiza la solicitud
        Returns:
            Tuple[Optional[UserPublicProfile], str]: (Perfil de usuario, mensaje de error)
        """
        pass
    @abstractmethod
    async def update_user_profile(
            self,
            user_id: UUID4,
            requester_id: UUID4,
            update_data: UserUpdate
        ) -> Tuple[Optional[UserResponse], str]:
        """
        Actualiza el perfil de un usuario
        Args:
            user_id: ID del usuario a actualizar
            requester_id: ID del solicitante
            update_data: Datos de actualización
        Returns:
            Tuple[Optional[UserResponse], str]: (Usuario actualizado, mensaje de error)
        """
        pass

    @abstractmethod
    async def list_users(
            self,
            requester_id: UUID4,
            search_query: Optional[str] = None,
            roles: Optional[List[UserRole]] = None,
            limit: int = 10,
            offset: int = 0
        ) -> Tuple[List[UserPublicProfile], int, str]:
        """
        Lista usuarios con paginación y filtros
        Args:
            requester_id: ID del usuario que realiza la solicitud
            search_query: Texto para búsqueda
            roles: Roles para filtrar
            limit: Límite de resultados
            offset: Desplazamiento
        Returns:
            Tuple[List[UserPublicProfile], int, str]: (Usuarios, total, mensaje error)
        """
        pass
        
    @abstractmethod
    async def update_user_roles(
            self,
            user_id: UUID4,
            requester_id: UUID4,
            new_roles: List[UserRole]
        ) -> Tuple[Optional[UserPublicProfile], str]:
        """
        Actualiza roles de usuario (solo admin)
        Args:
            user_id: ID del usuario a actualizar
            requester_id: ID del solicitante
            new_roles: Nuevos roles a asignar
        Returns:
            Tuple[Optional[UserPublicProfile], str]: (Usuario actualizado, mensaje error)
        """
        pass

    @abstractmethod
    async def change_user_status(
            self,
            user_id: UUID4,
            requester_id: UUID4,
            is_active: bool
        ) -> Tuple[bool, str]:
        """
        Activa/desactiva un usuario
        Args:
            user_id: ID del usuario
            requester_id: ID del solicitante
            is_active: Nuevo estado
        Returns:
            Tuple[bool, str]: (Resultado operación, mensaje error)
        """
        pass

    @abstractmethod
    async def reset_password(
            self,
            reset_data: UserPasswordReset
        ) -> Tuple[bool, str]:
        """
        Restablece la contraseña usando token válido
        Args:
            reset_data: Datos para resetear contraseña
        Returns:
            Tuple[bool, str]: (Resultado operación, mensaje error)
        """
        pass

    @abstractmethod
    async def verify_user_permission(
            self,
            user_id: UUID4,
            requester_id: UUID4,
            required_role: Optional[List[UserRole]] = None,
            allow_self: bool = False
        ) -> Tuple[bool, str]:
        """
        Verifica permisos del usuario
        Args:
            user_id: ID del usuario objetivo
            requester_id: ID del solicitante
            required_roles: Roles requeridos
            allow_self: Permite operación sobre sí mismo
        Returns:
            Tuple[bool, str]: (Tiene permisos, mensaje error)
        """
        pass
        
