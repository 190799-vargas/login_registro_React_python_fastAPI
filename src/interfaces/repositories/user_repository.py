# =======================================================================
# Operaciones CRUD básicas
# Métodos específicos para autenticación (OAuth, verificación de email)
# Funcionalidades avanzadas (paginación, conteo)
# Todos los métodos principales trabajan con UserEntity
# Métodos mejor estructurados:
#   * save() reemplaza a create_user() para operaciones de escritura unificadas
#   * search() devuelve entidades en lugar de DTOs
# Uso de value objects como Email e UserId
# Integra los enums UserRole y AuthProvider de core/domain/enums.py
# Separación clara entre operaciones de lectura y escritura
# Métodos específicos para gestión de roles
# Tipado más fuerte:
#   * UserId como value object en lugar de strings
#   * Mejor documentación de parámetros
# =======================================================================

from abc import ABC, abstractmethod
from typing import Optional, List
from datetime import datetime

from src.models.user import UserInDB, UserUpdate, UserResponse
from src.core.domain.enums import UserRole, AuthProvider
from src.core.domain.entities import UserEntity
from src.core.domain.value_objects import Email, UserId

class IUserRepository(ABC):
    """Interfaz abstracta para el reposotorio de usuarios con soporte para entidades"""

    # ---- Métodos de Lectura ----
    @abstractmethod
    async def get_by_id(self, user_id: UserId) -> Optional[UserEntity]:
        """Obtiene un usuario por ID"""
        pass

    @abstractmethod
    async def get_by_email(self, email: Email) -> Optional[UserEntity]:
        """Obtiene un usuario por email"""
        pass

    @abstractmethod
    async def get_by_provider_id(self, provider: AuthProvider, provider_id: str) -> Optional[UserEntity]:
        """Obtiene usuario por ID de proveedor Oauth"""
        pass

    # ---- Métodos de Escritura ----
    @abstractmethod
    async def save(self, user: UserEntity) -> UserEntity:
        """Guarda o actualiza una entidad User completa"""
        pass
    
    @abstractmethod
    async def update(self, user_id: UserId, update_data: UserUpdate) -> Optional[UserEntity]:
        """Actualiza parcialmente una entidad User"""
        pass

    @abstractmethod
    async def delete(self, user_id: UserId) -> bool:
        """Eliminación lógica de una entidad User"""
        pass

    # ---- Métodos Específicos ----
    @abstractmethod
    async def verify_email(self, user_id: UserId) -> bool:
        """Marca el email como verificado en la entidad"""
        pass

    @abstractmethod
    async def update_last_login(self, user_id: UserId) -> None:
        """Actualiza la última fecha de login"""
        pass

    # ---- Métodos de Consulta ----
    @abstractmethod
    async def search(
        self,
        query: Optional[str] = None,
        roles: Optional[List[UserRole]] = None,
        limit: int = 10,
        skip: int = 0
    ) -> List[UserEntity]:
        """Busca usuarios con paginación"""
        pass

    @abstractmethod
    async def count(self) -> int:
        """Devuelve el total de usuarios registrados"""
        pass

    # ---- Métodos de Compatibilidad (opcionales) ----
    @abstractmethod
    async def create_user(self, user: UserInDB) -> UserInDB:
        """Método legacy para compatibilidad (debería migrarse a save)"""
        pass

    @abstractmethod
    async def update_roles(self, user_id: UserId, roles: List[UserRole]) -> bool:
        """Método legacy para compatibilidad"""
        pass