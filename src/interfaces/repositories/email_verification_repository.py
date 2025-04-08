from abc import ABC, abstractmethod
from typing import Optional
from src.core.domain.value_objects import UserId

class IEmailVerificationRepository(ABC):
    """Interfaz abstracta para el repositorio de verificación de correo electrónico"""

    @abstractmethod
    async def save_token(self, user_id: UserId, token: str) -> None:
        pass

    @abstractmethod
    async def get_token(self, user_id: UserId) -> Optional[str]:
        pass

    @abstractmethod
    async def delete_token(self, user_id: UserId) -> None:
        pass