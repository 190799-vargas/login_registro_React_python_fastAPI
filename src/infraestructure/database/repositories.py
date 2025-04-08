# =================================================================================================================
# Implementación completa de la interfaz IUserRepository
# Operaciones atómicas con MongoDB usando las mejores prácticas
# Conversión automática entre: ObjectId de MongoDB ↔ str en las respuestas, Modelos Pydantic ↔ Documentos MongoDB
# Manejo de fechas automático (created_at, updated_at, last_login)
# Búsqueda avanzada con: Filtrado por texto (email o nombre), Filtrado por roles, Paginación (limit/skip)
# =================================================================================================================

from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from bson import ObjectId
from pymongo import ReturnDocument
from pymongo.results import InsertOneResult, UpdateResult

from src.core.domain.enums import UserRole, AuthProvider
from src.core.domain.entities import UserEntity
from src.core.domain.value_objects import PersonalName, Password, Email, SecurityToken
from src.interfaces.repositories.user_repository import IUserRepository
from src.models.user import UserInDB, UserUpdate, UserResponse
from mongodb import MongoDB

class UserRepository(IUserRepository):
    """Implementación concreta de IUserRepository con integración de Entidades y Value Objects"""

    # ---- Métodos principales ----
    async def get_by_id(self, user_id: str) -> Optional[UserEntity]:
        db = await MongoDB.get_db()
        user_data = await db.users.find_one({"_id": ObjectId(user_id)})
        return self._to_entity(user_data) if user_data else None

    async def create_user(self, entity: UserEntity) -> UserEntity:
        db = await MongoDB.get_db()
        user_data = self._to_document(entity)

        result: InsertOneResult = await db.users.insert_one(user_data)
        created_user = await db.users.find_one({"_id": result.inserted_id})
        return self._to_entity(created_user)
    
    async def update_user(self, user_id: str, update_data: UserUpdate) -> Optional[UserEntity]:
        db = await MongoDB.get_db()
        updates = update_data.dict(exclude_unset=True)
        updates["updated_at"] = datetime.now()

        updated_user = await db.users.find_one_and_update(
            {"_id": ObjectId(user_id)},
            {"$set": updates},
            return_document=ReturnDocument.AFTER
        )
        return self._to_entity(updated_user) if updated_user else None
    
    # ---- Métodos de Búsqueda ----
    async def get_by_email(self, email: str) -> Optional[UserEntity]:
        db = await MongoDB.get_db()
        user_data = await db.users.find_one({"email.value": email.lower()})
        return self._to_entity(user_data) if user_data else None
    
    async def get_by_provider_id(self, provider: AuthProvider, provider_id: str) -> Optional[UserEntity]:
        db = await MongoDB.get_db()
        user_data = await db.users.find_one({
            "provider": provider.value,
            "provider_id": provider_id
        })
        return self._to_entity(user_data) if user_data else None
    
    # ---- Métodos de Gestión ----
    async def update_last_login(self, user_id: str) -> None:
        db = await MongoDB.get_db()
        await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"last_login": datetime.now(timezone.utc)}}
        )
    
    # ---- Helpers de Conversión ----
    def _to_document(self, entity: UserEntity) -> Dict[str, Any]:
        """Convierte UserEntity a documento MongoDB"""
        return {
            "_id": entity.id,
            "email": {
                "value": entity.email.value,
                "verified": entity.email.verified,
                "provider": entity.email.provider.value
            },
            "hashed_password": entity.hashed_password,
            "full_name": entity.full_name,
            "roles": [role.value for role in entity.roles],
            "provider": entity.provider.value,
            "provider_id": entity.provider_id,
            "disabled": entity.disabled,
            "created_at": entity.created_at,
            "updated_at": entity.updated_at,
            "last_login": entity.last_login,
            "avatar_url": entity.avatar_url
        }

    def _to_entity(self, document: Dict[str, Any]) -> UserEntity:
        """Convierte documento MongoDB a UserEntity"""
        return UserEntity(
            id=document["_id"],
            email=Email(
                value=document["email"]["value"],
                verified=document["email"]["verified"],
                provider=AuthProvider(document["email"]["provider"])
            ),
            hashed_password=document["hashed_password"],
            full_name=document["full_name"],
            roles=[UserRole(role) for role in document["roles"]],
            provider=AuthProvider(document["provider"]),
            provider_id=document.get("provider_id"),
            disabled=document.get("disabled", False),
            created_at=document["created_at"],
            updated_at=document["updated_at"],
            last_login=document.get("last_login"),
            avatar_url=document.get("avatar_url")
        )
    # ---- Métodos Adicionales ----
    async def delete_user(self, user_id: str) -> bool:
        db = await MongoDB.get_db()
        result : UpdateResult = await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"disabled": True, "updated_at": datetime.now(timezone.utc)}}
        )
        return result.modified_count > 0
    
    async def search_users(
        self,
        query: Optional[str] = None,
        roles: Optional[List[UserRole]] = None,
        limit: int = 10,
        skip: int = 0
        ) -> List[UserResponse]:
            db = await MongoDB.get_db()
            filter_query = {}

            if query:
                filter_query["$or"] = [
                    {"email": {"$regex": query, "$options": "i"}},
                    {"full_name": {"$regex": query, "$options": "i"}}
                ]
            
            if roles:
                filter_query["roles"] = {"$in": [role.value for role in roles]}
            
            users = await db.users.find(filter_query).skip(skip).limit(limit).to_list(None)
            return [UserResponse(**user) for user in users]
    
    async def count_users(self) -> int:
        db = await MongoDB.get_db()
        return await db.users.count_documents({})