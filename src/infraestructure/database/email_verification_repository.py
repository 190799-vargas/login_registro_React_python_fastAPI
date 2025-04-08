from typing import Optional, Type
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId
from datetime import datetime, timezone

from src.core.domain.entities import EmailVerificationEntity
from src.interfaces.repositories.email_verification_repository import IEmailVerificationRepository




class MongoEmailVerificationRepository(IEmailVerificationRepository):
    def __init__(self, db: AsyncIOMotorDatabase) -> None: #ignore
        self._collection = db["email_verifications"]  # 👈 CORRECTO: el nombre de la colección va entre comillas

    async def save_verification(self, entity: EmailVerificationEntity) -> bool:
        """Guarda una verificación de email en la colección"""
        doc = {
            "_id": entity.id,
            "user_id": str(entity.user_id),
            "token": entity.token,
            "expires_at": entity.expires_at,
            "created_at": entity.created_at,
            "used": False
        }
        result = await self._collection.insert_one(doc)
        return result.acknowledged

    async def verify_email(self, entity: EmailVerificationEntity) -> bool:
        """Marca como usada una verificación de email si el token es válido y no ha expirado"""
        result = await self._collection.update_one(
            {
                "token": entity.token,
                "user_id": str(entity.user_id),
                "expires_at": {"$gt": datetime.now(timezone.utc)},
                "used": False
            },
            {"$set": {"used": True}}
        )
        return result.modified_count == 1
    
    async def delete_token(self, token: str) -> bool:
        result = await self._collection.delete_one({"token": token})
        return result.deleted_count == 1

    async def get_by_token(self, token: str) -> Optional[EmailVerificationEntity]:
        """Busca un token de verificación de email"""
        doc = await self._collection.find_one({"token": token})
        if not doc:
            return None
    
    
        return EmailVerificationEntity(
            id=doc["_id"],
            user_id=doc["user_id"],
            token=doc["token"],
            expires_at=doc["expires_at"],
            created_at=doc["created_at"]
        )