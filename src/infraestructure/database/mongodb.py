# =======================================================================
# Manejo profesional de conexiones:
#   1. Configuración de pool de conexiones (maxPoolSize, minPoolSize)
#   2. Timeouts configurables
#   3. Verificación de conexión al iniciar
# Índices optimizados:
#   1. Índice único para emails
#   2. Índice para búsqueda por provider_id (OAuth)
#   3. Índice de texto para búsqueda full-text en nombres
# Patrón Singleton:
#   1. Una sola instancia de conexión para toda la aplicación
#   2. Acceso global mediante MongoDB.get_db()
# Manejo de errores:
#   1. Logging detallado
#   2. Validación de conexión al inicio
# Compatible con MONGODB_URI del .env
# ======================================================================

from motor.motor_asyncio import AsyncIOMotorClient
from typing import Optional, Type
import logging
from src.config import settings

MotorClientType = Type[AsyncIOMotorClient]

class MongoDB:
    """Clase singleton para manejar la conexión a MongoDB"""
    _client: Optional[MotorClientType] = None
    _database_name: Optional[str] = None

    @classmethod
    async def initialize(cls):
        """Inicializa la conexión a MongoDB"""
        try:
            cls._client = MotorClientType(
                settings.MONGODB_URI,
                maxPoolSize=100,
                minPoolSize=10,
                connectTimeoutMS=5000,
                socketTimeoutMS=30000,
                serverSelectionTimeoutMS=5000
                )
            # Extraer el nombre de la base de datos de la URI
            cls._database_name = settings.MONGODB_URI.split("/")[-1].split("?")[0]

            # verifica la conexión
            await cls._client.server_info()
            logging.info(" Conexión a MongoDB establecida correctamente")

            # Creat índices
            await cls._create_indexes()

        except Exception as e:
            logging.error(f" Error conectando a MongoDB: {str(e)}")
            raise
    
    @classmethod
    async def _create_indexes(cls):
        """Crea índices necesarios para optimizar consultas"""
        db = cls.get_db()
        await db.users.create_index("email", unique=True)
        await db.users.create_index("provider_id")
        await db.users.create_index([("full_name", "text")])
        logging.info("Índices de MongoDB creados correctamente")

    @classmethod
    def get_db(cls):
        """Obtiene la instancia de la base de datos"""
        if cls._client is None:
            raise RuntimeError("MongoDB no está inicializado. Llama a MongoDB.initialize() primero")
        return cls._client[cls._database_name]
    
    @classmethod
    async def close_connection(cls):
        """Cierra la conexión con MongoDB"""
        if cls._client:
            cls._client.close()
            cls._client = None
            logging.info("Conexión a MongoDB cerrada.")
    
    @classmethod
    async def ping(cls) -> bool:
        """Verifica que la conexión esté activa"""
        try:
            db = await cls.get_db()
            await db.command('ping')
            return True
        except Exception:
            return False

