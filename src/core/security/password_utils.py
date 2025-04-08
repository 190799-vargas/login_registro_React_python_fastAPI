# ==================================================================================
# Patrón consistente:
#   * sigue el mismo patrón de retorno Tuple[resultado, error] que tu AuthService
#   * Es una clase inyectable como dependencia (mejor para testing)
# Seguridad mejorada:
#   * Validación de entradas vacías
#   * Manejo adecuado de errores
#   * Logging detallado
# Funcionalidad adicional:
#   * Método needs_update() para detectar hashes obsoletos
#   * Compatibilidad con la configuración de rounds desde settings
# Mantenimiento de compatibilidad:
#   * Conserva las funciones originales verify_password y hash_password
#   * No rompe el código existente que las use
# Tipado mejorado:
#   * Type hints completos en todos los métodos
#   * Mejor documentación de los parámetros y retornos
# ===================================================================================

from passlib.context import CryptContext
from src.config import settings
import logging
from typing import Optional, Tuple

class PasswordHasher:
    """Servicio para el hashing y verificación de contraseñas"""

    def __init__(self):
        self._context = CryptContext(
            schemes=["bcrypt"],
            deprecated="auto",
            bcrypt_rounds=settings.PASSWORD_HASH_ROUNDS
        )
        self._logger = logging.getLogger(__name__)

        
    def  verify(self, plain_password: str, hashed_password: str) -> Tuple[bool, Optional[str]]:
        """
        Verifica si una contraseña coincide con su hash
        Args:
            plain_password: Contraseña en texto plano
            hashed_password: Hash almacenado
        Returns:
            Tuple[bool, Optional[str]]: (Resultado de verificación, mensaje de error)
        """
        try:
            if not plain_password or not hashed_password:
                self._logger.warning("Empty password or hash provided for verification")
                return False, "Empty credentials"
                
            return self._context.verify(plain_password, hashed_password), None
            
        except Exception as e:
            self._logger.error(f"Password verification failed: {str(e)}")
            return False, "Password verification failed"
        
    def hash(self, password: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Genera hash seguro de una contraseña
        Args:
            password: Contraseña en texto plano
        Returns:
            Tuple[Optional[str], Optional[str]]: (Hash generado, mensaje de error)
        """
        try:
            if not password:
                self._logger.error("Attempted to hash empty password")
                return None, "Password cannot be empty"
                
            return self._context.hash(password), None
            
        except Exception as e:
            self._logger.error(f"Password hashing failed: {str(e)}")
            return None, "Password hashing failed"

    def needs_update(self, hashed_password: str) -> Tuple[bool, Optional[str]]:
        """
        Verifica si un hash necesita actualización
        Args:
            hashed_password: Hash a verificar
        Returns:
            Tuple[bool, Optional[str]]: (Si necesita actualización, mensaje de error)
        """
        try:
            if not hashed_password:
                return False, "Empty hash provided"
                
            return self._context.needs_update(hashed_password), None
            
        except Exception as e:
            self._logger.error(f"Hash update check failed: {str(e)}")
            return False, "Hash update check failed"

# Mantenemos las funciones legacy para compatibilidad
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Función legacy para compatibilidad"""
    hasher = PasswordHasher()
    result, _ = hasher.verify(plain_password, hashed_password)
    return result

def hash_password(password: str) -> str:
    """Función legacy para compatibilidad"""
    hasher = PasswordHasher()
    result, _ = hasher.hash(password)
    return result or ""  # type: ignore