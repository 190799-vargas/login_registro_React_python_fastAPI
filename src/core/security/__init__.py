# =======================================================
# Configura el esquema OAuth2 para toda la aplicación
# Hace disponibles las dependencias de autenticación
# Permite la inyección de JWTManager en cualquier ruta
# =======================================================

from fastapi import FastAPI
from .jwt_manager import JWTManager
from .dependencies import oauth2_scheme
from .password_utils import verify_password, hash_password

def setup_jwt(app: FastAPI):
    """Configura los esquemas de autenticacion JWT en la aplicación FastAPI"""
    # Esto hace que oauth2_scheme esté disponible para toda la app
    app.dependency_overrides.update({
        get_jwt_manager: lambda: JWTManager(),
        get_oauth2_scheme: lambda: oauth2_scheme
    })

# Funciones para inyección de dependencias
def get_jwt_manager() -> JWTManager:
    return JWTManager()

def get_oauth2_scheme():
    return oauth2_scheme

__all__ = [
    'setup_jwt',
    'JWTManager',
    'oauth2_scheme',
    'verify_password',
    'hash_password',
    'get_jwt_manager',
    'get_oauth2_scheme'
]
