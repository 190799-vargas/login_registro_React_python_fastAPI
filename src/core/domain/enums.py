from enum import Enum

class UserRole(str, Enum):
    """Roles de usuario disponibles en el sistema"""
    USER = "user"
    ADMIN = "admin"
    MODERATOR = "moderator"
    EDITOR = "editor"  # Ejemplo adicional

class AuthProvider(str, Enum):
    """Proveedores de autenticación soportados"""
    LOCAL = "local"
    GOOGLE = "google"
    GITHUB = "github"
    FACEBOOK = "facebook"
    MICROSOFT = "microsoft"  # Ejemplo adicional
