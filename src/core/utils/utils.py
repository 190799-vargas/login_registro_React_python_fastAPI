# src/core/utils.py
import random
import string
from typing import Optional

async def generate_random_string(
    length: int = 32,
    use_digits: bool = True,
    use_special_chars: bool = False,
    prefix: Optional[str] = None
    ) -> str:
        """
        Genera una cadena aleatoria segura para usos criptográficos.
        """
        chars = string.ascii_letters
        if use_digits:
            chars += string.digits
        if use_special_chars:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        random_str = ''.join(random.SystemRandom().choice(chars) for _ in range(length))
        
        if prefix:
            return f"{prefix}{random_str}"
        return random_str

async def async_generate_random_string(length: int = 32) -> str:
    """
    Versión asíncrona para generar strings aleatorios.
    """
    return generate_random_string(length)