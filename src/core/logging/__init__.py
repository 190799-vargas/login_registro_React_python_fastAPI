# ===========================================
# Establece el formato de logs (texto/JSON)
# Configura niveles de logging por entorno
# Prepara loggers para Uvicorn y aplicación
# ===========================================

import logging
import sys
from logging.config import dictConfig
from typing import Optional
from fastapi import FastAPI
from .middleware import LoggingMiddleware
from src.config import settings

def configure_loggin(log_as_json: bool = False, log_level: str = "INFO"):
    """
    Configuración centralizada del sistema de logging

    Args:
        log_as_json: Si True, usa formato JSON para logs
        log_level: Nivel de logging (DEBUG, INFO, WARNING ERROR, CRITICAL)
    """
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters":{
            "standard": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S"
            },
            "json": {
                "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
                "fmt": "%(asctime)s %(name)s %(levelname)s %(message)s"
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "json" if settings.LOG_AS_JSON else "standard",
                
                "stream": sys.stdout
            },
            "file": {
                "class": "logging.handlers.RotatingFileHandler",
                "filename": "app.log",
                "maxBytes": 10485760,  # 10MB
                "backupCount": 5,
                "formatter": "standard"
            }
        },
        "loggers": {
            "": {  # root logger
                "handlers": ["console"],
                "level": settings.LOG_LEVEL,
                "propagate": True
            },
            "uvicorn.error": {
                "level": "INFO",
                "propagate": False
            },
            "uvicorn.access": {
                "level": "INFO",
                "propagate": False
            }
        }
    }

    dictConfig(logging_config)

def add_logging_middleware(app: FastAPI):
    """Añade middleware de logging a la aplicación FastAPI"""
    app.add_middleware(LoggingMiddleware)

__all__ = [
    'configure_logging',
    'add_logging_middleware'
]
