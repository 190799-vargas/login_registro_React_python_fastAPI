# =========================================================================================================
# Complete Auth Endpoints:
#   Registration with email/password, Login with email/password (OAuth2 compatible)
#   OAuth provider login (Google, GitHub, etc.), Email verification,Password reset flow
#   Token refresh, Current user profile, Logout
# Security:
#   Proper HTTP status codes, Error handling for all scenarios
#   OAuth2 password flow integration, Token invalidation on logout
# Integration:
#   Uses your AuthService interface, Works with dependency injection, Supports both JSON and form-data
# Best Practices:
#   Clean route organization, Consistent response models, Proper request validation
#   RESTful design
# ========================================================================================================

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import EmailStr
from typing import Optional, Callable

from src.models.user import (
    UserCreate,
    UserLogin,
    UserOAuthCreate,
    UserPasswordReset,
    UserResponse
)
from src.services.auth_service import AuthService
from src.core.use_cases.auth_use_cases import (
    VerifyEmailWithTokenUseCase
)
from src.core.domain.entities import EmailVerificationEntity
from src.core.security.dependencies import get_current_user
from src.api.dependencies import (
    get_auth_service,
    get_verify_email_use_case
)
from src.core.domain.enums import AuthProvider
from src.core.domain.value_objects import Email
from src.core.domain.exceptions import (
    DomainException,
    InvalidCredentialsError,
    PermissionDeniedError,
    UserNotFoundError,
    InvalidTokenError,
    EmailAlreadyExistsError,
    EmailNotVerifiedError,
    EmailSendingError
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# 1. Define el tipo del manejador
ExceptionHandler = Callable[[Request, DomainException], JSONResponse]

# Manejo global de excepciones de dominio
async def handle_domain_exception(request: Request, exc: DomainException):
    return JSONResponse(
        status_code=exc.http_status,
        content={
            "error": exc.error_type.value,
            "message": exc.message,
            "code": exc.error_code,
            "details": exc.details
        }
    )

# Registro del manejador de excepciones
# 3. Registra el manejador directamente (sin asignación intermedia)
router.add_ecxeption_handler(DomainException, handle_domain_exception)  # type: ignore[arg-type]

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
        user_data: UserCreate,
        auth_service: AuthService = Depends(get_auth_service)
    ):
    """Registrar un nuevo usuario con email y contraseña"""
    try:
        user, _, _ = await auth_service.register(user_data)
        return user
    except EmailAlreadyExistsError as e:
        raise e # Será manejado por el exception_handler
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
@router.post("/login", response_model=UserResponse)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Authenticate user and return access token"""
    try:
        credentials = UserLogin(
            email=form_data.username,
            password=form_data.password
        )
        user, _, _ = await auth_service.login(credentials)
        return user
    except (InvalidCredentialsError, EmailNotVerifiedError) as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/login/{provider}", response_model=UserResponse)
async def oauth_login(
    provider: AuthProvider,
    oauth_data: UserOAuthCreate,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Authenticate using OAuth provider (Google, GitHub, etc.)"""
    try:
        user, _, _ = await auth_service.oauth_login(provider, oauth_data)
        return user
    except InvalidCredentialsError as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/verify-email")
async def verify_email(
    payload: EmailVerificationEntity,
    use_case: VerifyEmailWithTokenUseCase = Depends(get_verify_email_use_case)
    
):
    """Verify user email using verification token"""
    try:
        result = await use_case.execute(payload)
        if not result:
            raise InvalidTokenError("Invalid or expired verification token")
        return {"message": "Email successfully verified"}
    except InvalidTokenError as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/request-password-reset")
async def request_password_reset(
    email: EmailStr,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Request password reset link to be sent to email"""
    try:
        success = await auth_service.request_password_reset(Email(value=email))
        if not success:
            raise EmailSendingError("Failed to send password reset email")
        return {"message": "Password reset link sent if email exists"}
    except EmailSendingError as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/reset-password")
async def reset_password(
    reset_data: UserPasswordReset,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Reset user password using valid token"""
    try:
        success = await auth_service.reset_password(reset_data)
        if not success:
            raise InvalidTokenError("Invalid or expired reset token")
        return {"message": "Password successfully reset"}
    except InvalidTokenError as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/refresh-token")
async def refresh_token(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Refresh access token using refresh token"""
    try:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise InvalidTokenError("Refresh token missing")
        
        tokens = await auth_service.refresh_token(refresh_token)
        if not tokens:
            raise InvalidTokenError("Invalid refresh token")
        
        return {"access_token": tokens.access_token}
    except InvalidTokenError as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: UserResponse = Depends(get_current_user)
):
    """Get profile of currently authenticated user"""
    try:
        return current_user
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/logout")
async def logout():
    """Logout user by invalidating tokens (client-side)"""
    try:
        response = RedirectResponse(url="/")
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )