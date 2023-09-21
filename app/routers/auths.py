"""
Module Description

This module defines the authentication endpoints for user login. It provides functionality for
verifying user credentials and generating access tokens.

Dependencies:
- fastapi: FastAPI framework for building APIs
- Response: FastAPI Response class for handling HTTP responses
- HTTPException: FastAPI HTTPException class for raising exceptions with status codes
- status: HTTP status codes module for specifying response status codes
- Depends: FastAPI Dependency class for handling dependencies
- models: Module containing ORM models for database tables
- schemas: Module containing data models (schemas) for API request/response bodies
- utils: Module containing utility functions
- oauth2: Module for handling OAuth2 authentication

Exposed Endpoints:
- POST /auth/token/sign-in: User login and access token generation

Tags:
- Authentications: Tag for the authentication-related endpoints

Prefix:
- /auth: Prefix for all authentication-related endpoints
"""

from fastapi import APIRouter, Response, HTTPException, status, Depends
from sqlalchemy.orm import Session
from fastapi.security.oauth2 import OAuth2PasswordRequestForm

from app import utils
from app.db.database import get_db
from app.models import User
from app.schemas.auth import UserResponseSchema
from app.schemas.user_schemas import CreateUserSchema
from app.settings import oauth2

router = APIRouter(tags=["Authentications"], prefix="/api/auth")


@router.post('/login', response_model=UserResponseSchema)
async def user_login(
        res: Response,
        user_credentials: OAuth2PasswordRequestForm = Depends(),
        db: Session = Depends(get_db)
):
    """
        User Login

        Authenticates the user based on the provided credentials and generates an access token.

        Parameters:
        - res (Response): FastAPI Response object for setting cookies and returning the response.
        - usr_credentials (OAuth2PasswordRequestForm): Form containing user credentials (username and password).
        - db (Session): SQLAlchemy Session object for database operations.

        Returns:
        - dict: Dictionary containing user information and access token.

        Raises:
        - HTTPException(403): If the login credentials are invalid.
    """
    user = db.query(User).filter(User.email == user_credentials.username).first()
    if not user or not utils.verify(user_credentials.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Invalid login credentials')
    access_tok = oauth2.create_access_token(data={'user_id': user.id})
    res.set_cookie(key="token", value=access_tok)
    return {
        'message': 'User authenticated successfully',
        'statusCode': 200,
        'data': {
            'access_token': access_tok,
            'email': user.email,
            'id': user.id,
            'isAdmin': user.is_admin
        }
    }


@router.post('/user/signup', status_code=status.HTTP_201_CREATED)
async def user_signup(
        user: CreateUserSchema,
        db: Session = Depends(get_db)
):
    """
        User Signup

        Registers a new user in the database.

        Parameters:
        - user (CreateUserSchema): Schema containing user information.
        - db (Session): SQLAlchemy Session object for database operations.

        Returns:
        - dict: Dictionary containing user information and access token.

        Raises:
        - HTTPException(409): If the user already exists.
    """
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='User already exists')
    new_user = User(
        email=user.email,
        password_hash=utils.hashed(user.password),
        first_name=user.first_name,
        last_name=user.last_name,
        phone=user.phone_number,
        is_admin=False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    access_tok = oauth2.create_access_token(data={'user_id': new_user.id})
    return {
        'message': 'User registered successfully',
        'statusCode': 201,
        'data': {
            'access_token': access_tok,
            'email': new_user.email,
            'id': new_user.id,
            'isAdmin': new_user.is_admin
        }
    }
