from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.user_models import User
from app.settings.oauth2 import (
    oauth2_scheme, verify_tok, credentials_exception
)


def get_admin_user(
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    """
    Dependency function to get the admin user from the access token.

    Parameters:
        - token (str): Access token obtained from the request header.
        - db (Session): Database session dependency.

    Returns:
        models.Admins: Admin user retrieved from the database.

    Raises:
        HTTPException: If the access token is invalid, user is not found, or user is not authorized.
    """

    token = verify_tok(token, credentials_exception)
    user = db.query(User).filter(User.id == token.id).first()
    if not user and not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You are not authorized to execute this action"
        )
    return user


def get_user(
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    """
        Dependency function to get the user from the access token.

        Parameters:
            - token (str): Access token obtained from the request header.
            - db (Session): Database session dependency.

        Returns:
            models.User: Admin user retrieved from the database.

        Raises:
            HTTPException: If the access token is invalid, user is not found, or user is not authorized.
        """
    token = verify_tok(token, credentials_exception)
    user = db.query(User).filter(User.id == token.id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You are not authorized to execute this action"
        )
    return user


def get_user_by_email(db:Session, email:str):

  pass


def validate_email():
  
    pass

def validate_passowrd():
  
    pass