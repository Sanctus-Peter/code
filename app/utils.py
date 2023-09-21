"""
Module Name: AuthenticationUtils

This module provides utility functions for authentication and file validation in a FastAPI application.

Functions:
    - hashed(password: str) -> str: Hashes the provided password using bcrypt encryption.
    - verify(attempted_password, usr_password) -> bool: Verifies if a password matches a hashed user password.

Dependencies:
    - passlib.context.CryptContext: Password hashing and verification utility.
"""


from passlib.context import CryptContext


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hashed(password: str):
    """Hashes the provided password using the configured encryption algorithm.

    Args:
        password (str): The password to be hashed.

    Returns:
        str: The hashed password.
    """
    return pwd_context.hash(password)


def verify(attempted_password, usr_password):
    """Verifies if the attempted password matches the provided user password.

    Args:
        attempted_password: The password to be verified.
        usr_password: The user's stored hashed password.

    Returns:
        bool: True if the password is verified, False otherwise.
    """
    return pwd_context.verify(attempted_password, usr_password)
