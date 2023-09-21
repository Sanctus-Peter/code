from pydantic import BaseModel
from typing import Optional, Any


class TokData(BaseModel):
    id: Optional[Any] = None


class UserData(BaseModel):
    access_token: str
    email: str
    id: int
    isAdmin: bool


class UserResponseSchema(BaseModel):
    message: str
    statusCode: int
    data: UserData
