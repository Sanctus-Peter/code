from typing import List, Optional

from pydantic import BaseModel, EmailStr


class CreateUserSchema(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str
    phone_number: str


class UserResponseSchema(BaseModel):
    id: Optional[str]
    email: Optional[str]
    name: Optional[str]
    access_token: str
    is_admin: bool


class UserData(BaseModel):
    email: Optional[str]
    name: Optional[str]
    phone_number: Optional[str]
    bank_number: Optional[str]
    bank_code: Optional[str]
    bank_name: Optional[str]
    isAdmin: bool


class UserResponse(BaseModel):
    message: str
    statusCode: int
    data: UserData


class UserBankSchema(BaseModel):
    bank_number: str
    bank_code: str
    bank_name: str


class AllUserData(BaseModel):
    name: Optional[str]
    email: Optional[str]
    profile_picture: Optional[str]
    user_id: Optional[str]


class ResponseData(BaseModel):
    message: str
    statusCode: int
    data: List[AllUserData]
