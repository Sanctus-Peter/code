from pydantic import BaseModel, EmailStr


class CreateUserSchema(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str
    phone_number: str


class UserResponseSchema(BaseModel):
    id: int
    email: str
    name: str
    access_token: str
    is_admin: bool
