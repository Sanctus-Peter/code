import uuid

from pydantic import BaseModel


class UserCreate(BaseModel):
    name: str


class User(BaseModel):
    id: uuid.UUID
    name: str

    class Config:
        from_attributes = True
