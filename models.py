import uuid
from db import Base
from sqlalchemy import Column, String
from sqlalchemy.dialects.postgresql import UUID


class User(Base):
    __tablename__ = 'users'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    name = Column(String(100), nullable=False)
