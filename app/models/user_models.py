from sqlalchemy import Column, Integer, String, Boolean, text, TIMESTAMP, DateTime, DECIMAL, Enum, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.database import Base
from app.models import Lunch


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"))
    first_name = Column(String(255))
    last_name = Column(String(255))
    profile_pic = Column(String(255))  # Assuming a URL
    email = Column(String(255), unique=True, nullable=False)
    phone = Column(String(20))
    password_hash = Column(String(255), nullable=False)
    is_admin = Column(Boolean)
    lunch_credit_balance = Column(Integer)
    refresh_token = Column(String(255))
    bank_number = Column(String(255))
    bank_code = Column(String(255))
    bank_name = Column(String(255))
    bank_region = Column(String(255))
    currency = Column(String(128))
    currency_code = Column(String(4))
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("NOW()"))
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, onupdate=text("NOW()"))
    is_deleted = Column(Boolean, default=False)

    organization = relationship("Organization", back_populates="users")
    withdrawals = relationship("Withdrawal", back_populates="user")
    sender_lunches = relationship("Lunch", back_populates="sender", foreign_keys=[Lunch.sender_id])
    receiver_lunches = relationship("Lunch", back_populates="receiver", foreign_keys=[Lunch.receiver_id])


class Withdrawal(Base):
    __tablename__ = "withdrawals"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    status = Column(Enum("redeemed", "not_redeemed", name="withdrawal_status"), nullable=False)
    amount = Column(DECIMAL(10, 2), nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("NOW()"))
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, onupdate=text("NOW()"))
    is_deleted = Column(Boolean, default=False)

    user = relationship("User", back_populates="withdrawals")
