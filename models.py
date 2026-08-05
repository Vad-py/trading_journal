from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, BigInteger
from sqlalchemy.orm import relationship
from database import Base
import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    avatar_url = Column(String, nullable=True)

    api_keys = relationship("ApiKey", back_populates="owner", cascade="all, delete-orphan")
    trades = relationship("Trade", back_populates="owner", cascade="all, delete-orphan")

class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    platform = Column(String, nullable=False)
    api_key = Column(String, nullable=False)
    api_secret = Column(String, nullable=False)

    owner = relationship("User", back_populates="api_keys")

class Trade(Base):
    __tablename__ = "trades"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    
    # Уникальный ID сделки от Bybit (closed-pnl orderId)
    order_id = Column(String, nullable=False, index=True)
    
    platform = Column(String, nullable=False)
    symbol = Column(String, nullable=False)
    side = Column(String, nullable=False)  # Buy / Sell
    
    entry_price = Column(Float, nullable=False)
    exit_price = Column(Float, nullable=False)
    qty = Column(Float, nullable=False)
    
    pnl = Column(Float, nullable=False)
    pnl_percent = Column(Float, nullable=False)
    
    # Комиссии
    open_fee = Column(Float, default=0.0)
    close_fee = Column(Float, default=0.0)
    commission = Column(Float, default=0.0)
    
    # Время входа и выхода (timestamp в секундах для графика)
    entry_time = Column(BigInteger, nullable=True)
    exit_time = Column(BigInteger, nullable=True)
    
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    owner = relationship("User", back_populates="trades")