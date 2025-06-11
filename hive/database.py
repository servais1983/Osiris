from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, JSON, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os

# Configuration de la base de données
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/osiris")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Modèles de données
class Case(Base):
    __tablename__ = "cases"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="active")
    tags = Column(JSON, default=list)
    queries = relationship("Query", back_populates="case")

class Query(Base):
    __tablename__ = "queries"

    id = Column(String, primary_key=True)
    case_id = Column(String, ForeignKey("cases.id"))
    query_string = Column(String, nullable=False)
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    results = Column(JSON)
    case = relationship("Case", back_populates="queries")

class Agent(Base):
    __tablename__ = "agents"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    platform = Column(String, nullable=False)
    version = Column(String, nullable=False)
    status = Column(String, default="offline")
    last_seen = Column(DateTime, default=datetime.utcnow)
    capabilities = Column(JSON, default=list)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True)
    case_id = Column(String, ForeignKey("cases.id"))
    severity = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="new")
    alert_data = Column(JSON)

class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id = Column(String, primary_key=True)
    case_id = Column(String, ForeignKey("cases.id"))
    timestamp = Column(DateTime, nullable=False)
    event_type = Column(String, nullable=False)
    source = Column(String, nullable=False)
    data = Column(JSON)
    tags = Column(JSON, default=list)

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# Création des tables
def init_db():
    Base.metadata.create_all(bind=engine)

# Fonction pour obtenir une session de base de données
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Initialisation de la base de données
init_db() 