import os
import logging
import threading
from contextlib import contextmanager
from typing import Generator, Dict, Any

from dotenv import load_dotenv
from sqlalchemy import create_engine, event, text  # ✅ `text` added here
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session, Session as SessionType
from sqlalchemy.pool import QueuePool
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.engine.url import make_url

# Load environment variables from .env
load_dotenv()

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# Database configuration
class DatabaseConfig:
    URL: str = os.getenv("DATABASE_URL", "")
    POOL_SIZE: int = int(os.getenv("DB_POOL_SIZE", "20"))
    MAX_OVERFLOW: int = int(os.getenv("DB_MAX_OVERFLOW", "10"))
    POOL_RECYCLE: int = int(os.getenv("DB_POOL_RECYCLE", "3600"))
    POOL_TIMEOUT: int = int(os.getenv("DB_POOL_TIMEOUT", "30"))
    ECHO: bool = os.getenv("DB_ECHO", "false").lower() == "true"
    ISOLATION_LEVEL: str = os.getenv("DB_ISOLATION_LEVEL", "READ COMMITTED")
    DIALECT: str = ""

    @classmethod
    def validate(cls):
        if not cls.URL:
            raise ValueError("DATABASE_URL must be set in environment")
        try:
            parsed_url = make_url(cls.URL)
            cls.DIALECT = parsed_url.get_backend_name()
        except Exception as e:
            raise ValueError(f"Invalid DATABASE_URL: {e}")
        if cls.DIALECT not in ["postgresql", "mysql", "sqlite"]:
            raise ValueError(f"Unsupported database dialect: {cls.DIALECT}")

# Validate config before engine creation
DatabaseConfig.validate()

# Dialect-specific connect_args
connect_args = {}
if DatabaseConfig.DIALECT == "mysql":
    connect_args = {"connect_timeout": 5}
elif DatabaseConfig.DIALECT == "postgresql":
    connect_args = {
        "connect_timeout": 5,
        "keepalives": 1,
        "keepalives_idle": 30,
        "keepalives_interval": 10,
        "keepalives_count": 5
    }

# SQLite gets no connect_args
if DatabaseConfig.DIALECT == "sqlite":
    connect_args = {}

# Create SQLAlchemy engine
engine = create_engine(
    DatabaseConfig.URL,
    poolclass=QueuePool,
    pool_size=DatabaseConfig.POOL_SIZE,
    max_overflow=DatabaseConfig.MAX_OVERFLOW,
    pool_recycle=DatabaseConfig.POOL_RECYCLE,
    pool_timeout=DatabaseConfig.POOL_TIMEOUT,
    echo=DatabaseConfig.ECHO,
    isolation_level=DatabaseConfig.ISOLATION_LEVEL,
    connect_args=connect_args
)

# Set up session factory
SessionFactory = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False
)
Session = scoped_session(SessionFactory)
Base = declarative_base()

# Dependency for FastAPI
@contextmanager
def get_db() -> Generator[SessionType, None, None]:
    session = Session()
    try:
        yield session
        session.commit()
    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Database error occurred: {str(e)}")
        raise
    finally:
        session.close()
        Session.remove()

# Init database connection and tables
def init_db():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))  # ✅ Fixed here
        logger.info("Database connection test successful")
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables initialized")
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise

# Health check function
def check_db_connection() -> bool:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))  # ✅ text() used here too
        return True
    except Exception as e:
        logger.error(f"Database connection check failed: {str(e)}")
        return False

# Pool stats
def get_db_stats() -> Dict[str, Any]:
    return {
        "checked_out": engine.pool.checkedout(),
        "checked_in": engine.pool.checkedin(),
        "connections": engine.pool.status(),
        "size": engine.pool.size()
    }

# Thread-local session helpers
_thread_local = threading.local()

def get_thread_local_db() -> SessionType:
    if not hasattr(_thread_local, "session"):
        _thread_local.session = Session()
    return _thread_local.session

def cleanup_thread_local_db():
    if hasattr(_thread_local, "session"):
        _thread_local.session.close()
        del _thread_local.session
        Session.remove()

# SQLite PRAGMA for dev mode
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if DatabaseConfig.DIALECT == "sqlite":
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
SessionLocal = Session
# Run check at module import
init_db()
