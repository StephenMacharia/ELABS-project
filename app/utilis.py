import os
import random
import string
import hashlib
import logging
from datetime import datetime, timedelta, date
from typing import Optional, Dict, Any

from dotenv import load_dotenv
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from cryptography.fernet import Fernet, InvalidToken

from app.models import Labs, WellnessAppointments, AppointmentStatus

# -----------------------
# Initialization
# -----------------------

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Load environment variables
load_dotenv()

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# -----------------------
# Configuration Class
# -----------------------

class Config:
    SECRET_KEY: str = os.getenv("SECRET_KEY", "defaultsecretkey")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    FERNET_KEY: str = os.getenv("FERNET_SECRET_KEY", "")

    @classmethod
    def validate(cls):
        if cls.SECRET_KEY == "defaultsecretkey":
            raise ValueError("⚠️ SECRET_KEY must be set in the environment")
        if not cls.FERNET_KEY:
            raise ValueError("⚠️ FERNET_SECRET_KEY must be set in the environment")

# Validate config on import
Config.validate()

# Fernet initialization
fernet = Fernet(Config.FERNET_KEY.encode())

# -----------------------
# Security Utilities
# -----------------------

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hashed value.
    bcrypt only supports up to 72 bytes, so truncate before verifying.
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except ValueError as e:
        if "password cannot be longer than 72 bytes" in str(e):
            # Truncate to 72 bytes (not characters!)
            password_bytes = plain_password.encode('utf-8')
            if len(password_bytes) > 72:
                # Truncate to 72 bytes and decode back to string
                truncated_bytes = password_bytes[:72]
                # Try to decode, ignoring any incomplete trailing character
                truncated_password = truncated_bytes.decode('utf-8', 'ignore')
                logger.warning(f"Password truncated from {len(password_bytes)} bytes to 72 bytes for verification")
                return pwd_context.verify(truncated_password, hashed_password)
        # Re-raise if it's a different error
        logger.error(f"Password verification failed: {e}")
        return False


def get_password_hash(password: str) -> str:
    """
    Hash a password for storage.
    bcrypt only supports up to 72 bytes, so truncate before hashing.
    """
    # Convert to bytes to check length
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        # Truncate to 72 bytes and decode back to string
        truncated_bytes = password_bytes[:72]
        # Try to decode, ignoring any incomplete trailing character
        truncated_password = truncated_bytes.decode('utf-8', 'ignore')
        logger.warning(f"Password truncated from {len(password_bytes)} bytes to 72 bytes for hashing")
        return pwd_context.hash(truncated_password)
    return pwd_context.hash(password)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token with an expiration.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=Config.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})

    try:
        return jwt.encode(to_encode, Config.SECRET_KEY, algorithm=Config.ALGORITHM)
    except JWTError as e:
        logger.error(f"[JWT ERROR] Token generation failed: {e}")
        raise ValueError("Token generation failed")

# -----------------------
# Code Generation
# -----------------------

def generate_random_code(length: int = 6) -> str:
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))


def generate_unique_code(db: Session, length: int = 6, max_attempts: int = 10) -> str:
    for _ in range(max_attempts):
        code = generate_random_code(length)
        exists = db.query(WellnessAppointments).filter_by(random_code=code).first()
        if not exists:
            return code
    raise ValueError("Failed to generate unique code after maximum attempts")

# -----------------------
# Appointment Scheduling
# -----------------------

def ai_schedule_appointment(patient_id: int, test_date: date, db: Session) -> Optional[WellnessAppointments]:
    """
    AI-based appointment scheduling that picks the first available lab.
    """
    try:
        available_labs = db.query(Labs).filter(Labs.capacity > 0).order_by(Labs.lab_id).all()
        if not available_labs:
            logger.warning("No labs with available capacity found")
            return None

        selected_lab = available_labs[0]
        random_code = generate_unique_code(db)

        appointment = WellnessAppointments(
            patient_id=patient_id,
            test_date=test_date,
            lab_id=selected_lab.lab_id,
            random_code=random_code,
            scheduled_by_ai=True,
            status=AppointmentStatus.SCHEDULED,
            appointment_date=datetime.utcnow()
        )

        selected_lab.capacity -= 1

        db.add_all([appointment, selected_lab])
        db.commit()
        db.refresh(appointment)
        return appointment

    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"[DB ERROR] While scheduling: {e}")
        return None
    except Exception as e:
        logger.error(f"[ERROR] Unexpected error during scheduling: {e}")
        return None

# -----------------------
# Encryption & Decryption
# -----------------------

def encrypt_message(message: str) -> str:
    try:
        return fernet.encrypt(message.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise ValueError("Encryption failed") from e


def decrypt_message(encrypted_message: str) -> str:
    try:
        return fernet.decrypt(encrypted_message.encode()).decode()
    except InvalidToken:
        logger.error("Decryption failed: Invalid token")
        raise ValueError("Invalid encryption token")
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise ValueError("Decryption failed") from e

# -----------------------
# Audit Trail Utilities
# -----------------------

def create_audit_hash(
    user_id: int,
    action: str,
    target_type: str,
    target_id: int,
    timestamp: datetime,
    previous_hash: str = ""
) -> str:
    record = f"{user_id}-{action}-{target_type}-{target_id}-{timestamp.isoformat()}-{previous_hash}"
    return hashlib.sha256(record.encode()).hexdigest()
