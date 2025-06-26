from typing import List, Optional
from datetime import date, datetime
from enum import Enum as PyEnum

from sqlalchemy import (
    Boolean, Column, Date, DateTime, Enum, Float, ForeignKey, Index,
    Integer, String, Text, text, func
)
from sqlalchemy.dialects.mysql import TINYINT, LONGTEXT
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


# ===== Base Class =====
class Base(DeclarativeBase):
    pass


# ===== ENUMS =====
class AppointmentStatus(str, PyEnum):
    scheduled = "scheduled"
    completed = "completed"
    cancelled = "cancelled"
    noshow = "noshow"
    pending = "pending"


class AppointmentType(str, PyEnum):
    routine = "routine"
    urgent = "urgent"
    follow_up = "follow_up"
    wellness = "wellness"


class NotificationChannel(str, PyEnum):
    sms = "sms"
    email = "email"
    whatsapp = "whatsapp"
    ivr = "ivr"
    push = "push"


class UserRole(str, PyEnum):
    admin = "admin"
    lab_tech = "lab_tech"
    staff = "staff"
    patient = "patient"  # ✅ lowercase to match DB


class ResultStatus(str, PyEnum):
    pending = "pending"
    ready = "ready"
    error = "error"
    under_review = "under_review"


class TicketStatus(str, PyEnum):
    open = "open"
    in_progress = "in_progress"
    resolved = "resolved"
    closed = "closed"


# ===== MODELS =====

class Labs(Base):
    __tablename__ = 'labs'

    lab_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    lab_name: Mapped[str] = mapped_column(String(100), nullable=False)
    location: Mapped[str] = mapped_column(String(100), nullable=False)
    capacity: Mapped[int] = mapped_column(Integer, server_default=text('10'))
    is_active: Mapped[bool] = mapped_column(TINYINT(1), server_default=text('1'))
    max_capacity = mapped_column(Integer, nullable=True)
    current_capacity = mapped_column(Integer, nullable=True)

    # Relationships
    appointment_slots: Mapped[List["AppointmentSlots"]] = relationship(back_populates='lab')
    equipment_logs: Mapped[List["EquipmentLogs"]] = relationship(back_populates='lab')
    quality_reports: Mapped[List["QualityReports"]] = relationship(back_populates='lab')
    wellness_appointments: Mapped[List["WellnessAppointments"]] = relationship(back_populates='lab')
    test_results: Mapped[List["TestResults"]] = relationship(back_populates='lab')

    __table_args__ = (
        Index('idx_lab_location', 'location'),
    )


class Users(Base):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole),
        nullable=False,
        server_default=text("'patient'")
    )
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime)
    is_active: Mapped[bool] = mapped_column(TINYINT(1), server_default=text('1'))
    created_at = mapped_column(DateTime, default=func.now())

    # Relationships
    sent_messages: Mapped[List["ChatMessages"]] = relationship(
        foreign_keys='ChatMessages.sender_id', back_populates='sender'
    )
    received_messages: Mapped[List["ChatMessages"]] = relationship(
        foreign_keys='ChatMessages.recipient_id', back_populates='recipient'
    )
    patient = relationship("Patient", back_populates="user", uselist=False)


class Patient(Base):
    __tablename__ = 'patients'

    patient_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, unique=True)
    full_name: Mapped[str] = mapped_column(String(100), nullable=False)
    date_of_birth: Mapped[date] = mapped_column(Date, nullable=False)
    gender: Mapped[str] = mapped_column(String(10), nullable=False)
    phone_number: Mapped[str] = mapped_column(String(20), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    is_verified: Mapped[bool] = mapped_column(TINYINT(1), server_default=text('0'))
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    biometric_data: Mapped[Optional[str]] = mapped_column(LONGTEXT)
    facial_hash: Mapped[Optional[str]] = mapped_column(LONGTEXT)
    preferred_channel: Mapped[NotificationChannel] = mapped_column(
        Enum(NotificationChannel), server_default=text("'sms'")
    )
    points: Mapped[int] = mapped_column(Integer, server_default=text('0'))
    badge: Mapped[str] = mapped_column(String(20), server_default=text("'bronze'"))
    prefer_digital_notifications: Mapped[bool] = mapped_column(TINYINT(1), server_default=text('1'))
    voice_pin: Mapped[Optional[str]] = mapped_column(String(255))
    entity_type = Column(String(50))

    # Relationships
    user = relationship("Users", back_populates="patient")
    notifications: Mapped[List["Notifications"]] = relationship(back_populates='patient')
    support_tickets: Mapped[List["SupportTickets"]] = relationship(back_populates='patient')
    wellness_profiles: Mapped[List["WellnessProfiles"]] = relationship(back_populates='patient')
    appointments: Mapped[List["WellnessAppointments"]] = relationship(back_populates='patient')

    __table_args__ = (
        Index('idx_patient_email', 'email'),
        Index('idx_patient_phone', 'phone_number'),
    )


class AppointmentSlots(Base):
    __tablename__ = 'appointment_slots'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    lab_id: Mapped[int] = mapped_column(ForeignKey('labs.lab_id'), nullable=False)
    slot_time: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    is_available: Mapped[bool] = mapped_column(TINYINT(1), server_default=text('1'))
    predicted_demand_score: Mapped[float] = mapped_column(Float, server_default=text('0.0'))

    lab: Mapped["Labs"] = relationship(back_populates='appointment_slots')

    __table_args__ = (
        Index('idx_slot_lab_time', 'lab_id', 'slot_time', unique=True),
    )


class TestResults(Base):
    __tablename__ = 'test_results'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    lab_id: Mapped[int] = mapped_column(ForeignKey('labs.lab_id'))
    patient_id: Mapped[int] = mapped_column(ForeignKey('patients.patient_id'))
    result_file_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    result_status: Mapped[str] = mapped_column(
        Enum('pending', 'ready', 'error', name='result_status_enum'),
        nullable=False,
        default='pending'
    )
    generated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    lab: Mapped["Labs"] = relationship(back_populates='test_results')
    patient: Mapped["Patient"] = relationship()

    __table_args__ = (
        Index('idx_result_patient', 'patient_id'),
        Index('idx_result_status', 'result_status'),
    )


class WellnessAppointments(Base):
    __tablename__ = 'wellness_appointments'

    appointment_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    patient_id: Mapped[int] = mapped_column(ForeignKey('patients.patient_id'))
    lab_id: Mapped[int] = mapped_column(ForeignKey('labs.lab_id'))
    appointment_date = mapped_column(DateTime)
    test_date: Mapped[date] = mapped_column(Date)
    status: Mapped[AppointmentStatus] = mapped_column(Enum(AppointmentStatus))
    appointment_type: Mapped[AppointmentType] = mapped_column(Enum(AppointmentType), default=AppointmentType.routine)
    random_code: Mapped[str] = mapped_column(String(50), unique=True)
    is_checked_in: Mapped[bool] = mapped_column(default=False)
    scheduled_by_ai: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    lab: Mapped["Labs"] = relationship(back_populates='wellness_appointments')
    patient: Mapped["Patient"] = relationship(back_populates='appointments')

    __table_args__ = (
        Index('idx_appointment_patient', 'patient_id'),
        Index('idx_appointment_lab', 'lab_id'),
        Index('idx_appointment_status', 'status'),
        Index('idx_appointment_code', 'random_code', unique=True),
    )


class EquipmentLogs(Base):
    __tablename__ = 'equipment_logs'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    lab_id: Mapped[int] = mapped_column(ForeignKey('labs.lab_id'))
    equipment_name: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(50))
    last_maintenance: Mapped[Optional[date]] = mapped_column(Date)
    next_maintenance: Mapped[Optional[date]] = mapped_column(Date)
    notes: Mapped[Optional[str]] = mapped_column(Text)

    lab: Mapped["Labs"] = relationship(back_populates='equipment_logs')


class QualityReports(Base):
    __tablename__ = 'quality_reports'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    lab_id: Mapped[int] = mapped_column(ForeignKey('labs.lab_id'))
    report_date: Mapped[date] = mapped_column(Date)
    score: Mapped[float] = mapped_column(Float)
    inspector: Mapped[str] = mapped_column(String(100))
    comments: Mapped[Optional[str]] = mapped_column(Text)

    lab: Mapped["Labs"] = relationship(back_populates='quality_reports')


class Notifications(Base):
    __tablename__ = 'notifications'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    patient_id: Mapped[int] = mapped_column(ForeignKey('patients.patient_id'))
    message: Mapped[str] = mapped_column(Text)
    channel: Mapped[NotificationChannel] = mapped_column(Enum(NotificationChannel))
    sent_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    is_read: Mapped[bool] = mapped_column(TINYINT(1), server_default=text('0'))

    patient: Mapped["Patient"] = relationship(back_populates='notifications')


class SupportTickets(Base):
    __tablename__ = 'support_tickets'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    patient_id: Mapped[int] = mapped_column(ForeignKey('patients.patient_id'))
    subject: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[TicketStatus] = mapped_column(Enum(TicketStatus), default=TicketStatus.open)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    patient: Mapped["Patient"] = relationship(back_populates='support_tickets')


class WellnessProfiles(Base):
    __tablename__ = 'wellness_profiles'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    patient_id: Mapped[int] = mapped_column(ForeignKey('patients.patient_id'))
    height: Mapped[Optional[float]] = mapped_column(Float)
    weight: Mapped[Optional[float]] = mapped_column(Float)
    blood_type: Mapped[Optional[str]] = mapped_column(String(10))
    allergies: Mapped[Optional[str]] = mapped_column(Text)
    chronic_conditions: Mapped[Optional[str]] = mapped_column(Text)
    last_updated: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    patient: Mapped["Patient"] = relationship(back_populates='wellness_profiles')


class ChatMessages(Base):
    __tablename__ = 'chat_messages'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    recipient_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    message: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    sent_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    is_read: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text('false'))

    sender: Mapped["Users"] = relationship(foreign_keys=[sender_id], back_populates='sent_messages')
    recipient: Mapped["Users"] = relationship(foreign_keys=[recipient_id], back_populates='received_messages')

    __table_args__ = (
        Index('idx_chat_participants', 'sender_id', 'recipient_id'),
    )


class AuditTrail(Base):
    __tablename__ = "audit_trail"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(255))
    table_name: Mapped[Optional[str]] = mapped_column(String(100))
    record_id: Mapped[Optional[int]] = mapped_column(Integer)
    old_values: Mapped[Optional[str]] = mapped_column(Text)
    new_values: Mapped[Optional[str]] = mapped_column(Text)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    entity_id = mapped_column(Integer)
    entity_type: Mapped[str] = mapped_column(String(50))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped[Optional["Users"]] = relationship()

    __table_args__ = (
        Index('idx_audit_user', 'user_id'),
        Index('idx_audit_table_record', 'table_name', 'record_id'),
    )
