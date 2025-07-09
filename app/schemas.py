from typing import Optional, List, Literal
from pydantic import BaseModel, EmailStr, ConfigDict, Field, field_serializer
from datetime import date, datetime
from enum import Enum

# ---------------------------
# Shared JSON Encoders
# ---------------------------

json_encoders = {
    date: lambda v: v.isoformat(),
    datetime: lambda v: v.isoformat()
}

# ---------------------------
# Enums
# ---------------------------

class NotificationChannel(str, Enum):
    sms = 'sms'
    email = 'email'
    whatsapp = 'whatsapp'
    ivr = 'ivr'
    push = 'push'

class UserRole(str, Enum):
    admin = 'admin'
    lab_tech = 'lab_tech'
    staff = 'staff'
    patient = 'patient'

class AppointmentStatus(str, Enum):
    scheduled = 'scheduled'
    completed = 'completed'
    cancelled = 'cancelled'
    noshow = 'noshow'
    pending = 'PENDING'

class AppointmentType(str, Enum):
    routine = 'routine'
    urgent = 'urgent'
    follow_up = 'follow_up'
    wellness = 'wellness'

class TicketStatus(str, Enum):
    open = 'open'
    in_progress = 'in_progress'
    resolved = 'resolved'
    closed = 'closed'

class ResultStatus(str, Enum):
    pending = 'pending'
    ready = 'ready'
    error = 'error'
    under_review = 'under_review'

# ---------------------------
# User Models
# ---------------------------

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: Optional[EmailStr] = None  # Make email optional
    role: UserRole = Field(default=UserRole.patient)
    is_active: bool = True

    model_config = ConfigDict(use_enum_values=True)

class UserCreate(UserBase):
    password: str = Field(..., min_length=5)
    role: UserRole = Field(default=UserRole.patient)
    # Make email required during creation if needed
    email: EmailStr = Field(...)

class UserRead(UserBase):
    id: int
    last_login: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)


# ---------------------------
# Patient Models
# ---------------------------

class PatientBase(BaseModel):
    full_name: str
    date_of_birth: date
    gender: str
    phone_number: str
    email: Optional[EmailStr]
    is_verified: bool = False

    model_config = ConfigDict(json_encoders=json_encoders)

class PatientCreate(PatientBase):
    password: str = Field(..., min_length=8)

class PatientRead(PatientBase):
    patient_id: int

    model_config = ConfigDict(from_attributes=True)

# ---------------------------
# Appointment Models
# ---------------------------

class WellnessAppointmentBase(BaseModel):
    patient_id: int
    lab_id: int
    appointment_date: datetime
    test_date: date
    status: AppointmentStatus = AppointmentStatus.scheduled
    appointment_type: AppointmentType = AppointmentType.routine

    @field_serializer('status')
    def serialize_status(self, status: AppointmentStatus, _info):
        return status.value

    model_config = ConfigDict(json_encoders=json_encoders)

class WellnessAppointmentRead(WellnessAppointmentBase):
    appointment_id: int
    random_code: str
    is_checked_in: bool = False
    scheduled_by_ai: Optional[bool] = False
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# ---------------------------
# Lab Models
# ---------------------------

class LabBase(BaseModel):
    lab_name: str
    location: str
    capacity: int

class LabRead(LabBase):
    lab_id: int
    max_capacity: Optional[int] = None
    current_capacity: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)

# ---------------------------
# Test Result Models
# ---------------------------

class TestResultBase(BaseModel):
    lab_id: int
    patient_id: int
    result_status: ResultStatus = ResultStatus.pending

class TestResultRead(TestResultBase):
    id: int
    result_file_path: Optional[str] = None
    generated_at: datetime

    model_config = ConfigDict(from_attributes=True)

# ---------------------------
# Notification Models
# ---------------------------

class NotificationBase(BaseModel):
    patient_id: int
    message: str
    channel: NotificationChannel = NotificationChannel.sms

class NotificationRead(NotificationBase):
    id: int
    sent_at: datetime
    is_read: bool = False

    model_config = ConfigDict(from_attributes=True)

# ---------------------------
# Support Ticket Models
# ---------------------------

class SupportTicketBase(BaseModel):
    patient_id: int
    subject: str
    description: str
    status: TicketStatus = TicketStatus.open

class SupportTicketRead(SupportTicketBase):
    id: int
    created_at: datetime
    resolved_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

# ---------------------------
# Wellness Profile Models
# ---------------------------

class WellnessProfileBase(BaseModel):
    patient_id: int
    height: Optional[float]
    weight: Optional[float]
    blood_type: Optional[str]
    allergies: Optional[str]
    chronic_conditions: Optional[str]

class WellnessProfileRead(WellnessProfileBase):
    id: int
    last_updated: datetime

    model_config = ConfigDict(from_attributes=True)

# ---------------------------
# Equipment Log Models
# ---------------------------

class EquipmentLogBase(BaseModel):
    lab_id: int
    equipment_name: str
    status: str
    last_maintenance: Optional[date]
    next_maintenance: Optional[date]
    notes: Optional[str]

class EquipmentLogRead(EquipmentLogBase):
    id: int

    model_config = ConfigDict(from_attributes=True)

# ---------------------------
# Quality Report Models
# ---------------------------

class QualityReportBase(BaseModel):
    lab_id: int
    report_date: date
    score: float
    inspector: str
    comments: Optional[str]

class QualityReportRead(QualityReportBase):
    id: int

    model_config = ConfigDict(from_attributes=True)

# ---------------------------
# Chat Message Models
# ---------------------------

class ChatMessageBase(BaseModel):
    sender_id: int
    recipient_id: int
    message: str = Field(..., min_length=1, max_length=500)

class ChatMessageRead(ChatMessageBase):
    id: int
    created_at: datetime
    sent_at: datetime
    is_read: bool = False

    model_config = ConfigDict(from_attributes=True)

# ---------------------------
# Audit Trail Models
# ---------------------------

class AuditTrailBase(BaseModel):
    user_id: int
    action: str
    entity_type: str
    table_name: Optional[str]
    record_id: Optional[int]
    old_values: Optional[str]
    new_values: Optional[str]
    ip_address: Optional[str]
    entity_id: Optional[int]
    timestamp: datetime

    model_config = ConfigDict(json_encoders=json_encoders)

class AuditTrailRead(AuditTrailBase):
    id: int

    model_config = ConfigDict(from_attributes=True)

# ---------------------------
# Auth Models
# ---------------------------

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: Optional[int] = None

class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[int] = None
    scopes: List[str] = []