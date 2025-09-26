from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.exc import IntegrityError
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import func
from fastapi import Query
from fastapi import File, UploadFile
from app.utilis import (
    get_password_hash,
    verify_password,
    create_access_token,
    ai_schedule_appointment,
    create_audit_hash
)
from dotenv import load_dotenv
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import List, Optional
from jose import jwt, JWTError
from datetime import datetime, date, timedelta
import os
import json
import logging
from pydantic import BaseModel

from app.database import SessionLocal, engine
from app.models import Base, Patient, WellnessAppointments, TestResults, Labs, Users, ChatMessages, AuditTrail
from app.schemas import (
    Token,
    UserCreate,
    UserRead,
    PatientCreate,
    PatientRead,
    WellnessAppointmentRead,
    WellnessAppointmentBase,
    TestResultBase,
    TestResultRead,
    LabBase,
    LabRead,
    ChatMessageBase,
    ChatMessageRead
)

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Wellness Appointment System API",
    description="API for managing wellness appointments and patient data",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("*", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 10000))

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY not set in .env")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError as e:
        logger.error(f"JWT Error: {str(e)}")
        raise credentials_exception

    user = db.query(Users).filter(Users.username == username).first()
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: Users = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user

@app.post("/auth/register", response_model=Token)
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    print("Received payload:", user)
    username = user.username.lower()
    hashed_password = get_password_hash(user.password)

    # Create new user
    new_user = Users(
        username=username,
        email=user.email,
        password=hashed_password,
        role=user.role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # If user is a patient, create associated patient record
    if user.role == "patient":
        patient = Patient(
            user_id=new_user.id,
            full_name=new_user.username.title(),
            email=new_user.email
        )
        db.add(patient)
        db.commit()

    # Generate and return token
    access_token = create_access_token(data={"sub": new_user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    username = form_data.username.lower()
    user = db.query(Users).filter(Users.username == username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Update last login time
    user.last_login = datetime.utcnow()
    db.commit()
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/me", response_model=UserRead)
async def read_current_user(current_user: Users = Depends(get_current_user)):
    return current_user

@app.post("/patients", response_model=PatientRead, status_code=status.HTTP_201_CREATED)
async def create_patient(patient: PatientCreate, db: Session = Depends(get_db), current_user: Users = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can create patients")
    existing_patient = db.query(Patient).filter(Patient.email == patient.email).first()
    if existing_patient:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="A patient with this email already exists.")
    patient_data = patient.dict()
    patient_data["biometric_data"] = json.dumps(patient_data.get("biometric_data", {}))
    patient_data["facial_hash"] = json.dumps(patient_data.get("facial_hash", {}))
    try:
        new_patient = Patient(**patient_data)
        db.add(new_patient)
        db.commit()
        db.refresh(new_patient)
        audit_log = AuditTrail(
            user_id=current_user.id,
            action=f"Created patient {new_patient.patient_id}",
            entity_type="Patient",
            entity_id=new_patient.patient_id,
            timestamp=datetime.utcnow()
        )
        db.add(audit_log)
        db.commit()
        return new_patient
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Database constraint error.")

@app.get("/admin/patients")
async def get_all_patients(
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return db.query(Patient).all()

@app.get("/admin/tests")
async def get_all_tests(
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return db.query(TestResults).all()

@app.get("/admin/appointments")
async def get_all_appointments(
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return db.query(WellnessAppointments).all()

@app.get("/admin/dashboard-stats")
async def get_dashboard_stats(db: Session = Depends(get_db), current_user: Users = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")

    # Total users count
    total_users = db.query(func.count(Users.id)).scalar()
    
    # Active labs count
    active_labs = db.query(func.count(Labs.lab_id)).scalar()
    
    # Appointments today count
    appointments_today = db.query(func.count(WellnessAppointments.appointment_id))\
        .filter(func.date(WellnessAppointments.appointment_date) == date.today()).scalar()
    
    # Total tests done
    total_tests = db.query(func.count(TestResults.id)).scalar()
    
    # Total appointments created
    total_appointments = db.query(func.count(WellnessAppointments.appointment_id)).scalar()

    return {
        "total_users": total_users,
        "active_labs": active_labs,
        "appointments_today": appointments_today,
        "total_tests": total_tests,
        "total_appointments": total_appointments
    }

@app.get("/admin/recent-users")
async def get_recent_users(db: Session = Depends(get_db), current_user: Users = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")

    # Get recent users with their last login time
    users = db.query(Users).order_by(Users.last_login.desc()).limit(5).all()
    
    return [
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "is_active": user.is_active,
            "created_at": user.created_at,
            "last_login": user.last_login
        }
        for user in users
    ]

@app.get("/patient/dashboard-stats")
async def get_patient_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user)
):
    if current_user.role != "patient":
        raise HTTPException(status_code=403, detail="Patients only")

    appointment_count = db.query(WellnessAppointments).filter(
        WellnessAppointments.patient_id == current_user.id
    ).count()

    test_result_count = db.query(TestResults).filter(
        TestResults.patient_id == current_user.id
    ).count()

    unread_message_count = db.query(ChatMessages).filter(
        ChatMessages.recipient_id == current_user.id,
        ChatMessages.is_read == False
    ).count()

    health_score = "85%"  # Placeholder

    return {
        "appointments": appointment_count,
        "test_results": test_result_count,
        "unread_messages": unread_message_count,
        "health_score": health_score
    }

@app.get("/patient/test-results/recent", response_model=List[TestResultRead])
async def get_recent_test_results(
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user)
):
    if current_user.role != "patient":
        raise HTTPException(status_code=403, detail="Patients only")

    # Fetch patient record linked to current user
    patient = db.query(Patient).filter(Patient.user_id == current_user.id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient record not found")

    try:
        results = db.query(TestResults).filter(
            TestResults.patient_id == patient.patient_id
        ).order_by(TestResults.generated_at.desc()).limit(5).all()
        return results
    except Exception as e:
        logger.error(f"Failed to retrieve recent test results: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.get("/patient/appointments/upcoming")
async def get_upcoming_appointments(
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user)
):
    if current_user.role != "patient":
        raise HTTPException(status_code=403, detail="Patients only")

    upcoming = db.query(WellnessAppointments).filter(
        WellnessAppointments.patient_id == current_user.id,
        WellnessAppointments.appointment_date >= date.today()
    ).order_by(WellnessAppointments.appointment_date.asc()).limit(5).all()
    return upcoming

@app.get("/appointments/{appointment_id}", response_model=WellnessAppointmentRead)
async def get_appointment(appointment_id: int, db: Session = Depends(get_db), current_user: Users = Depends(get_current_user)):
    appointment = db.query(WellnessAppointments).filter(WellnessAppointments.appointment_id == appointment_id).first()
    if not appointment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Appointment not found")
    if current_user.role != "admin" and current_user.id != appointment.patient_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this appointment")
    return appointment

@app.get("/appointments/patient/{patient_id}", response_model=List[WellnessAppointmentRead])
async def get_patient_appointments(patient_id: int, db: Session = Depends(get_db), current_user: Users = Depends(get_current_user)):
    if current_user.role != "patient" or current_user.id != patient_id:
        raise HTTPException(status_code=403, detail="Not authorized")
    return db.query(WellnessAppointments).filter(WellnessAppointments.patient_id == patient_id).all()

@app.post("/test-results", response_model=TestResultRead, status_code=201)
async def create_test_result(
    result: TestResultBase, 
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user)
):
    if current_user.role not in ["lab_tech", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only lab technicians and admins can create test results"
        )

    try:
        new_result = TestResults(**result.dict())
        db.add(new_result)
        db.commit()
        db.refresh(new_result)

        audit_log = AuditTrail(
            user_id=current_user.id,
            action=f"Created test result {new_result.id}",
            entity_type="test_result",
            timestamp=datetime.utcnow()
        )
        db.add(audit_log)
        db.commit()
        return new_result
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Error saving test result: {str(e)}"
        )

@app.get("/test-results/{result_id}", response_model=TestResultRead)
async def get_test_result(
    result_id: int, 
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user)
):
    result = db.query(TestResults).filter(TestResults.id == result_id).first()
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Test result not found"
        )
    if current_user.role not in ["admin", "lab_tech"] and current_user.id != result.patient_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this test result"
        )
    return result

@app.get("/patients/{patient_id}/test-results", response_model=List[TestResultRead])
async def list_test_results_for_patient(
    patient_id: int,
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user)
):
    if current_user.role != "admin":
        patient = db.query(Patient).filter(Patient.user_id == current_user.id).first()
        if not patient or patient.patient_id != patient_id:
            raise HTTPException(status_code=403, detail="Not authorized")
    return db.query(TestResults).filter(TestResults.patient_id == patient_id).all()

@app.delete("/test-results/{result_id}")
async def delete_test_result(
    result_id: int,
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")

    result = db.query(TestResults).filter(TestResults.id == result_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="Test result not found")

    db.delete(result)
    db.commit()
    return {"message": "Test result deleted successfully"}

@app.post("/labs", response_model=LabRead)
async def create_lab(
    lab: LabBase, 
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can create labs"
        )
    
    new_lab = Labs(**lab.dict())
    db.add(new_lab)
    db.commit()
    db.refresh(new_lab)
    
    audit_log = AuditTrail(
        user_id=current_user.id,
        action=f"Created lab {new_lab.lab_id}",
        entity_type="lab",
        entity_id=new_lab.lab_id,
        timestamp=datetime.utcnow()
    )
    db.add(audit_log)
    db.commit()
    return new_lab

@app.get("/labs", response_model=List[LabRead])
async def get_labs(db: Session = Depends(get_db)):
    return db.query(Labs).all()

@app.get("/labs/{lab_id}", response_model=LabRead)
async def get_lab(lab_id: int, db: Session = Depends(get_db)):
    lab = db.query(Labs).filter(Labs.lab_id == lab_id).first()
    if not lab:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Lab not found"
        )
    return lab

@app.post("/messages", response_model=ChatMessageRead)
async def send_message(
    message: ChatMessageBase, 
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user)
):
    if message.sender_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only send messages as yourself"
        )

    if not message.message.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message content cannot be empty"
        )

    new_message = ChatMessages(**message.dict())
    db.add(new_message)
    db.commit()
    db.refresh(new_message)
    return new_message

@app.get("/messages/{user_id}", response_model=List[ChatMessageRead])
async def get_messages(
    user_id: int, 
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user)
):
    if current_user.id != id and current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view these messages"
        )

    return db.query(ChatMessages).filter(
        or_(
            ChatMessages.sender_id == id,
            ChatMessages.recipient_id == id
        )
    ).order_by(ChatMessages.sent_at.asc()).all()

@app.get("/admin/audit-logs")
async def get_audit_logs(
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can view audit logs"
        )
    return db.query(AuditTrail).all()

@app.post("/admin/upload-census")
async def upload_census_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")

    filename = file.filename
    contents = await file.read()
    total_rows = contents.decode("utf-8").count("\n")  # naive row count
    logger.info(f"Uploaded file {filename} with approx {total_rows} rows")
    return {"message": f"File '{filename}' processed", "rows": total_rows}

@app.get("/admin/alerts")
async def get_system_alerts(
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user)
):
    if current_user.role not in ["admin", "lab_tech"]:
        raise HTTPException(status_code=403, detail="Admins or Lab Techs only")

    alerts = []

    labs = db.query(Labs).all()
    for lab in labs:
        if lab.max_capacity and lab.current_capacity / lab.max_capacity >= 0.85:
            alerts.append({
                "type": "warning",
                "title": f"{lab.name} approaching capacity",
                "message": f"{lab.current_capacity}/{lab.max_capacity} used",
                "timestamp": datetime.utcnow().isoformat()
            })

    alerts.append({
        "type": "success",
        "title": "System backup completed successfully",
        "message": "All data has been backed up securely",
        "timestamp": (datetime.utcnow() - timedelta(minutes=5)).isoformat()
    })

    return alerts

@app.get("/admin/qr-logs")
async def get_qr_registration_logs(
    current_user: Users = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")

    logs = [
        {"name": "Emily Johnson", "role": "Patient", "scanned_at": "2025-06-23T10:12:00Z"},
        {"name": "Dr. Chen", "role": "Lab Technician", "scanned_at": "2025-06-23T10:10:00Z"},
    ]
    return logs

@app.get("/admin/lab-capacity")
async def get_lab_capacity(db: Session = Depends(get_db), current_user: Users = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")

    labs = db.query(Labs).all()
    return [
        {
            "name": lab.lab_name,
            "current": lab.current_capacity,
            "max": lab.max_capacity,
            "percentage": int((lab.current_capacity / lab.max_capacity) * 100) if lab.max_capacity else 0
        }
        for lab in labs
    ]

@app.get("/labtech/dashboard-stats")
async def labtech_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_active_user)
):
    if current_user.role != "lab_tech":
        raise HTTPException(status_code=403, detail="Lab technicians only")
    
    pending_tests = db.query(func.count(TestResults.id)).filter(TestResults.result_status == "pending").scalar()
    completed_today = db.query(func.count(TestResults.id)).filter(
        TestResults.result_status == "ready",
        func.date(TestResults.generated_at) == date.today()
    ).scalar()
    urgent_tests = db.query(func.count(WellnessAppointments.appointment_id)).filter(WellnessAppointments.appointment_type == "urgent").scalar()
    
    avg_time = "45min"
    return {
        "pending_tests": pending_tests,
        "pending_change": 6,
        "completed_today": completed_today,
        "completed_change": 15,
        "urgent_tests": urgent_tests,
        "urgent_change": -2,
        "avg_time": avg_time,
        "avg_time_change": "-5min"
    }

@app.get("/labtech/test-queue")
async def labtech_test_queue(
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_active_user)
):
    if current_user.role != "lab_tech":
        raise HTTPException(status_code=403, detail="Lab technicians only")
    
    results = db.query(TestResults, Patient).join(Patient, TestResults.patient_id == Patient.patient_id)\
        .filter(TestResults.result_status == "pending").all()
    
    queue = [
        {
          "id": f"TST-{r.TestResults.id:03d}",
          "patient": r.Patient.full_name,
          "test": "Lab Result",
          "priority": "Urgent" if r.TestResults.result_status == "pending" else "Normal",
          "estimatedTime": "30 min",
          "status": "In Progress" if r.TestResults.result_status == "pending" else "Completed"
        }
        for r in results
    ]
    return queue

@app.get("/labtech/messages")
async def labtech_messages(
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_active_user)
):
    if current_user.role != "lab_tech":
        raise HTTPException(status_code=403, detail="Lab technicians only")
    
    msgs = db.query(ChatMessages).filter(ChatMessages.recipient_id == current_user.id).order_by(ChatMessages.sent_at.desc()).limit(10).all()
    return [
        {
          "from": m.sender.username if m.sender else "Unknown",
          "message": m.message,
          "time": m.sent_at.strftime("%H:%M"),
          "unread": not m.is_read
        } for m in msgs
    ]

@app.websocket("/ws/chat/{user_id}")
async def websocket_chat(websocket: WebSocket, user_id: int):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_text(f"Message received: {data}")
    except WebSocketDisconnect:
        logger.info(f"User {user_id} disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)

@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/auth/logout")
async def logout(current_user: Users = Depends(get_current_user)):
    return JSONResponse(
        status_code=200,
        content={
            "message": "Logout successful. Please clear the token on the client side."
        }
    )
