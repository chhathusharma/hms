from app import app, db, User, Doctor, Patient, Appointment
from werkzeug.security import generate_password_hash
from datetime import datetime

with app.app_context():
    # Drop all tables
    db.drop_all()
    
    # Create all tables
    db.create_all()
    
    # Create admin user
    admin = User(username='admin', role='admin')
    admin.set_password('admin')
    db.session.add(admin)

    # Create a test doctor
    doctor_user = User(username='doctor1', role='doctor')
    doctor_user.set_password('doctor1')
    db.session.add(doctor_user)
    db.session.flush()  # This will assign an ID to doctor_user

    doctor = Doctor(
        user_id=doctor_user.id,
        name='Dr. John Smith',
        specialization='General Medicine',
        email='john.smith@hospital.com',
        phone='1234567890'
    )
    db.session.add(doctor)

    # Create a test patient
    patient_user = User(username='patient1', role='patient')
    patient_user.set_password('patient1')
    db.session.add(patient_user)
    db.session.flush()  # This will assign an ID to patient_user

    patient = Patient(
        user_id=patient_user.id,
        name='Jane Doe',
        email='jane.doe@example.com',
        phone='9876543210',
        age=30,
        address='123 Main St',
        blood_group='A+'
    )
    db.session.add(patient)

    # Commit all changes
    db.session.commit()

    print("Database initialized successfully!")
