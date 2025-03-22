from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from sqlalchemy import func

# Ensure instance directory exists
if not os.path.exists('instance'):
    os.makedirs('instance')

app = Flask(__name__, static_url_path='', static_folder='static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hospital.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin, doctor, patient

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_patient(self):
        return self.role == 'patient'

    def is_admin(self):
        return self.role == 'admin'

    def is_doctor(self):
        return self.role == 'doctor'

class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    specialization = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    visit_charge = db.Column(db.Float, nullable=False, default=0.0)
    user = db.relationship('User', backref=db.backref('doctor', uselist=False))

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    address = db.Column(db.String(200), nullable=False)
    blood_group = db.Column(db.String(5), nullable=True)
    user = db.relationship('User', backref=db.backref('patient', uselist=False))

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    time_slot = db.Column(db.String(20), nullable=True)  # Made nullable for compatibility
    status = db.Column(db.String(20), default='pending')
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    patient = db.relationship('Patient', backref='appointments')
    doctor = db.relationship('Doctor', backref='appointments')

    @staticmethod
    def get_available_slots(doctor_id, date):
        # Define all possible time slots (9 AM to 5 PM, 1-hour slots)
        all_slots = [
            "09:00-10:00", "10:00-11:00", "11:00-12:00", "12:00-13:00",
            "13:00-14:00", "14:00-15:00", "15:00-16:00", "16:00-17:00"
        ]
        
        # Get booked appointments for the doctor on the given date
        booked_appointments = Appointment.query.filter(
            Appointment.doctor_id == doctor_id,
            func.date(Appointment.date) == date.date(),
            Appointment.status != 'cancelled'
        ).all()
        
        # Get booked time slots
        booked_slots = []
        for appt in booked_appointments:
            if appt.time_slot:  # Handle appointments without time_slot
                booked_slots.append(appt.time_slot)
            else:
                # For old appointments without time_slot, block the hour based on date
                hour = appt.date.strftime('%H:00-%H:00')
                if hour in all_slots:
                    booked_slots.append(hour)
        
        # Return available slots
        return [slot for slot in all_slots if slot not in booked_slots]

class BloodReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    hemoglobin = db.Column(db.Float)
    wbc_count = db.Column(db.Float)
    rbc_count = db.Column(db.Float)
    platelets = db.Column(db.Float)
    status = db.Column(db.String(20), default='pending')
    notes = db.Column(db.Text)
    patient = db.relationship('Patient', backref='blood_reports')
    doctor = db.relationship('Doctor', backref='blood_reports')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    doctors = Doctor.query.all()
    specializations = db.session.query(Doctor.specialization).distinct().all()
    specializations = [s[0] for s in specializations]  # Extract values from tuples
    return render_template('index.html', doctors=doctors, specializations=specializations)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        
        if not username or not password or not role:
            flash('Please enter all fields')
            return render_template('unified_login.html')
        
        user = User.query.filter_by(username=username, role=role).first()
        
        if not user or not user.check_password(password):
            flash('Invalid username or password')
            return render_template('unified_login.html')
        
        login_user(user)
        flash(f'Welcome back, {username}!')
        
        # Redirect based on role
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif role == 'doctor':
            return redirect(url_for('doctor_dashboard'))
        else:
            return redirect(url_for('patient_dashboard'))
    
    # If user is already logged in, redirect to appropriate dashboard
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'doctor':
            return redirect(url_for('doctor_dashboard'))
        else:
            return redirect(url_for('patient_dashboard'))
    
    return render_template('unified_login.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.role == 'admin':
        flash('Access denied. Please login as administrator.')
        return redirect(url_for('login'))
    
    # Get counts for dashboard
    patient_count = Patient.query.count()
    doctor_count = Doctor.query.count()
    appointment_count = Appointment.query.count()
    blood_report_count = BloodReport.query.count()
    
    # Get recent appointments
    recent_appointments = Appointment.query.order_by(Appointment.date.desc()).limit(5).all()
    
    # Get pending blood reports
    pending_blood_reports = BloodReport.query.filter_by(status='pending').all()
    
    return render_template('admin/dashboard.html',
                         patient_count=patient_count,
                         doctor_count=doctor_count,
                         appointment_count=appointment_count,
                         blood_report_count=blood_report_count,
                         recent_appointments=recent_appointments,
                         pending_blood_reports=pending_blood_reports)

@app.route('/admin/doctors')
@login_required
def admin_doctors():
    if not current_user.role == 'admin':
        flash('Access denied')
        return redirect(url_for('index'))
    doctors = Doctor.query.all()
    return render_template('admin/doctors.html', doctors=doctors)

@app.route('/admin/patients')
@login_required
def admin_patients():
    if not current_user.role == 'admin':
        flash('Access denied')
        return redirect(url_for('index'))
    patients = Patient.query.all()
    return render_template('admin/patients.html', patients=patients)

@app.route('/admin/blood_reports')
@login_required
def admin_blood_reports():
    if not current_user.role == 'admin':
        flash('Access denied')
        return redirect(url_for('index'))
    reports = BloodReport.query.order_by(BloodReport.date.desc()).all()
    return render_template('admin/blood_reports.html', reports=reports)

@app.route('/admin/appointments')
@login_required
def admin_appointments():
    if not current_user.role == 'admin':
        return redirect(url_for('login', role='admin'))
    appointments = db.session.query(
        Appointment, Doctor, Patient
    ).join(Doctor).join(Patient).all()
    return render_template('admin/appointments.html', appointments=appointments)

@app.route('/admin/doctor/delete/<int:id>', methods=['POST'])
@login_required
def delete_doctor(id):
    if not current_user.role == 'admin':
        return redirect(url_for('login', role='admin'))
    doctor = Doctor.query.get_or_404(id)
    user = User.query.get(doctor.user_id)
    db.session.delete(doctor)
    db.session.delete(user)
    db.session.commit()
    flash('Doctor deleted successfully')
    return redirect(url_for('admin_doctors'))

@app.route('/admin/add_doctor', methods=['GET', 'POST'])
@login_required
def add_doctor():
    if not current_user.role == 'admin':
        return redirect(url_for('login', role='admin'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name')
        email = request.form.get('email')
        specialization = request.form.get('specialization')
        phone = request.form.get('phone')
        visit_charge = request.form.get('visit_charge')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template('admin/add_doctor.html')
            
        if Doctor.query.filter_by(email=email).first():
            flash('Email already registered')
            return render_template('admin/add_doctor.html')
        
        user = User(username=username, role='doctor')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        doctor = Doctor(
            user_id=user.id,
            name=name,
            email=email,
            specialization=specialization,
            phone=phone,
            visit_charge=visit_charge
        )
        db.session.add(doctor)
        db.session.commit()
        
        flash('Doctor added successfully!')
        return redirect(url_for('admin_doctors'))
    
    return render_template('admin/add_doctor.html')

@app.route('/admin/add_patient', methods=['GET', 'POST'])
@login_required
def add_patient():
    if not current_user.role == 'admin':
        return redirect(url_for('login', role='admin'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        address = request.form.get('address')
        age = request.form.get('age')
        blood_group = request.form.get('blood_group')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template('admin/add_patient.html')
            
        if Patient.query.filter_by(email=email).first():
            flash('Email already registered')
            return render_template('admin/add_patient.html')
        
        user = User(username=username, role='patient')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        patient = Patient(
            user_id=user.id,
            name=name,
            email=email,
            phone=phone,
            address=address,
            age=int(age),
            blood_group=blood_group
        )
        db.session.add(patient)
        db.session.commit()
        
        flash('Patient added successfully!')
        return redirect(url_for('admin_patients'))
    
    return render_template('admin/add_patient.html')

@app.route('/admin/generate_blood_test/<int:patient_id>', methods=['GET', 'POST'])
@login_required
def admin_generate_blood_test(patient_id):
    if not current_user.role == 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))

    patient = Patient.query.get_or_404(patient_id)
    doctors = Doctor.query.all()

    if request.method == 'POST':
        doctor_id = request.form.get('doctor_id')
        hemoglobin = request.form.get('hemoglobin')
        wbc_count = request.form.get('wbc_count')
        rbc_count = request.form.get('rbc_count')
        platelets = request.form.get('platelets')
        notes = request.form.get('notes')

        blood_report = BloodReport(
            patient_id=patient_id,
            doctor_id=doctor_id,
            date=datetime.now(),
            hemoglobin=hemoglobin,
            wbc_count=wbc_count,
            rbc_count=rbc_count,
            platelets=platelets,
            notes=notes,
            status='completed'
        )
        db.session.add(blood_report)
        db.session.commit()

        flash('Blood test report generated successfully.', 'success')
        return redirect(url_for('admin_blood_reports'))

    return render_template('admin/generate_blood_test.html', patient=patient, doctors=doctors)

@app.route('/admin/blood_report/add', methods=['GET', 'POST'])
@login_required
def admin_add_blood_report():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        patient_id = request.form.get('patient_id')
        doctor_id = request.form.get('doctor_id')
        
        try:
            new_report = BloodReport(
                patient_id=patient_id,
                doctor_id=doctor_id,
                date=datetime.now(),
                status='pending'
            )
            db.session.add(new_report)
            db.session.commit()
            flash('Blood report created successfully')
            return redirect(url_for('admin_blood_reports'))
        except:
            db.session.rollback()
            flash('Error creating blood report')
    
    patients = Patient.query.all()
    doctors = Doctor.query.all()
    return render_template('admin/add_blood_report.html', patients=patients, doctors=doctors)

@app.route('/admin/blood_report/edit/<int:report_id>', methods=['GET', 'POST'])
@login_required
def edit_blood_report(report_id):
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    report = BloodReport.query.get_or_404(report_id)
    
    if request.method == 'POST':
        try:
            # Convert string values to float with proper validation
            hemoglobin = request.form.get('hemoglobin')
            wbc_count = request.form.get('wbc_count')
            rbc_count = request.form.get('rbc_count')
            platelets = request.form.get('platelets')

            report.hemoglobin = float(hemoglobin) if hemoglobin else None
            report.wbc_count = float(wbc_count) if wbc_count else None
            report.rbc_count = float(rbc_count) if rbc_count else None
            report.platelets = float(platelets) if platelets else None
            
            # Update status based on whether all fields are filled
            report.status = 'completed' if all([report.hemoglobin, report.wbc_count, report.rbc_count, report.platelets]) else 'pending'
            
            db.session.commit()
            flash('Blood report updated successfully', 'success')
            return redirect(url_for('admin_blood_reports'))
        except ValueError:
            flash('Please enter valid numeric values for all fields', 'danger')
        except:
            db.session.rollback()
            flash('Error updating blood report', 'danger')
    
    return render_template('admin/edit_blood_report.html', report=report)

@app.route('/doctor/dashboard')
@login_required
def doctor_dashboard():
    if not current_user.role == 'doctor':
        flash('Access denied. Please login as doctor.')
        return redirect(url_for('login'))
    
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor:
        flash('Doctor profile not found.')
        return redirect(url_for('login'))
    
    # Get today's appointments
    today = datetime.now().date()
    today_appointments = Appointment.query.filter(
        Appointment.doctor_id == doctor.id,
        Appointment.date >= today,
        Appointment.date < today + timedelta(days=1)
    ).all()
    
    # Get pending appointments
    pending_appointments = Appointment.query.filter_by(
        doctor_id=doctor.id,
        status='pending'
    ).order_by(Appointment.date).all()
    
    # Get all blood reports for debugging
    pending_blood_reports = BloodReport.query.filter_by(
        doctor_id=doctor.id
    ).order_by(BloodReport.date.desc()).all()
    
    # Debug information
    print(f"Doctor ID: {doctor.id}")
    print(f"Number of pending blood reports: {len(pending_blood_reports)}")
    for report in pending_blood_reports:
        print(f"""
Blood Report ID: {report.id}
Patient: {report.patient.name if report.patient else 'No patient'}
Date: {report.date}
Status: {report.status}
Hemoglobin: {report.hemoglobin}
WBC Count: {report.wbc_count}
RBC Count: {report.rbc_count}
Platelets: {report.platelets}
------------------""")
    
    return render_template('doctor/dashboard.html',
                         doctor=doctor,
                         today_appointments=today_appointments,
                         pending_appointments=pending_appointments,
                         pending_blood_reports=pending_blood_reports)

@app.route('/doctor/appointments')
@login_required
def doctor_appointments():
    if not current_user.role == 'doctor':
        flash('Access denied')
        return redirect(url_for('index'))
    
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    appointments = Appointment.query.filter_by(doctor_id=doctor.id).order_by(Appointment.date.desc()).all()
    return render_template('doctor/appointments.html', appointments=appointments)

@app.route('/doctor/update_appointment/<int:id>', methods=['POST'])
@login_required
def update_appointment(id):
    if not current_user.role == 'doctor':
        flash('Access denied')
        return redirect(url_for('login'))
    
    appointment = Appointment.query.get_or_404(id)
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    
    # Verify the appointment belongs to this doctor
    if appointment.doctor_id != doctor.id:
        flash('Access denied')
        return redirect(url_for('doctor_appointments'))

    # Update appointment status
    status = request.form.get('status')
    notes = request.form.get('notes')
    
    if status:
        appointment.status = status
    if notes:
        appointment.notes = notes
    
    db.session.commit()
    flash('Appointment updated successfully')
    return redirect(url_for('doctor_appointments'))

@app.route('/doctor/blood_reports')
@login_required
def doctor_blood_reports():
    if not current_user.role == 'doctor':
        flash('Access denied')
        return redirect(url_for('index'))
    
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    reports = BloodReport.query.filter_by(doctor_id=doctor.id).order_by(BloodReport.date.desc()).all()
    return render_template('doctor/blood_reports.html', reports=reports)

@app.route('/doctor/generate_blood_report/<int:patient_id>', methods=['GET', 'POST'])
@login_required
def generate_blood_report(patient_id):
    if not current_user.role == 'doctor':
        flash('Access denied')
        return redirect(url_for('index'))
    
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    patient = Patient.query.get_or_404(patient_id)
    
    if request.method == 'POST':
        try:
            report = BloodReport(
                patient_id=patient_id,
                doctor_id=doctor.id,
                hemoglobin=float(request.form.get('hemoglobin')) if request.form.get('hemoglobin') else None,
                wbc_count=float(request.form.get('wbc_count')) if request.form.get('wbc_count') else None,
                rbc_count=float(request.form.get('rbc_count')) if request.form.get('rbc_count') else None,
                platelets=float(request.form.get('platelets')) if request.form.get('platelets') else None,
                notes=request.form.get('notes'),
                status='completed'
            )
            db.session.add(report)
            db.session.commit()
            flash('Blood report generated successfully', 'success')
            return redirect(url_for('doctor_blood_reports'))
        except ValueError:
            flash('Please enter valid numeric values for all fields', 'danger')
        except:
            db.session.rollback()
            flash('Error generating blood report', 'danger')
    
    return render_template('doctor/generate_blood_report.html', patient=patient)

@app.route('/complete_appointment/<int:id>', methods=['POST'])
@login_required
def complete_appointment(id):
    if not current_user.is_doctor():
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    appointment = Appointment.query.get_or_404(id)
    
    # Check if this doctor owns this appointment
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor or appointment.doctor_id != doctor.id:
        flash('Access denied. This is not your appointment.', 'danger')
        return redirect(url_for('doctor_appointments'))

    # Check if appointment can be completed
    if appointment.status != 'confirmed':
        flash('Only confirmed appointments can be completed.', 'warning')
        return redirect(url_for('doctor_appointments'))

    # Update appointment status and notes
    appointment.status = 'completed'
    appointment.notes = request.form.get('notes', '')
    
    try:
        db.session.commit()
        flash('Appointment completed successfully.', 'success')
    except:
        db.session.rollback()
        flash('Error completing appointment.', 'danger')

    return redirect(url_for('doctor_appointments'))

@app.route('/confirm_appointment/<int:id>', methods=['POST'])
@login_required
def confirm_appointment(id):
    if not current_user.is_doctor():
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    appointment = Appointment.query.get_or_404(id)
    
    # Check if this doctor owns this appointment
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor or appointment.doctor_id != doctor.id:
        flash('Access denied. This is not your appointment.', 'danger')
        return redirect(url_for('doctor_appointments'))

    # Check if appointment can be confirmed
    if appointment.status != 'pending':
        flash('Only pending appointments can be confirmed.', 'warning')
        return redirect(url_for('doctor_appointments'))

    # Update appointment status
    appointment.status = 'confirmed'
    
    try:
        db.session.commit()
        flash('Appointment confirmed successfully.', 'success')
    except:
        db.session.rollback()
        flash('Error confirming appointment.', 'danger')

    return redirect(url_for('doctor_appointments'))

@app.route('/reject_appointment/<int:id>', methods=['POST'])
@login_required
def reject_appointment(id):
    if not current_user.is_doctor():
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    appointment = Appointment.query.get_or_404(id)
    
    # Check if this doctor owns this appointment
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor or appointment.doctor_id != doctor.id:
        flash('Access denied. This is not your appointment.', 'danger')
        return redirect(url_for('doctor_appointments'))

    # Check if appointment can be rejected
    if appointment.status != 'pending':
        flash('Only pending appointments can be rejected.', 'warning')
        return redirect(url_for('doctor_appointments'))

    # Update appointment status
    appointment.status = 'rejected'
    
    try:
        db.session.commit()
        flash('Appointment rejected successfully.', 'success')
    except:
        db.session.rollback()
        flash('Error rejecting appointment.', 'danger')

    return redirect(url_for('doctor_appointments'))

@app.route('/patient/dashboard')
@login_required
def patient_dashboard():
    # Only allow admin or the patient themselves to access
    if not (current_user.is_admin() or current_user.is_patient()):
        flash('Access denied. This page is only for admins and patients.', 'danger')
        return redirect(url_for('index'))
    
    # Get patient info - if admin, they need to specify patient_id in query param
    if current_user.is_admin():
        patient_id = request.args.get('patient_id')
        if not patient_id:
            flash('Please specify a patient ID.', 'warning')
            return redirect(url_for('admin_dashboard'))
        patient = Patient.query.filter_by(id=patient_id).first()
    else:
        patient = Patient.query.filter_by(user_id=current_user.id).first()

    if not patient:
        flash('Patient profile not found.', 'danger')
        return redirect(url_for('index'))
    
    # Get recent appointments
    appointments = Appointment.query.filter_by(patient_id=patient.id).order_by(Appointment.date.desc()).limit(5).all()
    
    # Get recent blood reports
    reports = BloodReport.query.filter_by(patient_id=patient.id).order_by(BloodReport.date.desc()).limit(5).all()
    
    # Get list of doctors for booking appointments
    doctors = Doctor.query.all()
    
    return render_template('patient/dashboard.html', 
                         patient=patient,
                         appointments=appointments, 
                         reports=reports, 
                         doctors=doctors,
                         is_admin=current_user.is_admin(),
                         now=datetime.now())

@app.route('/book_appointment/<int:doctor_id>', methods=['GET'])
@login_required
def show_book_appointment(doctor_id):
    if not current_user.is_patient():
        flash('Only patients can book appointments.', 'danger')
        return redirect(url_for('index'))
    
    doctor = Doctor.query.get_or_404(doctor_id)
    today = datetime.now().strftime('%Y-%m-%d')
    
    return render_template('patient/book_appointment.html', 
                         doctor=doctor,
                         today=today)

@app.route('/book_appointment', methods=['POST'])
@login_required
def book_appointment():
    if not current_user.is_patient():
        flash('Only patients can book appointments.', 'danger')
        return redirect(url_for('index'))

    try:
        # Get form data
        doctor_id = request.form.get('doctor_id')
        date_str = request.form.get('date')
        time_slot = request.form.get('time_slot')
        reason = request.form.get('reason')

        if not all([doctor_id, date_str, time_slot, reason]):
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('patient_dashboard'))

        # Get the patient
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if not patient:
            flash('Patient profile not found.', 'danger')
            return redirect(url_for('patient_dashboard'))

        # Get the doctor
        doctor = Doctor.query.get(doctor_id)
        if not doctor:
            flash('Selected doctor not found.', 'danger')
            return redirect(url_for('patient_dashboard'))

        # Parse date
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d')
            start_time = datetime.strptime(time_slot.split('-')[0], '%H:%M')
            appointment_datetime = datetime.combine(date.date(), start_time.time())
            
            # Validate future date
            if appointment_datetime < datetime.now():
                flash('Please select a future date and time.', 'warning')
                return redirect(url_for('show_book_appointment', doctor_id=doctor_id))

            # Check if slot is still available
            available_slots = Appointment.get_available_slots(doctor_id, date)
            if time_slot not in available_slots:
                flash('This time slot is no longer available. Please choose another time.', 'warning')
                return redirect(url_for('show_book_appointment', doctor_id=doctor_id))

            # Create and save the appointment
            appointment = Appointment(
                patient_id=patient.id,
                doctor_id=doctor.id,
                date=appointment_datetime,
                time_slot=time_slot,
                status='pending',
                notes=reason
            )
            
            db.session.add(appointment)
            db.session.commit()
            
            flash('Appointment booked successfully! Awaiting confirmation.', 'success')
            return redirect(url_for('patient_appointments'))
            
        except ValueError as e:
            flash('Invalid date or time format.', 'danger')
            return redirect(url_for('show_book_appointment', doctor_id=doctor_id))
            
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while booking the appointment.', 'danger')
        return redirect(url_for('show_book_appointment', doctor_id=doctor_id))

@app.route('/cancel_appointment/<int:id>', methods=['POST'])
@login_required
def cancel_appointment(id):
    if not current_user.role == 'patient':
        return redirect(url_for('login', role='patient'))
    
    appointment = Appointment.query.get_or_404(id)
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    
    if not patient or appointment.patient_id != patient.id:
        flash('Unauthorized access')
        return redirect(url_for('patient_dashboard'))
    
    if appointment.status != 'pending':
        flash('Only pending appointments can be cancelled')
        return redirect(url_for('patient_dashboard'))
    
    try:
        db.session.delete(appointment)
        db.session.commit()
        flash('Appointment cancelled successfully')
    except:
        flash('Error cancelling appointment')
    
    return redirect(url_for('patient_dashboard'))

@app.route('/patient/register', methods=['GET', 'POST'])
def patient_register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        address = request.form.get('address')
        age = request.form.get('age')
        blood_group = request.form.get('blood_group')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template('patient/register.html')
            
        if Patient.query.filter_by(email=email).first():
            flash('Email already registered')
            return render_template('patient/register.html')
        
        user = User(username=username, role='patient')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        patient = Patient(
            user_id=user.id,
            name=name,
            email=email,
            phone=phone,
            address=address,
            age=int(age),
            blood_group=blood_group
        )
        db.session.add(patient)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    
    return render_template('patient/register.html')

@app.route('/setup-admin', methods=['GET', 'POST'])
def setup_admin():
    # Check if admin already exists
    admin = User.query.filter_by(role='admin').first()
    if admin:
        flash('Admin already exists!')
        return redirect(url_for('login', role='admin'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template('setup_admin.html')
        
        admin = User(username=username, role='admin')
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        
        flash('Admin account created successfully!')
        return redirect(url_for('login', role='admin'))
    
    return render_template('setup_admin.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/download_report/<int:report_id>')
@login_required
def download_report(report_id):
    report = BloodReport.query.get_or_404(report_id)
    
    # GN Hospital color scheme
    colors_gn = {
        'primary': colors.HexColor('#13C5DD'),    # Primary blue
        'secondary': colors.HexColor('#354F8E'),  # Secondary blue
        'light': colors.HexColor('#EFF5F9'),     # Light background
        'dark': colors.HexColor('#1D2A4D')       # Dark blue
    }
    
    # Create a BytesIO buffer
    buffer = BytesIO()
    
    # Create the PDF document
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15*mm,
        leftMargin=15*mm,
        topMargin=20*mm,
        bottomMargin=20*mm
    )
    
    # Styles
    styles = getSampleStyleSheet()
    
    # Custom styles matching GN Hospital theme
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=28,
        textColor=colors_gn['primary'],
        spaceAfter=5,
        alignment=1  # Center alignment
    )
    
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors_gn['dark'],
        spaceAfter=20,
        alignment=1
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors_gn['secondary'],
        spaceBefore=15,
        spaceAfter=10
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors_gn['dark']
    )
    
    # Elements list
    elements = []
    
    # Add hospital logo and title
    elements.append(Paragraph('<i>GN Hospital</i>', title_style))
    elements.append(Paragraph('Blood Test Report', subtitle_style))
    elements.append(Spacer(1, 10*mm))
    
    # Report header with report ID and date
    header_data = [
        ['Report ID:', f'#{report.id}', 'Date:', report.date.strftime('%B %d, %Y')],
    ]
    header_table = Table(header_data, colWidths=[1.2*inch, 1.5*inch, 1*inch, 2*inch])
    header_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors_gn['primary']),
        ('BACKGROUND', (0, 0), (0, -1), colors_gn['light']),
        ('BACKGROUND', (2, 0), (2, -1), colors_gn['light']),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors_gn['dark']),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 5*mm))
    
    # Patient and Doctor Info in a side-by-side layout
    elements.append(Paragraph('Patient & Doctor Information', heading_style))
    info_data = [
        ['Patient Details', 'Doctor Details'],
        [
            f"Name: {report.patient.name}\n" +
            f"Age: {report.patient.age}\n" +
            f"Blood Group: {report.patient.blood_group}\n" +
            f"Phone: {report.patient.phone}\n" +
            f"Email: {report.patient.email}",
            
            f"Name: Dr. {report.doctor.name}\n" +
            f"Specialization: {report.doctor.specialization}\n" +
            f"Phone: {report.doctor.phone}\n" +
            f"Email: {report.doctor.email}"
        ]
    ]
    info_table = Table(info_data, colWidths=[3*inch, 3*inch])
    info_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors_gn['primary']),
        ('BACKGROUND', (0, 0), (-1, 0), colors_gn['primary']),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('PADDING', (0, 0), (-1, -1), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors_gn['light']),
        ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 1), (-1, -1), 'TOP'),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 10*mm))
    
    # Test Results
    elements.append(Paragraph('Test Results', heading_style))
    
    test_data = [
        ['Parameter', 'Result', 'Reference Range', 'Status'],
        ['Hemoglobin', f"{report.hemoglobin} g/dL", '12.0-15.5 g/dL',
         'Normal' if 12.0 <= float(report.hemoglobin) <= 15.5 else 'Abnormal'],
        ['WBC Count', f"{report.wbc_count} K/µL", '4.5-11.0 K/µL',
         'Normal' if 4.5 <= float(report.wbc_count) <= 11.0 else 'Abnormal'],
        ['RBC Count', f"{report.rbc_count} M/µL", '4.5-5.5 M/µL',
         'Normal' if 4.5 <= float(report.rbc_count) <= 5.5 else 'Abnormal'],
        ['Platelets', f"{report.platelets} K/µL", '150-450 K/µL',
         'Normal' if 150 <= float(report.platelets) <= 450 else 'Abnormal']
    ]
    
    test_table = Table(test_data, colWidths=[1.8*inch, 1.5*inch, 1.8*inch, 1.2*inch])
    test_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors_gn['primary']),
        ('BACKGROUND', (0, 0), (-1, 0), colors_gn['primary']),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors_gn['light']),
        # Conditional formatting for status
        *[
            ('TEXTCOLOR', (-1, i), (-1, i),
             colors_gn['primary'] if row[-1] == 'Normal' else colors.red)
            for i, row in enumerate(test_data[1:], 1)
        ],
        ('FONTNAME', (-1, 1), (-1, -1), 'Helvetica-Bold'),
    ]))
    elements.append(test_table)
    elements.append(Spacer(1, 10*mm))
    
    # Notes section
    if report.notes:
        elements.append(Paragraph('Doctor\'s Notes', heading_style))
        notes_para = Paragraph(report.notes, normal_style)
        notes_table = Table([[notes_para]], colWidths=[6.3*inch])
        notes_table.setStyle(TableStyle([
            ('BOX', (0, 0), (-1, -1), 0.5, colors_gn['primary']),
            ('BACKGROUND', (0, 0), (-1, -1), colors_gn['light']),
            ('PADDING', (0, 0), (-1, -1), 10),
        ]))
        elements.append(notes_table)
    
    # Footer with disclaimer
    elements.append(Spacer(1, 15*mm))
    disclaimer_text = (
        "Disclaimer: This report is for informational purposes only and should be reviewed by a qualified healthcare professional. "
        "The reference ranges provided are general guidelines and may vary based on the laboratory and patient-specific factors."
    )
    disclaimer_style = ParagraphStyle(
        'Disclaimer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors_gn['secondary'],
        alignment=1
    )
    elements.append(Paragraph(disclaimer_text, disclaimer_style))
    
    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    
    # Create response
    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=GN_Hospital_Blood_Report_{report.id}.pdf'
    
    return response

@app.route('/setup_test_accounts')
def setup_test_accounts():
    # Create admin account if it doesn't exist
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

    # Create test doctor account if it doesn't exist
    doctor_user = User.query.filter_by(username='doctor').first()
    if not doctor_user:
        doctor_user = User(username='doctor', role='doctor')
        doctor_user.set_password('doctor123')
        db.session.add(doctor_user)
        db.session.commit()

        # Create doctor profile
        doctor = Doctor(
            user_id=doctor_user.id,
            name='Dr. John Smith',
            specialization='General Medicine',
            email='doctor@example.com',
            phone='1234567890',
            visit_charge=500.0
        )
        db.session.add(doctor)
        db.session.commit()

    # Create test patient account if it doesn't exist
    patient_user = User.query.filter_by(username='patient').first()
    if not patient_user:
        patient_user = User(username='patient', role='patient')
        patient_user.set_password('patient123')
        db.session.add(patient_user)
        db.session.commit()

        # Create patient profile
        patient = Patient(
            user_id=patient_user.id,
            name='John Doe',
            email='patient@example.com',
            phone='9876543210',
            age=30,
            address='123 Main St',
            blood_group='O+'
        )
        db.session.add(patient)
        db.session.commit()

    # Add test blood reports if they don't exist
    doctor = Doctor.query.filter_by(email='doctor@example.com').first()
    patient = Patient.query.filter_by(email='patient@example.com').first()
    
    if doctor and patient:
        # Check if we already have test reports
        existing_reports = BloodReport.query.filter_by(doctor_id=doctor.id, patient_id=patient.id).count()
        if existing_reports == 0:
            # Create a pending report
            pending_report = BloodReport(
                doctor_id=doctor.id,
                patient_id=patient.id,
                date=datetime.now(),
                status='pending'
            )
            db.session.add(pending_report)
            
            # Create a completed report
            completed_report = BloodReport(
                doctor_id=doctor.id,
                patient_id=patient.id,
                date=datetime.now() - timedelta(days=7),
                hemoglobin=14.5,
                wbc_count=7500,
                rbc_count=5.2,
                platelets=250000,
                status='completed'
            )
            db.session.add(completed_report)
            db.session.commit()

    return 'Test accounts and blood reports created successfully! Use the following credentials:<br><br>' + \
           'Admin - username: admin, password: admin123<br>' + \
           'Doctor - username: doctor, password: doctor123<br>' + \
           'Patient - username: patient, password: patient123'

@app.route('/delete_blood_report/<int:report_id>', methods=['POST'])
@login_required
def delete_blood_report(report_id):
    if not current_user.role in ['admin', 'doctor']:
        flash('Access denied')
        return redirect(url_for('index'))
    
    report = BloodReport.query.get_or_404(report_id)
    
    # Only allow admin or the assigned doctor to delete the report
    if current_user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if not doctor or report.doctor_id != doctor.id:
            flash('Access denied')
            return redirect(url_for('doctor_blood_reports'))
    
    try:
        db.session.delete(report)
        db.session.commit()
        flash('Blood report deleted successfully')
    except:
        db.session.rollback()
        flash('Error deleting blood report')
    
    if current_user.role == 'admin':
        return redirect(url_for('admin_blood_reports'))
    else:
        return redirect(url_for('doctor_blood_reports'))

@app.route('/patient/blood_reports')
@login_required
def patient_blood_reports():
    # Get patient info - if admin, they need to specify patient_id in query param
    if current_user.is_admin():
        patient_id = request.args.get('patient_id')
        if not patient_id:
            flash('Please specify a patient ID.', 'warning')
            return redirect(url_for('admin_dashboard'))
        patient = Patient.query.filter_by(id=patient_id).first()
    else:
        if not current_user.is_patient():
            flash('Access denied. This page is only for patients.', 'danger')
            return redirect(url_for('index'))
        patient = Patient.query.filter_by(user_id=current_user.id).first()

    if not patient:
        flash('Patient profile not found.', 'danger')
        return redirect(url_for('index'))

    # Get all blood reports for the patient
    reports = BloodReport.query.filter_by(patient_id=patient.id).order_by(BloodReport.date.desc()).all()
    return render_template('patient/blood_reports.html', reports=reports, patient=patient, is_admin=current_user.is_admin())

@app.route('/patient/appointments')
@login_required
def patient_appointments():
    if not (current_user.is_admin() or current_user.is_patient()):
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    
    # Get patient info - if admin, they need to specify patient_id in query param
    if current_user.is_admin():
        patient_id = request.args.get('patient_id')
        if not patient_id:
            flash('Please specify a patient ID.', 'warning')
            return redirect(url_for('admin_dashboard'))
        patient = Patient.query.filter_by(id=patient_id).first()
    else:
        patient = Patient.query.filter_by(user_id=current_user.id).first()

    if not patient:
        flash('Patient profile not found.', 'danger')
        return redirect(url_for('index'))

    # Get all appointments for the patient
    appointments = Appointment.query.filter_by(patient_id=patient.id).order_by(Appointment.date.desc()).all()
    
    return render_template('patient/appointments.html',
                         patient=patient,
                         appointments=appointments,
                         is_admin=current_user.is_admin())

@app.route('/blood_report/<int:report_id>')
@login_required
def view_blood_report(report_id):
    # Get the report
    report = BloodReport.query.get_or_404(report_id)
    
    # Get patient info - if admin, they need to specify patient_id in query param
    if current_user.is_admin():
        patient_id = request.args.get('patient_id')
        if not patient_id:
            flash('Please specify a patient ID.', 'warning')
            return redirect(url_for('admin_dashboard'))
        patient = Patient.query.filter_by(id=patient_id).first()
    else:
        if not current_user.is_patient():
            flash('Access denied. This page is only for patients.', 'danger')
            return redirect(url_for('index'))
        patient = Patient.query.filter_by(user_id=current_user.id).first()

    if not patient:
        flash('Patient profile not found.', 'danger')
        return redirect(url_for('index'))

    # Check if the report belongs to the patient
    if report.patient_id != patient.id:
        flash('Access denied. You can only view your own reports.', 'danger')
        return redirect(url_for('patient_dashboard'))
    
    return render_template('patient/view_blood_report.html', 
                         report=report, 
                         patient=patient, 
                         is_admin=current_user.is_admin())

@app.route('/search_doctors', methods=['GET'])
def search_doctors():
    specialization = request.args.get('specialization', '')
    name = request.args.get('name', '')
    
    query = Doctor.query
    
    if specialization:
        query = query.filter(Doctor.specialization == specialization)
    if name:
        query = query.filter(Doctor.name.ilike(f'%{name}%'))
    
    doctors = query.all()
    specializations = db.session.query(Doctor.specialization).distinct().all()
    specializations = [s[0] for s in specializations]
    
    return render_template('index.html', doctors=doctors, specializations=specializations, 
                         search_specialization=specialization, search_name=name)

@app.route('/edit_visit_charge/<int:id>', methods=['POST'])
@login_required
def edit_visit_charge(id):
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('index'))
    
    doctor = Doctor.query.get_or_404(id)
    visit_charge = request.form.get('visit_charge')
    
    try:
        visit_charge = float(visit_charge)
        if visit_charge < 0:
            raise ValueError("Visit charge cannot be negative")
        
        doctor.visit_charge = visit_charge
        db.session.commit()
        flash('Visit charge updated successfully')
    except ValueError:
        flash('Invalid visit charge amount')
    
    return redirect(url_for('admin_doctors'))

@app.route('/get_available_slots')
def get_available_slots():
    doctor_id = request.args.get('doctor_id')
    date_str = request.args.get('date')
    
    if not doctor_id or not date_str:
        return jsonify({'error': 'Missing parameters'}), 400
    
    try:
        date = datetime.strptime(date_str, '%Y-%m-%d')
        available_slots = Appointment.get_available_slots(int(doctor_id), date)
        return jsonify({'slots': available_slots})
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        setup_test_accounts()  # Create test accounts when starting the server
    app.run(debug=True)
