from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = '123456'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///parking_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'error'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    full_name = db.Column(db.String(100), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    reservations = db.relationship('Reservation', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ParkingLot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prime_location_name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    address = db.Column(db.String(200), nullable=False)
    pin_code = db.Column(db.String(10), nullable=False)
    maximum_number_of_spots = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    spots = db.relationship('ParkingSpot', backref='lot', lazy=True, cascade='all, delete-orphan')

class ParkingSpot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lot_id = db.Column(db.Integer, db.ForeignKey('parking_lot.id'), nullable=False)
    status = db.Column(db.String(1), default='A')  # A-Available, O-Occupied
    reservations = db.relationship('Reservation', backref='spot', lazy=True)

class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    spot_id = db.Column(db.Integer, db.ForeignKey('parking_spot.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    parking_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    leaving_timestamp = db.Column(db.DateTime, nullable=True)
    parking_cost = db.Column(db.Float, nullable=True)
    vehicle_number = db.Column(db.String(20), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    duration_hours = db.Column(db.Float, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create tables and admin user
def create_tables():
    with app.app_context():
        db.create_all()
        # Create admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin', 
                email='admin@parking.com',
                full_name='System Administrator',
                is_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()

# Validation functions
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    if not phone:
        return True  # Phone is optional
    pattern = r'^[+]?[\d\s-()]{10,15}$'
    return re.match(pattern, phone) is not None

def validate_vehicle_number(vehicle_number):
    if not vehicle_number:
        return False
    pattern = r'^[A-Z]{2}[0-9]{2}[A-Z]{2}[0-9]{4}$|^[A-Z]{2}[0-9]{2}[A-Z]{1,2}[0-9]{1,4}$'
    return re.match(pattern, vehicle_number.upper()) is not None

def validate_pin_code(pin_code):
    pattern = r'^[0-9]{6}$'
    return re.match(pattern, pin_code) is not None

# Helper functions
def admin_required(f):
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        if not current_user.is_admin:
            flash('Admin access required.', 'error')
            return redirect(url_for('user_dashboard'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        phone = request.form.get('phone', '').strip()
        full_name = request.form.get('full_name', '').strip()
        
        # Backend validation
        errors = []
        
        if len(username) < 3:
            errors.append('Username must be at least 3 characters long.')
        
        if not validate_email(email):
            errors.append('Please enter a valid email address.')
        
        if len(password) < 6:
            errors.append('Password must be at least 6 characters long.')
        
        if phone and not validate_phone(phone):
            errors.append('Please enter a valid phone number.')
        
        if not full_name:
            errors.append('Full name is required.')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            errors.append('Username already exists.')
        
        if User.query.filter_by(email=email).first():
            errors.append('Email already exists.')
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('register.html')
        
        # Create new user
        user = User(username=username, email=email, phone=phone, full_name=full_name)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    lots = ParkingLot.query.all()
    total_spots = db.session.query(ParkingSpot).count()
    occupied_spots = db.session.query(ParkingSpot).filter_by(status='O').count()
    available_spots = total_spots - occupied_spots
    total_users = User.query.filter_by(is_admin=False).count()
    total_reservations = Reservation.query.count()
    active_reservations = Reservation.query.filter_by(is_active=True).count()
    
    return render_template('admin_dashboard.html', 
                         lots=lots, 
                         total_spots=total_spots,
                         occupied_spots=occupied_spots,
                         available_spots=available_spots,
                         total_users=total_users,
                         total_reservations=total_reservations,
                         active_reservations=active_reservations)

@app.route('/admin/parking-lots')
@admin_required
def admin_parking_lots():
    search_query = request.args.get('search', '').strip()
    if search_query:
        lots = ParkingLot.query.filter(
            ParkingLot.prime_location_name.contains(search_query) |
            ParkingLot.address.contains(search_query) |
            ParkingLot.pin_code.contains(search_query)
        ).all()
    else:
        lots = ParkingLot.query.all()
    return render_template('admin_parking_lots.html', lots=lots, search_query=search_query)

@app.route('/admin/add-lot', methods=['GET', 'POST'])
@admin_required
def add_parking_lot():
    if request.method == 'POST':
        name = request.form['name'].strip()
        price = request.form['price']
        address = request.form['address'].strip()
        pin_code = request.form['pin_code'].strip()
        max_spots = request.form['max_spots']
        
        # Backend validation
        errors = []
        
        if not name:
            errors.append('Location name is required.')
        
        try:
            price = float(price)
            if price <= 0:
                errors.append('Price must be greater than 0.')
        except ValueError:
            errors.append('Please enter a valid price.')
        
        if not address:
            errors.append('Address is required.')
        
        if not validate_pin_code(pin_code):
            errors.append('Pin code must be exactly 6 digits.')
        
        try:
            max_spots = int(max_spots)
            if max_spots <= 0:
                errors.append('Number of spots must be greater than 0.')
        except ValueError:
            errors.append('Please enter a valid number of spots.')
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('add_parking_lot.html')
        
        # Create parking lot
        lot = ParkingLot(
            prime_location_name=name,
            price=price,
            address=address,
            pin_code=pin_code,
            maximum_number_of_spots=max_spots
        )
        db.session.add(lot)
        db.session.commit()
        
        # Create parking spots
        for i in range(max_spots):
            spot = ParkingSpot(lot_id=lot.id, status='A')
            db.session.add(spot)
        
        db.session.commit()
        flash('Parking lot created successfully!', 'success')
        return redirect(url_for('admin_parking_lots'))
    
    return render_template('add_parking_lot.html')

@app.route('/admin/edit-lot/<int:lot_id>', methods=['GET', 'POST'])
@admin_required
def edit_parking_lot(lot_id):
    lot = ParkingLot.query.get_or_404(lot_id)
    
    if request.method == 'POST':
        lot.prime_location_name = request.form['name'].strip()
        lot.address = request.form['address'].strip()
        lot.pin_code = request.form['pin_code'].strip()
        
        # Validation
        errors = []
        
        try:
            lot.price = float(request.form['price'])
            if lot.price <= 0:
                errors.append('Price must be greater than 0.')
        except ValueError:
            errors.append('Please enter a valid price.')
        
        if not validate_pin_code(lot.pin_code):
            errors.append('Pin code must be exactly 6 digits.')
        
        try:
            new_max_spots = int(request.form['max_spots'])
            if new_max_spots <= 0:
                errors.append('Number of spots must be greater than 0.')
        except ValueError:
            errors.append('Please enter a valid number of spots.')
            new_max_spots = lot.maximum_number_of_spots
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('edit_parking_lot.html', lot=lot)
        
        current_spots = len(lot.spots)
        
        if new_max_spots > current_spots:
            # Add new spots
            for i in range(new_max_spots - current_spots):
                spot = ParkingSpot(lot_id=lot.id, status='A')
                db.session.add(spot)
        elif new_max_spots < current_spots:
            # Remove spots (only if they're available)
            spots_to_remove = current_spots - new_max_spots
            available_spots = ParkingSpot.query.filter_by(lot_id=lot.id, status='A').limit(spots_to_remove).all()
            
            if len(available_spots) < spots_to_remove:
                flash('Cannot reduce spots. Some spots are occupied.', 'error')
                return render_template('edit_parking_lot.html', lot=lot)
            
            for spot in available_spots:
                db.session.delete(spot)
        
        lot.maximum_number_of_spots = new_max_spots
        db.session.commit()
        flash('Parking lot updated successfully!', 'success')
        return redirect(url_for('admin_parking_lots'))
    
    return render_template('edit_parking_lot.html', lot=lot)

@app.route('/admin/delete-lot/<int:lot_id>')
@admin_required
def delete_parking_lot(lot_id):
    lot = ParkingLot.query.get_or_404(lot_id)
    
    # Check if any spots are occupied
    occupied_spots = ParkingSpot.query.filter_by(lot_id=lot_id, status='O').count()
    if occupied_spots > 0:
        flash('Cannot delete parking lot. Some spots are occupied.', 'error')
        return redirect(url_for('admin_parking_lots'))
    
    db.session.delete(lot)
    db.session.commit()
    flash('Parking lot deleted successfully!', 'success')
    return redirect(url_for('admin_parking_lots'))

@app.route('/admin/users')
@admin_required
def admin_users():
    search_query = request.args.get('search', '').strip()
    if search_query:
        users = User.query.filter(
            User.is_admin == False,
            (User.username.contains(search_query) |
             User.email.contains(search_query) |
             User.full_name.contains(search_query))
        ).all()
    else:
        users = User.query.filter_by(is_admin=False).all()
    
    # Get reservation count for each user
    user_stats = {}
    for user in users:
        active_reservations = Reservation.query.filter_by(user_id=user.id, is_active=True).count()
        total_reservations = Reservation.query.filter_by(user_id=user.id).count()
        user_stats[user.id] = {
            'active_reservations': active_reservations,
            'total_reservations': total_reservations
        }
    
    return render_template('admin_users.html', users=users, user_stats=user_stats, search_query=search_query)

@app.route('/admin/spots')
@admin_required
def admin_spots():
    search_query = request.args.get('search', '').strip()
    if search_query:
        spots = db.session.query(ParkingSpot, ParkingLot).join(ParkingLot).filter(
            ParkingLot.prime_location_name.contains(search_query) |
            ParkingSpot.id.like(f'%{search_query}%')
        ).all()
    else:
        spots = db.session.query(ParkingSpot, ParkingLot).join(ParkingLot).all()
    
    return render_template('admin_spots.html', spots=spots, search_query=search_query)

@app.route('/admin/reservations')
@admin_required
def admin_reservations():
    reservations = db.session.query(Reservation, User, ParkingSpot, ParkingLot).join(
        User, Reservation.user_id == User.id
    ).join(
        ParkingSpot, Reservation.spot_id == ParkingSpot.id
    ).join(
        ParkingLot, ParkingSpot.lot_id == ParkingLot.id
    ).order_by(Reservation.parking_timestamp.desc()).all()
    
    return render_template('admin_reservations.html', reservations=reservations)

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    lots = ParkingLot.query.all()
    active_reservations = Reservation.query.filter_by(user_id=current_user.id, is_active=True).all()
    
    # Add available spots count for each lot
    for lot in lots:
        lot.available_spots = len([spot for spot in lot.spots if spot.status == 'A'])
    
    return render_template('user_dashboard.html', lots=lots, active_reservations=active_reservations)

@app.route('/user/book-spot/<int:lot_id>', methods=['POST'])
@login_required
def book_spot(lot_id):
    vehicle_number = request.form['vehicle_number'].strip().upper()
    
    # Validation
    if not validate_vehicle_number(vehicle_number):
        flash('Please enter a valid vehicle number (e.g., MH12AB1234).', 'error')
        return redirect(url_for('user_dashboard'))
    
    # Check if user already has an active reservation
    existing_reservation = Reservation.query.filter_by(user_id=current_user.id, is_active=True).first()
    if existing_reservation:
        flash('You already have an active parking reservation. Please release it first.', 'error')
        return redirect(url_for('user_dashboard'))
    
    # Find first available spot in the lot
    available_spot = ParkingSpot.query.filter_by(lot_id=lot_id, status='A').first()
    
    if not available_spot:
        flash('No available spots in this parking lot.', 'error')
        return redirect(url_for('user_dashboard'))
    
    # Create reservation
    reservation = Reservation(
        spot_id=available_spot.id,
        user_id=current_user.id,
        vehicle_number=vehicle_number,
        parking_cost=0  # Will be calculated when leaving
    )
    
    # Update spot status
    available_spot.status = 'O'
    
    db.session.add(reservation)
    db.session.commit()
    
    flash('Parking spot booked successfully!', 'success')
    return redirect(url_for('user_dashboard'))

@app.route('/user/release-spot/<int:reservation_id>')
@login_required
def release_spot(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)
    
    if reservation.user_id != current_user.id:
        flash('Unauthorized action.', 'error')
        return redirect(url_for('user_dashboard'))
    
    # Calculate parking cost and duration
    if reservation.parking_timestamp:
        leaving_time = datetime.utcnow()
        duration = leaving_time - reservation.parking_timestamp
        hours = duration.total_seconds() / 3600
        lot = ParkingLot.query.get(reservation.spot.lot_id)
        cost = hours * lot.price
        
        reservation.parking_cost = round(cost, 2)
        reservation.duration_hours = round(hours, 2)
        reservation.leaving_timestamp = leaving_time
    
    # Update reservation and spot
    reservation.is_active = False
    reservation.spot.status = 'A'
    
    db.session.commit()
    
    flash(f'Parking spot released. Duration: {reservation.duration_hours} hours. Total cost: ₹{reservation.parking_cost}', 'success')
    return redirect(url_for('user_dashboard'))

@app.route('/user/history')
@login_required
def user_history():
    reservations = Reservation.query.filter_by(user_id=current_user.id).order_by(Reservation.parking_timestamp.desc()).all()
    
    # Calculate total statistics
    total_spent = sum(r.parking_cost or 0 for r in reservations if not r.is_active)
    total_hours = sum(r.duration_hours or 0 for r in reservations if not r.is_active)
    
    return render_template('user_history.html', 
                         reservations=reservations, 
                         total_spent=total_spent,
                         total_hours=total_hours)

# API Routes
@app.route('/api/lots', methods=['GET'])
def api_lots():
    lots = ParkingLot.query.all()
    return jsonify([{
        'id': lot.id,
        'name': lot.prime_location_name,
        'price': lot.price,
        'address': lot.address,
        'pin_code': lot.pin_code,
        'max_spots': lot.maximum_number_of_spots,
        'available_spots': len([spot for spot in lot.spots if spot.status == 'A'])
    } for lot in lots])

@app.route('/api/spots/<int:lot_id>', methods=['GET'])
def api_spots(lot_id):
    spots = ParkingSpot.query.filter_by(lot_id=lot_id).all()
    return jsonify([{
        'id': spot.id,
        'status': spot.status,
        'lot_id': spot.lot_id
    } for spot in spots])

@app.route('/api/reservations', methods=['GET'])
@login_required
def api_reservations():
    if current_user.is_admin:
        reservations = Reservation.query.all()
    else:
        reservations = Reservation.query.filter_by(user_id=current_user.id).all()
    
    return jsonify([{
        'id': r.id,
        'user_id': r.user_id,
        'spot_id': r.spot_id,
        'vehicle_number': r.vehicle_number,
        'parking_timestamp': r.parking_timestamp.isoformat() if r.parking_timestamp else None,
        'leaving_timestamp': r.leaving_timestamp.isoformat() if r.leaving_timestamp else None,
        'parking_cost': r.parking_cost,
        'duration_hours': r.duration_hours,
        'is_active': r.is_active
    } for r in reservations])

@app.route('/api/stats')
@login_required
def api_stats():
    if current_user.is_admin:
        # Admin stats
        total_lots = ParkingLot.query.count()
        total_spots = ParkingSpot.query.count()
        occupied_spots = ParkingSpot.query.filter_by(status='O').count()
        total_users = User.query.filter_by(is_admin=False).count()
        total_reservations = Reservation.query.count()
        
        # Monthly reservation data for charts
        monthly_data = db.session.query(
            db.func.strftime('%Y-%m', Reservation.parking_timestamp).label('month'),
            db.func.count(Reservation.id).label('count')
        ).group_by('month').limit(12).all()
        
        return jsonify({
            'total_lots': total_lots,
            'total_spots': total_spots,
            'occupied_spots': occupied_spots,
            'available_spots': total_spots - occupied_spots,
            'total_users': total_users,
            'total_reservations': total_reservations,
            'monthly_reservations': [{'month': m.month, 'count': m.count} for m in monthly_data]
        })
    else:
        # User stats
        user_reservations = Reservation.query.filter_by(user_id=current_user.id).all()
        total_spent = sum(r.parking_cost or 0 for r in user_reservations if not r.is_active)
        total_hours = sum(r.duration_hours or 0 for r in user_reservations if not r.is_active)
        
        return jsonify({
            'total_reservations': len(user_reservations),
            'active_reservations': len([r for r in user_reservations if r.is_active]),
            'total_spent': total_spent,
            'total_hours': total_hours
        })

if __name__ == '__main__':
    create_tables()
    app.run(debug=True)