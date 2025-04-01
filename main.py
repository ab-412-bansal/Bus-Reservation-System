from flask import *
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"]="sqlite:///db.sqlite"
app.config["SECRET_KEY"]="2210993778"
db = SQLAlchemy()

bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'student' or 'admin'

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash.encode('utf-8'), password.encode('utf-8'))



class Bus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bus_name = db.Column(db.String(100), nullable=False)
    total_seats = db.Column(db.Integer, nullable=False)
    routes = db.relationship('Route', backref='bus', lazy=True)
    reservations = db.relationship('Reservation', backref='bus', lazy=True)

class Route(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    starting_point = db.Column(db.String(100), nullable=False)
    end_point = db.Column(db.String(100), nullable=False)
    departure_time = db.Column(db.Time, nullable=False)
    arrival_time = db.Column(db.Time, nullable=False)
    bus_id = db.Column(db.Integer, db.ForeignKey('bus.id'), nullable=False)

class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    route_id = db.Column(db.Integer, db.ForeignKey('route.id'), nullable=False)
    bus_id = db.Column(db.Integer, db.ForeignKey('bus.id'), nullable=False)  # Add a foreign key for bus
    reservation_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)



db.init_app(app)

with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        user = User.query.filter_by(username=username, role=role).first()
        if user and user.check_password(password):
            login_user(user)
            if role == 'student':
                return redirect(url_for('student_reserve'))
            elif role == 'admin':
                return redirect(url_for('register_bus'))
        else:
            msg='Invalid username, password, or role'
            return render_template('login.html',message=msg)
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        name = request.form['name']
        role = request.form['role']
        if User.query.filter_by(username=username, role=role, name=name).first():
            msg = 'Username already exists'
            return render_template('signup.html',message=msg)
        else:
            user = User(username=username, role=role, name=name)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            msg = 'Account created successfully'
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/student/reserve', methods=['GET', 'POST'])
@login_required
def student_reserve():
    buses = Bus.query.all()  # Fetch all available buses
    return render_template('available_buses.html', buses=buses)

@app.route('/confirm_booking/<int:bus_id>', methods=['GET', 'POST'])
@login_required
def confirm_booking(bus_id):
    bus = Bus.query.get_or_404(bus_id)
    if request.method == 'POST':
        username = current_user.username
        password = request.form['password']
        num_seats = int(request.form['num_seats'])
        if not current_user.check_password(password):
            flash('Invalid password', 'error')
            return redirect(url_for('confirm_booking', bus_id=bus_id))
        elif num_seats <= 0:
            flash('Number of seats must be greater than zero', 'error')
            return redirect(url_for('confirm_booking', bus_id=bus_id))
        elif num_seats > (bus.total_seats - len(bus.reservations)):
            flash('Not enough seats available', 'error')
            return redirect(url_for('confirm_booking', bus_id=bus_id))
        else:
            # Create reservation
            reservation = Reservation(user_id=current_user.id, route_id=bus.routes[0].id, bus_id=bus.id)
            db.session.add(reservation)
            db.session.commit()
            flash('Booking confirmed successfully', 'success')
            return redirect(url_for('ticket', bus_id=bus_id,num_seats=num_seats,route_id=bus.routes[0].id))
    return render_template('confirm_booking.html', bus=bus)

@app.route('/view_reservations', methods=['GET'])
@login_required
def view_reservations():
    # Get reservations made by the current user
    reservations = Reservation.query.filter_by(user_id=current_user.id).all()
    return render_template('view_reservations.html', reservations=reservations)

@app.route('/ticket/<int:bus_id>/<int:num_seats>/<int:route_id>')
@login_required
def ticket(bus_id,num_seats,route_id):
    bus = Bus.query.filter_by(id=bus_id).first()
    route = Route.query.filter_by(id=route_id).first()  # Assuming there's only one route per bus for simplicity
    user = current_user
    return render_template('ticket.html', bus=bus, route=route,user=user,num_seats=num_seats)


@app.route('/register_bus', methods=['GET', 'POST'])
@login_required
def register_bus():
    if current_user.role != 'admin':
        flash('You are not authorized to perform this action', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        bus_name = request.form['bus_name']
        total_seats = int(request.form['total_seats'])
        starting_point = request.form['starting_point']
        end_point = request.form['end_point']
        departure_time = datetime.strptime(request.form['departure_time'], '%H:%M').time()
        arrival_time = datetime.strptime(request.form['arrival_time'], '%H:%M').time()

        # Create and add the new bus to the database
        bus = Bus(bus_name=bus_name, total_seats=total_seats)
        db.session.add(bus)
        db.session.commit()

        # Create and add the new route to the database
        route = Route(starting_point=starting_point, end_point=end_point, 
                      departure_time=departure_time, arrival_time=arrival_time, bus_id=bus.id)
        db.session.add(route)
        db.session.commit()

        flash('Bus registered successfully', 'success')
        return redirect(url_for('register_bus'))

    return render_template('register_bus.html')

@app.route('/admin/view_buses', methods=['GET'])
@login_required
def view_buses():
    if current_user.role != 'admin':
        flash('You are not authorized to access this page', 'error')
        return redirect(url_for('index'))
    
    buses = Bus.query.all()
    return render_template('view_buses.html', buses=buses)

if __name__=='__main__':
    app.run(debug=False)