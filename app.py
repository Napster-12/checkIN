from datetime import datetime, date
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace_this_with_a_strong_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'moepi.sql')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# -------------------- Flask-Mail configuration --------------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'codnellsmall@gmail.com'
app.config['MAIL_PASSWORD'] = 'mrmxmmomvhvfqoee'
app.config['MAIL_DEFAULT_SENDER'] = 'codnellsmall@gmail.com'
mail = Mail(app)

# Token serializer
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# -------------------- Database --------------------
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# -------------------- Models --------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class CheckIn(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    slot = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    date = db.Column(db.Date, nullable=False)
    comment = db.Column(db.String(255), nullable=True)

    user = db.relationship('User', backref='checkins')


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -------------------- Constants --------------------
CHECKIN_SLOTS = ["11:00", "13:00", "16:00"]

# -------------------- Routes --------------------
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form.get('fullname', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')

        if not fullname or not email or not password:
            flash('Please fill all required fields.', 'danger')
            return redirect(url_for('register'))

        if not email.endswith('@tekete.co.za'):
            flash('Only work emails ending with @tekete.co.za are allowed.', 'danger')
            return redirect(url_for('register'))

        parts = email.split('@')[0].split('.')
        if len(parts) != 2:
            flash('Email must be in the format name.surname@tekete.co.za.', 'danger')
            return redirect(url_for('register'))

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        existing = User.query.filter_by(email=email).first()
        if existing:
            flash('An account with that email already exists.', 'danger')
            return redirect(url_for('register'))

        user = User(fullname=fullname, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))

        login_user(user)
        flash('Logged in successfully.', 'success')
        return redirect(url_for('admin_dashboard') if user.is_admin else url_for('dashboard'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('home'))

# -------------------- Forgot Password --------------------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(user.email, salt='password-reset-salt')
            reset_link = url_for('reset_password', token=token, _external=True)

            msg = Message('Password Reset Request', recipients=[user.email])
            msg.body = f"Hi {user.fullname},\n\nClick the link below to reset your password:\n{reset_link}\n\nIf you didn't request this, ignore this email."
            mail.send(msg)

        flash('If this email exists, a password reset link has been sent.', 'info')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))

        user = User.query.filter_by(email=email).first()
        if user:
            user.set_password(password)
            db.session.commit()
            flash('Your password has been reset. You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# -------------------- Employee Dashboard --------------------
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

    now = datetime.now()
    slot_states = {}
    for slot in CHECKIN_SLOTS:
        already = CheckIn.query.filter_by(
            user_id=current_user.id, slot=slot, date=now.date()
        ).first()
        slot_states[slot] = {'already': bool(already), 'comment': already.comment if already else None}

    recent = CheckIn.query.filter_by(user_id=current_user.id)\
        .order_by(CheckIn.timestamp.desc())\
        .limit(20).all()

    return render_template('dashboard.html', slot_states=slot_states, now=now, recent=recent)


@app.route('/checkin/<slot>', methods=['POST'])
@login_required
def checkin(slot):
    if slot not in CHECKIN_SLOTS:
        flash('Invalid check-in slot.', 'danger')
        return redirect(url_for('dashboard'))

    comment = request.form.get('comment', '').strip()
    now = datetime.now()

    existing = CheckIn.query.filter_by(
        user_id=current_user.id, slot=slot, date=now.date()
    ).first()

    if existing:
        flash(f"You already checked in for {slot} today.", 'warning')
        return redirect(url_for('dashboard'))

    ci = CheckIn(
        user_id=current_user.id,
        slot=slot,
        timestamp=now,
        date=now.date(),
        comment=comment
    )
    db.session.add(ci)
    db.session.commit()
    flash(f"Check-in for {slot} recorded with comment: '{comment}'.", 'success')
    return redirect(url_for('dashboard'))

# -------------------- Admin Dashboard --------------------
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    # Filters
    name_filter = request.form.get('name', '').strip()
    month_filter = request.form.get('month', '')
    year_filter = request.form.get('year', '')

    query = CheckIn.query.join(User)

    if name_filter:
        query = query.filter(User.fullname.ilike(f"%{name_filter}%"))
    if month_filter:
        query = query.filter(db.extract('month', CheckIn.date) == int(month_filter))
    if year_filter:
        query = query.filter(db.extract('year', CheckIn.date) == int(year_filter))

    checkins = query.order_by(CheckIn.date.desc(), CheckIn.timestamp.desc()).all()

    # Metrics
    total_checkins = len(checkins)
    overall_check = len(CheckIn.query.all())
    highest_checkin_employee = db.session.query(
        User.fullname, db.func.count(CheckIn.id).label('total')
    ).join(CheckIn).group_by(User.id).order_by(db.desc('total')).first()
    earliest_checkin = db.session.query(
        CheckIn
    ).order_by(CheckIn.timestamp.asc()).first()

    return render_template('admin_dashboard.html',
                           checkins=checkins,
                           total_checkins=total_checkins,
                           overall_check=overall_check,
                           highest_checkin_employee=highest_checkin_employee,
                           earliest_checkin=earliest_checkin,
                           name_filter=name_filter,
                           month_filter=month_filter,
                           year_filter=year_filter)

# -------------------- Run --------------------
if __name__ == '__main__':
    app.run(debug=True)
