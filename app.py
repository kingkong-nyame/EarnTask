from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FloatField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Email
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Setup logging
logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)  # Plain text password
    balance = db.Column(db.Float, default=0.0)
    profile_picture = db.Column(db.String(120), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    tasks = db.relationship('UserTask', backref='user', lazy=True)
    withdrawals = db.relationship('Withdrawal', backref='user', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    reward = db.Column(db.Float, nullable=False)

class UserTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    tiktok_clicked = db.Column(db.Boolean, default=False)
    instagram_clicked = db.Column(db.Boolean, default=False)
    youtube_clicked = db.Column(db.Boolean, default=False)
    twitter_clicked = db.Column(db.Boolean, default=False)
    linkedin_clicked = db.Column(db.Boolean, default=False)
    snapchat_clicked = db.Column(db.Boolean, default=False)

class Withdrawal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')
    requested_at = db.Column(db.DateTime, default=datetime.utcnow)

# WTForms
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ProfileForm(FlaskForm):
    username = StringField('Username')
    current_password = PasswordField('Current Password')
    new_password = PasswordField('New Password')
    submit = SubmitField('Update Profile')

class WithdrawForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired()])
    submit = SubmitField('Withdraw')

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception as e:
        logging.error(f"Error loading user {user_id}: {str(e)}")
        return None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            username = form.username.data
            email = form.email.data
            password = form.password.data
            if User.query.filter_by(username=username).first():
                flash('Username already exists!')
                return redirect(url_for('register'))
            if User.query.filter_by(email=email).first():
                flash('Email already registered!')
                return redirect(url_for('register'))
            user = User(
                username=username,
                email=email,
                password=password,  # Store plain text password
                balance=5.0,
                is_admin=(username == 'admin'),
                registered_at=datetime.utcnow()
            )
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! You can now log in.')
            logging.info(f"User {username} registered successfully")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Registration error: {str(e)}")
            flash('An error occurred during registration. Please try again.')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            username = form.username.data
            password = form.password.data
            user = User.query.filter_by(username=username).first()
            if user and user.password == password:  # Direct comparison
                login_user(user)
                logging.info(f"User {user.username} logged in successfully")
                return redirect(url_for('dashboard'))
            else:
                logging.warning(f"Failed login attempt for username: {username}")
                flash('Invalid username or password!')
        except Exception as e:
            logging.error(f"Login error: {str(e)}")
            flash('An error occurred during login. Please try again.')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logging.info(f"User {current_user.username} logged out")
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    all_tasks = [
        {
            'id': 1,
            'name': 'Social Media Engagement 1',
            'description': 'Follow, like, and comment on the specified TikTok, Instagram, and YouTube accounts.',
            'reward': 20.0,
            'details': {
                'tiktok': {'url': 'https://www.tiktok.com/@emjudecodingtech?_t=ZM-8wJvcqficBJ&_r=1', 'actions': 'Follow, like, and comment on the latest video'},
                'instagram': {'url': 'https://www.instagram.com/emjudecodingtech?igsh=ajBmenNoM29tcmln&utm_source=qr', 'actions': 'Follow, like, and comment on the latest post'},
                'youtube': {'url': 'https://youtube.com/@emjude_coding_tech?si=8hJKAP3sdHTPDI9T', 'actions': 'Like, comment, and subscribe to the channel'}
            }
        },
        {
            'id': 2,
            'name': 'Social Media Engagement 2',
            'description': 'Follow, like, and comment on the specified TikTok, Instagram, and YouTube accounts.',
            'reward': 20.0,
            'details': {
                'tiktok': {'url': 'https://www.tiktok.com/@emjude2?_t=ZM-8wSNkHMTFtW&_r=1', 'actions': 'Follow, like, and comment on the latest video'},
                'instagram': {'url': 'https://www.instagram.com/emjudecodingtech?igsh=ajBmenNoM29tcmln&utm_source=qr', 'actions': 'Follow, like, and comment on the latest post'},
                'youtube': {'url': 'https://youtube.com/@forexfalcon3040?si=6FXl_lwv4hyaoMhd', 'actions': 'Like, comment, and subscribe to the channel'}
            }
        },
        {
            'id': 3,
            'name': 'Social Media Engagement 3',
            'description': 'Follow, like, and comment on the specified Twitter, Instagram, and YouTube accounts.',
            'reward': 20.0,
            'details': {
                'twitter': {'url': 'https://x.com/emjudecoding?s=21', 'actions': 'Follow, like, and comment on the latest tweet'},
                'instagram': {'url': 'https://www.instagram.com/emjudecodingtech?igsh=ajBmenNoM29tcmln&utm_source=qr', 'actions': 'Follow, like, and comment on the latest post'},
                'tiktok': {'url': 'https://www.tiktok.com/@kiitotech?_t=ZM-8wScc7WLdpN&_r=1', 'actions': 'Follow, like, and comment on the latest video'}
            }
        },
        {
            'id': 4,
            'name': 'Social Media Engagement 4',
            'description': 'Follow, like, and comment on the specified Twitter, TikTok, and YouTube accounts.',
            'reward': 20.0,
            'details': {
                'tiktok': {'url': 'https://www.tiktok.com/@footprintfx1?_t=ZM-8wST45939eB&_r=1', 'actions': 'Follow, like, and comment on the latest video'},
                'tiktok': {'url': 'https://www.tiktok.com/@vintage_vogue_legacy?_t=ZM-8wSc9rWjQu7&_r=1', 'actions': 'Follow, like, and comment on the latest video'},
                'youtube': {'url': 'http://www.youtube.com/@alphahaze4506', 'actions': 'Like, comment, and subscribe to the channel'}
            }
        },
        {
            'id': 5,
            'name': 'Social Media Engagement 5',
            'description': 'Follow, like, and comment on the specified LinkedIn, Instagram, and YouTube accounts.',
            'reward': 20.0,
            'details': {
                'linkedin': {'url': 'https://www.linkedin.com/in/emmanuel-nti-gyimah-9a18b5238?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=ios_app', 'actions': 'Follow, like, and comment on the latest post'},
                'instagram': {'url': 'https://www.instagram.com/emjudecodingtech?igsh=ajBmenNoM29tcmln&utm_source=qr', 'actions': 'Follow, like, and comment on the latest post'},
                'youtube': {'url': 'https://www.youtube.com/@kiitotech7874', 'actions': 'Like, comment, and subscribe to the channel'}
            }
        },
        {
            'id': 6,
            'name': 'Social Media Engagement 6',
            'description': 'Follow, like, and comment on the specified Snapchat, Instagram, and YouTube accounts.',
            'reward': 20.0,
            'details': {
                'telegram': {'url': 'https://t.me/onestopgoodies', 'actions': 'Follow, like, and comment on the latest story'},
                'instagram': {'url': 'https://www.instagram.com/emjudecodingtech?igsh=ajBmenNoM29tcmln&utm_source=qr', 'actions': 'Follow, like, and comment on the latest post'},
                'youtube': {'url': 'https://youtube.com/@emjude_coding_tech?si=8hJKAP3sdHTPDI9T', 'actions': 'Like, comment, and subscribe to the channel'}
            }
        },
        {
            'id': 7,
            'name': 'Quantum Cipher Challenge',
            'description': 'Decode an encrypted message intercepted from a quantum communication channel.',
            'reward': 50.0,
            'details': {
                'instructions': 'Decode the cipher text: "QZFMPXJHLTKAFHGVU". This message was encrypted using a quantum-based one-time pad with an unknown key of infinite length. No key or additional context is provided. Submit the plaintext.',
                'cipher_text': 'QZFMPXJHLTKAFHGVU'
            }
        }
    ]

    form = WithdrawForm()

    try:
        # Initialize tasks in the database
        for task_data in all_tasks:
            if not db.session.get(Task, task_data['id']):
                task = Task(id=task_data['id'], name=task_data['name'], description=task_data['description'], reward=task_data['reward'])
                db.session.add(task)
        db.session.commit()

        # Ensure UserTask entries exist
        for task_data in all_tasks:
            if not UserTask.query.filter_by(user_id=current_user.id, task_id=task_data['id']).first():
                user_task = UserTask(user_id=current_user.id, task_id=task_data['id'], completed=False)
                db.session.add(user_task)
        db.session.commit()

        # Calculate current day since registration (1-based)
        days_since_registration = (datetime.utcnow() - current_user.registered_at).days + 1
        current_task_day = min(days_since_registration, 7)  # Cap at day 7

        # Filter tasks to show only the task for the current day
        tasks_to_show = []
        for task in all_tasks:
            if task['id'] == current_task_day:
                user_task = UserTask.query.filter_by(user_id=current_user.id, task_id=task['id']).first()
                task['status'] = {
                    'completed': user_task.completed,
                    'tiktok_clicked': user_task.tiktok_clicked,
                    'instagram_clicked': user_task.instagram_clicked,
                    'youtube_clicked': user_task.youtube_clicked,
                    'twitter_clicked': user_task.twitter_clicked,
                    'linkedin_clicked': user_task.linkedin_clicked,
                    'telegram_clicked': user_task.telegram_clicked
                }
                tasks_to_show.append(task)
                break

        # Get completed tasks for history
        completed_tasks = []
        user_tasks = UserTask.query.filter_by(user_id=current_user.id).all()
        for ut in user_tasks:
            if ut.completed:
                task = db.session.get(Task, ut.task_id)
                completed_tasks.append({
                    'name': task.name,
                    'reward': task.reward,
                    'completed_at': ut.completed_at.strftime('%Y-%m-%d %H:%M:%S') if ut.completed_at else 'Unknown'
                })

        logging.info(f"Dashboard loaded for user {current_user.username}, day {current_task_day}")
        return render_template('dashboard.html', tasks=tasks_to_show, user=current_user, completed_tasks=completed_tasks, form=form, current_task_day=current_task_day)
    except Exception as e:
        logging.error(f"Dashboard error: {str(e)}")
        flash('An error occurred while loading the dashboard. Please try again.')
        return redirect(url_for('index'))

@app.route('/track_link/<int:task_id>/<platform>', methods=['POST'])
@login_required
def track_link(task_id, platform):
    try:
        user_task = UserTask.query.filter_by(user_id=current_user.id, task_id=task_id).first()
        if user_task and task_id in [1, 2, 3, 4, 5, 6]:
            if platform == 'tiktok':
                user_task.tiktok_clicked = True
            elif platform == 'instagram':
                user_task.instagram_clicked = True
            elif platform == 'youtube':
                user_task.youtube_clicked = True
            elif platform == 'twitter':
                user_task.twitter_clicked = True
            elif platform == 'linkedin':
                user_task.linkedin_clicked = True
            elif platform == 'telegram':
                user_task.snapchat_clicked = True
            db.session.commit()
            logging.info(f"Tracked {platform} link click for task {task_id} by user {current_user.username}")
        return '', 204
    except Exception as e:
        logging.error(f"Track link error: {str(e)}")
        return '', 500

@app.route('/complete_task/<int:task_id>', methods=['POST'])
@login_required
def complete_task(task_id):
    try:
        user_task = UserTask.query.filter_by(user_id=current_user.id, task_id=task_id).first()
        if not user_task or user_task.completed:
            flash('Task already completed or invalid!')
            return redirect(url_for('dashboard'))

        task_rewards = {1: 20.0, 2: 20.0, 3: 20.0, 4: 20.0, 5: 20.0, 6: 20.0, 7: 50.0}
        if task_id not in task_rewards:
            flash('Invalid task!')
            return redirect(url_for('dashboard'))

        if task_id in [1, 2]:
            if not (user_task.tiktok_clicked and user_task.instagram_clicked and user_task.youtube_clicked):
                flash('You must click all social media links before completing this task!')
                return redirect(url_for('dashboard'))
        elif task_id == 3:
            if not (user_task.twitter_clicked and user_task.instagram_clicked and user_task.youtube_clicked):
                flash('You must click all social media links before completing this task!')
                return redirect(url_for('dashboard'))
        elif task_id == 4:
            if not (user_task.twitter_clicked and user_task.tiktok_clicked and user_task.youtube_clicked):
                flash('You must click all social media links before completing this task!')
                return redirect(url_for('dashboard'))
        elif task_id == 5:
            if not (user_task.linkedin_clicked and user_task.instagram_clicked and user_task.youtube_clicked):
                flash('You must click all social media links before completing this task!')
                return redirect(url_for('dashboard'))
        elif task_id == 6:
            if not (user_task.snapchat_clicked and user_task.instagram_clicked and user_task.youtube_clicked):
                flash('You must click all social media links before completing this task!')
                return redirect(url_for('dashboard'))
        elif task_id == 7:
            cipher_solution = request.form.get('cipher_solution')
            if not cipher_solution:
                flash('Please provide a cipher solution!')
                return redirect(url_for('dashboard'))
            # Intentionally unsolvable, so reject all solutions
            flash('Incorrect solution. This quantum cipher cannot be decoded with the given information.')
            return redirect(url_for('dashboard'))

        user_task.completed = True
        user_task.completed_at = datetime.utcnow()
        current_user.balance += task_rewards[task_id]
        db.session.commit()
        flash(f'Task completed! You earned GH₵{task_rewards[task_id]}')
        logging.info(f"Task {task_id} completed by user {current_user.username}, earned GH₵{task_rewards[task_id]}")
        return redirect(url_for('dashboard'))
    except Exception as e:
        db.session.rollback()
        logging.error(f"Complete task error: {str(e)}")
        flash('An error occurred while completing the task. Please try again.')
        return redirect(url_for('dashboard'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    if form.validate_on_submit():
        try:
            if form.username.data and form.username.data != current_user.username:
                if User.query.filter_by(username=form.username.data).first():
                    flash('Username already taken!')
                else:
                    current_user.username = form.username.data
                    flash('Username updated successfully!')

            if form.current_password.data and form.new_password.data:
                if current_user.password == form.current_password.data:  # Direct comparison
                    current_user.password = form.new_password.data  # Direct update
                    flash('Password updated successfully!')
                else:
                    flash('Current password is incorrect!')

            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"{current_user.id}_{file.filename}")
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    current_user.profile_picture = filename
                    flash('Profile picture updated successfully!')
                else:
                    flash('Invalid file format! Only PNG, JPG, JPEG allowed.')

            db.session.commit()
            logging.info(f"Profile updated for user {current_user.username}")
        except Exception as e:
            db.session.rollback()
            logging.error(f"Profile update error: {str(e)}")
            flash('An error occurred while updating your profile. Please try again.')
        return redirect(url_for('profile'))

    withdrawals = Withdrawal.query.filter_by(user_id=current_user.id).order_by(Withdrawal.requested_at.desc()).all()
    return render_template('profile.html', user=current_user, withdrawals=withdrawals, form=form)

@app.route('/withdraw', methods=['POST'])
@login_required
def withdraw():
    form = WithdrawForm()
    if form.validate_on_submit():
        try:
            # Check if all 7 tasks are completed
            completed_tasks = UserTask.query.filter_by(user_id=current_user.id, completed=True).count()
            if completed_tasks < 7:
                flash('You must complete all 7 tasks before withdrawing!')
                return redirect(url_for('dashboard'))

            amount = form.amount.data
            if amount < 10:
                flash('Minimum withdrawal amount is GH₵10!')
                return redirect(url_for('dashboard'))
            if amount > current_user.balance:
                flash('Insufficient balance!')
                return redirect(url_for('dashboard'))
            
            withdrawal = Withdrawal(user_id=current_user.id, amount=amount)
            current_user.balance -= amount
            db.session.add(withdrawal)
            db.session.commit()
            flash(f'Withdrawal request for GH₵{amount} submitted successfully!')
            logging.info(f"Withdrawal request for GH₵{amount} submitted by user {current_user.username}")
        except Exception as e:
            db.session.rollback()
            logging.error(f"Withdrawal error: {str(e)}")
            flash('An error occurred while processing your withdrawal. Please try again.')
    else:
        flash('Invalid withdrawal amount!')
    return redirect(url_for('dashboard'))

@app.route('/admin/withdrawals', methods=['GET', 'POST'])
@login_required
def admin_withdrawals():
    if not current_user.is_admin:
        flash('Access denied: Admins only!')
        return redirect(url_for('dashboard'))
    
    try:
        if request.method == 'POST':
            withdrawal_id = request.form.get('withdrawal_id')
            action = request.form.get('action')
            withdrawal = db.session.get(Withdrawal, withdrawal_id)
            if withdrawal:
                if action == 'approve':
                    withdrawal.status = 'completed'
                    flash(f'Withdrawal GH₵{withdrawal.amount} approved!')
                elif action == 'reject':
                    withdrawal.status = 'rejected'
                    withdrawal.user.balance += withdrawal.amount
                    flash(f'Withdrawal GH₵{withdrawal.amount} rejected and refunded!')
                db.session.commit()
                logging.info(f"Withdrawal {withdrawal_id} {action}d by admin {current_user.username}")
        
        withdrawals = Withdrawal.query.join(User).all()
        return render_template('admin_withdrawals.html', withdrawals=withdrawals)
    except Exception as e:
        logging.error(f"Admin withdrawals error: {str(e)}")
        flash('An error occurred while processing withdrawals. Please try again.')
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print("Starting Flask server at http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)