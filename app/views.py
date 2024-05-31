from flask import render_template, url_for, flash, redirect, request
from app import app, db, bcrypt
from flask_login import login_user, current_user, logout_user, login_required
from app.utils import is_superadmin, is_admin, is_user, has_permission

from app.models import User, Role, Permission  # Correctly import Role and Permission


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role_name = request.form.get('role_name')

        role = Role.query.filter_by(role_name=role_name).first()
        if not role:
            flash('Invalid role.', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password_hash=hashed_password, role=role)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/home')
@login_required
def home():
    return render_template('home.html', title='Home')

@app.route('/manage_roles', methods=['GET', 'POST'])
@login_required
def manage_roles():
    if not is_superadmin(current_user):
        flash('Access denied. Only Superadmins can access this page.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        # Add role management code here
        pass

    roles = Role.query.all()
    permissions = Permission.query.all()
    return render_template('manage_roles.html', roles=roles, permissions=permissions)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not is_admin(current_user):
        flash('Access denied. Only admins can access this page.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        # Add admin-specific code here
        pass

    return render_template('admin.html')

@app.route('/user', methods=['GET', 'POST'])
@login_required
def user():
    if not is_user(current_user):
        flash('Access denied. Only users can access this page.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        # Add user-specific code here
        pass

    return render_template('user.html')


@app.route("/admin_dashboard")
@login_required
def admin_dashboard():
    if not current_user.has_permission('view_user'):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))
    return render_template('admin_dashboard.html')

@app.route("/create_user", methods=['GET', 'POST'])
@login_required
def create_user():
    if not current_user.has_permission('create_user'):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))
    # Logic for creating a user
    return render_template('create_user.html')

# Other routes and logic
