import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from login_form.db import get_db
from login_form.user import User

bp = Blueprint('auth', __name__, url_prefix='/')

@bp.route('/')
def index():
    return render_template('index.html')

def validate_username(username):
    # Basic validation
    if not username or len(username) < 3 or len(username) > 50:
        return False
    # Only allow letters, numbers, and underscore
    return username.replace('_', '').isalnum()

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        error = None
        if not username:
            error = 'Username is required.'
        elif not validate_username(username):
            error = 'Username can only contain letters, numbers, and underscore.'
        elif not password:
            error = 'Password is required.'
        
        if error is None:
            try:
                User.create(username, password)
                return redirect(url_for('auth.login'))
            except Exception as e:
                error = f"User {username} is already registered."
                
        flash(error)

    return render_template('register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        error = None
        user = User.find_with_credentials(username, password)

        if user is None:
            error = 'Incorrect username or password.'

        if error is None:
            session.clear()
            session['user_id'] = user.id
            return redirect(url_for('auth.index'))

        flash(error)

    return render_template('login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = User.find_by_id(user_id)

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view