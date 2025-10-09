from flask import request, jsonify, render_template, redirect, session
import sqlite3
import secrets
import string
from uuid import uuid4
from functools import wraps
from models import DB_FILE, get_user_by_username, get_user_by_uuid

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('uuid'):
            return redirect('/login')
        
        user = get_user_by_uuid(session['uuid'])
        if not user or user['role'] != '0':
            return jsonify({'error': 'Admin access required'}), 403
            
        return f(*args, **kwargs)
    return decorated_function

def create_auth_routes(app):
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if session.get('uuid'):
            user = get_user_by_uuid(session['uuid'])
            if user:
                return redirect('/home')
            
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            user = get_user_by_username(username)
            if user and user['password'] == password:
                session['uuid'] = user['uuid']
                if user['role'] == '0':
                    return redirect('/admin')
                return redirect('/home')
            return render_template('login.html', error='Invalid credentials')
        return render_template('login.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if session.get('uuid'):
            return redirect('/home')
            
        if request.method == 'POST':
            return render_template('register.html', error='Use the registration form properly.')
        return render_template('register.html')

    @app.route('/confirm-register', methods=['POST'])
    def confirm_register():
        username = request.form['username']
        email = request.form.get('email', '')
        alphabet = string.ascii_letters + string.digits + '!@#$%^&*'
        password = ''.join(secrets.choice(alphabet) for _ in range(12))
        role = request.form.get('role', '2')

        role_map = {
            '1': 'editor',
            '2': 'user',
        }

        if role == '0':
            return jsonify({'error': 'Admin registration is not allowed.'}), 403

        if role not in role_map:
            return jsonify({'error': 'Invalid role id.'}), 400

        uid = str(uuid4())

        try:
            with sqlite3.connect(DB_FILE) as db:
                db.execute('INSERT INTO users (uuid, username, email, password, role) VALUES (?, ?, ?, ?, ?)',
                           (uid, username, email, password, role))
                db.commit()
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username already exists.'}), 400

        session['uuid'] = uid
        session['first_login'] = True
        session['first_login_password'] = password

        return jsonify({
            'success': True,
            'redirect': '/home'
        }), 200

    @app.route('/logout')
    def logout():
        session.clear()
        return redirect('/')