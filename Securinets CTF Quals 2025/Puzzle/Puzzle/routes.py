from flask import request, jsonify, render_template, redirect, send_from_directory, session, render_template_string, send_file, abort
import sqlite3
import os
import ipaddress
from uuid import uuid4
from pathlib import Path
from datetime import datetime
from models import DB_FILE, DB_DIR, DATA_DIR, get_user_by_username, get_user_by_uuid
from auth import admin_required

def is_localhost():
    client_ip = request.remote_addr
    try:
        ip = ipaddress.ip_address(client_ip)
        return ip.is_loopback
    except ValueError:
        return False

def create_main_routes(app):
    @app.route('/static/<path:path>')
    def send_static(path):
        return send_from_directory('static', path)

    @app.route('/')
    def index():
        if session.get('uuid'):
            return redirect('/home')
        return render_template('index.html')

    @app.route('/home')
    def home():
        if not session.get('uuid'):
            return redirect('/login')
        
        user = get_user_by_uuid(session['uuid'])
        if not user:
            return redirect('/login')
        
        first_login_password = None
        if session.get('first_login'):
            first_login_password = session.get('first_login_password')
            session.pop('first_login', None)
            session.pop('first_login_password', None)
        
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            c.execute("""
                SELECT 
                    articles.*,
                    author.username as author_name,
                    author.uuid as author_uuid,
                    collab.username as collaborator_name,
                    collab.uuid as collaborator_uuid
                FROM articles 
                JOIN users author ON articles.author_uuid = author.uuid 
                LEFT JOIN users collab ON articles.collaborator_uuid = collab.uuid
                WHERE articles.author_uuid = ? OR articles.collaborator_uuid = ?
                ORDER BY articles.created_at DESC
            """, (session['uuid'], session['uuid']))
            
            articles = [dict(row) for row in c.fetchall()]
            
            c.execute("SELECT COUNT(*) FROM articles WHERE author_uuid = ?", (session['uuid'],))
            article_count = c.fetchone()[0]
            
        return render_template('home.html', articles=articles, article_count=article_count, first_login_password=first_login_password)

    @app.route('/profile')
    def profile():
        uuid_ = session.get('uuid')
        if not uuid_:
            return redirect('/login')

        user = get_user_by_uuid(uuid_)
        if not user:
            return redirect('/login')

        return render_template('profile.html', user=user)

    @app.route('/publish', methods=['GET', 'POST'])
    def publish():
        if not session.get('uuid'):
            return redirect('/login')
    
        user = get_user_by_uuid(session['uuid'])
        if not user:
            return redirect('/login')
        
        if user['role'] == '0':
            return jsonify({'error': 'Admins cannot publish articles'}), 403
        
        if request.method == 'POST':
            title = request.form.get('title')
            content = request.form.get('content')
            collaborator = request.form.get('collaborator')
            
            if not title or not content:
                return jsonify({'error': 'Title and content are required'}), 400
            
            try:
                with sqlite3.connect(DB_FILE) as conn:
                    c = conn.cursor()
                    c.execute("SELECT COUNT(*) FROM articles WHERE author_uuid = ?", (session['uuid'],))
                    article_count = c.fetchone()[0]
                    
                    if (article_count >= 20):
                        return jsonify({'error': 'You have reached the maximum limit of 20 articles'}), 403
                    
                    if collaborator:
                        collab_user = get_user_by_username(collaborator)
                        if not collab_user:
                            return jsonify({'error': 'Collaborator not found'}), 404
                        
                        request_uuid = str(uuid4())
                        article_uuid = str(uuid4())
                        c.execute("""
                            INSERT INTO collab_requests (uuid, article_uuid, title, content, from_uuid, to_uuid)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (request_uuid, article_uuid, title, content, session['uuid'], collab_user['uuid']))
                        conn.commit()
                        return jsonify({'message': 'Collaboration request sent'})
                    else:
                        article_uuid = str(uuid4())
                        c.execute("""
                            INSERT INTO articles (uuid, title, content, author_uuid)
                            VALUES (?, ?, ?, ?)
                        """, (article_uuid, title, content, session['uuid']))
                        conn.commit()
                        return jsonify({'message': 'Article published successfully'})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        return render_template('publish.html')

    @app.route('/article/<string:article_uuid>')
    def view_article(article_uuid):
        if not session.get('uuid'):
            return redirect('/login')
        
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("""
                SELECT 
                    articles.*,
                    author.username as author_name,
                    author.uuid as author_uuid,
                    collab.username as collaborator_name,
                    collab.uuid as collaborator_uuid
                FROM articles 
                JOIN users author ON articles.author_uuid = author.uuid 
                LEFT JOIN users collab ON articles.collaborator_uuid = collab.uuid
                WHERE articles.uuid = ?
            """, (article_uuid,))
            article = c.fetchone()
            
        if not article:
            return 'Article not found', 404
            
        return render_template('article.html', article=dict(article))

    @app.route('/collab/request', methods=['POST'])
    def send_collab():
        if not is_localhost():
            return jsonify({'error': 'Access denied.'}), 403
            
        current_uuid = session.get('uuid')
        if not current_uuid:
            return 'Unauthorized', 401

        user = get_user_by_uuid(session['uuid'])
        if not user:
            return redirect('/login')
        if user['role'] == '0':
            return jsonify({'error': 'Admins cannot collaborate'}), 403
        
        target_username = request.form.get('username')
        target_user = get_user_by_username(target_username)
        if not target_user:
            return 'User not found', 404

        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            query = f"INSERT INTO collab_requests VALUES ('{current_uuid}', '{target_user['uuid']}')"
            c.execute(query)
            conn.commit()

        return jsonify({
            'message': 'Request sent',
            'to_uuid': target_user['uuid']
        })

    @app.route('/collab/requests')
    def view_collabs():
        if not is_localhost():
            return jsonify({'error': 'Access denied.'}), 403
            
        current_uuid = session.get('uuid')
        if not current_uuid:
            return 'Unauthorized', 401
        
        user = get_user_by_uuid(session['uuid'])
        if not user:
            return redirect('/login')
        if user['role'] == '0':
            return jsonify({'error': 'Admins cannot collaborate'}), 403

        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM collab_requests WHERE from_uuid=?", (current_uuid,))
            sent = c.fetchall()
        return jsonify({'sent_requests': sent})

    @app.route('/collaborations')
    def view_collaborations():
        if not session.get('uuid'):
            return redirect('/login')
        
        user = get_user_by_uuid(session['uuid'])
        if not user:
            return redirect('/login')
        if user['role'] == '0':
            return jsonify({'error': 'Admins cannot collaborate'}), 403
        
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            c.execute("""
                SELECT cr.*, u.username as requester_name 
                FROM collab_requests cr
                JOIN users u ON cr.from_uuid = u.uuid
                WHERE cr.to_uuid = ? AND cr.status = 'pending'
            """, (session['uuid'],))
            incoming_requests = [dict(row) for row in c.fetchall()]
            
            c.execute("""
                SELECT cr.*, u.username as recipient_name 
                FROM collab_requests cr
                JOIN users u ON cr.to_uuid = u.uuid
                WHERE cr.from_uuid = ? AND cr.status = 'pending'
            """, (session['uuid'],))
            outgoing_requests = [dict(row) for row in c.fetchall()]
        
        return render_template('collaborations.html', 
                             incoming_requests=incoming_requests,
                             outgoing_requests=outgoing_requests)

    @app.route('/collab/accept/<string:request_uuid>', methods=['POST'])
    def accept_collaboration(request_uuid):
        if not session.get('uuid'):
            return jsonify({'error': 'Unauthorized'}), 401
        
        user = get_user_by_uuid(session['uuid'])
        if not user:
            return redirect('/login')
        if user['role'] == '0':
            return jsonify({'error': 'Admins cannot collaborate'}), 403
        
        try:
            with sqlite3.connect(DB_FILE) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                
                c.execute("SELECT * FROM collab_requests WHERE uuid = ?", (request_uuid,))
                request = c.fetchone()
                
                if not request:
                    return jsonify({'error': 'Request not found'}), 404
                
                c.execute("""
                    INSERT INTO articles (uuid, title, content, author_uuid, collaborator_uuid)
                    VALUES (?, ?, ?, ?, ?)
                """, (request['article_uuid'], request['title'], request['content'], 
                      request['from_uuid'], request['to_uuid']))
                
                c.execute("UPDATE collab_requests SET status = 'accepted' WHERE uuid = ?", (request_uuid,))
                conn.commit()
                
                return jsonify({'message': 'Collaboration accepted'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/users')
    def get_users_error():
        return jsonify({
            'error': 'Missing UUID parameter',
            'usage': '/users/<uuid>'
        }), 500

    @app.route('/users/<string:target_uuid>')
    def get_user_details(target_uuid):
        current_uuid = session.get('uuid')
        if not current_uuid:
            return jsonify({'error': 'Unauthorized'}), 401
        
        current_user = get_user_by_uuid(current_uuid)
        if not current_user or current_user['role'] not in ('0', '1'):
            return jsonify({'error': 'Invalid user role'}), 403
            
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("""
                SELECT uuid, username, email, phone_number, role, password
                FROM users 
                WHERE uuid = ?
            """, (target_uuid,))
            user = c.fetchone()
            
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        return jsonify({
            'uuid': user['uuid'],
            'username': user['username'],
            'email': user['email'],
            'phone_number': user['phone_number'],
            'role': user['role'],
            'password': user['password']
        })

    @app.route('/admin')
    @admin_required
    def admin_panel(ban_message=None):
        try:
            with sqlite3.connect(DB_FILE) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                
                c.execute("""
                    SELECT 
                        COUNT(*) as total_users,
                        SUM(CASE WHEN role = '0' THEN 1 ELSE 0 END) as admin_count,
                        SUM(CASE WHEN role = '1' THEN 1 ELSE 0 END) as editor_count,
                        SUM(CASE WHEN role = '2' THEN 1 ELSE 0 END) as user_count
                    FROM users
                """)
                user_stats = dict(c.fetchone())

                c.execute("""
                    SELECT 
                        COUNT(*) as total_articles,
                        COUNT(DISTINCT author_uuid) as unique_authors,
                        COUNT(DISTINCT collaborator_uuid) as unique_collaborators
                    FROM articles
                """)
                article_stats = dict(c.fetchone())
                
                c.execute("""
                    SELECT 
                        COUNT(*) as total_requests,
                        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_requests,
                        SUM(CASE WHEN status = 'accepted' THEN 1 ELSE 0 END) as accepted_requests
                    FROM collab_requests
                """)
                collab_stats = dict(c.fetchone())
                
                c.execute("""
                    SELECT 
                        articles.*,
                        users.username as author_name
                    FROM articles
                    JOIN users ON articles.author_uuid = users.uuid
                    ORDER BY articles.created_at DESC
                    LIMIT 10
                """)
                recent_articles = [dict(row) for row in c.fetchall()]
                
                return render_template('admin.html',
                                    user_stats=user_stats,
                                    article_stats=article_stats,
                                    collab_stats=collab_stats,
                                    ban_message=ban_message,
                                    recent_articles=recent_articles)
                
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/admin/ban_user', methods=['POST'])
    @admin_required
    def ban_user():
        def is_safe_input(user_input):
            blacklist = [
            '__', 'subclasses', 'self', 'request', 'session',
            'config', 'os', 'import', 'builtins', 'eval', 'exec', 'compile',
            'globals', 'locals', 'vars', 'delattr', 'getattr', 'setattr', 'hasattr',
            'base', 'init', 'new', 'dict', 'tuple', 'list', 'object', 'type',
            'repr', 'str', 'bytes', 'bytearray', 'format', 'input', 'help',
            'file', 'open', 'read', 'write', 'close', 'seek', 'flush', 'popen',
            'system', 'subprocess', 'shlex', 'commands', 'marshal', 'pickle', 'tempfile',
            'os.system', 'subprocess.Popen', 'shutil', 'pathlib', 'walk', 'stat',
            '[', '(', ')', '|', '%','_', '"','<', '>','~'
            ]
            lower_input = user_input.lower()
            return not any(bad in lower_input for bad in blacklist)

        username = request.form.get('username', '')

        if not is_safe_input(username):
            return admin_panel(ban_message='Blocked input.'), 400

        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = c.fetchone()

        if not user:
            template = 'User {} does not exist.'.format(username)
        else:
            template = 'User account {} is too recent to be banned'.format(username)

        ban_message = render_template_string(template)

        return admin_panel(ban_message=ban_message), 200

    @app.route('/db')
    def list_db_files():
        """Public directory listing for /db"""
        files = []
        for file in Path(DB_DIR).glob('*'):
            if file.is_file():
                files.append({
                    'name': file.name,
                    'size': file.stat().st_size,
                    'modified': datetime.fromtimestamp(file.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                })
        
        return render_template('directory.html', 
                             path='/db',
                             files=files,
                             is_public=True)

    @app.route('/data')
    @admin_required
    def list_data_files():
        files = []
        for file in Path(DATA_DIR).glob('*'):
            if file.is_file():
                files.append({
                    'name': file.name,
                    'size': file.stat().st_size,
                    'modified': datetime.fromtimestamp(file.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                })
        
        return render_template('directory.html', 
                             path='/data',
                             files=files,
                             is_public=False)

    @app.route('/data/', defaults={'req_path': ''})
    @app.route('/data/<path:req_path>')
    @admin_required
    def serve_data(req_path):
        abs_path = os.path.abspath(os.path.join(DATA_DIR, req_path))
        data_dir_abs = os.path.abspath(DATA_DIR)
        if os.path.commonpath([data_dir_abs, abs_path]) != data_dir_abs:
            return abort(403)

        if not os.path.exists(abs_path):
            return abort(404)

        if os.path.isfile(abs_path):
            return send_file(abs_path)

        files = []
        for file in os.listdir(abs_path):
            file_path = os.path.join(abs_path, file)
            stats = os.stat(file_path)
            files.append({
                'name': file,
                'size': stats.st_size,
                'modified': datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            })

        return render_template('directory.html', 
                             path=f'/data/{req_path}',
                             files=files,
                             is_public=False)
    
    @app.route('/db/', defaults={'req_path': ''})
    @app.route('/db/<path:req_path>')
    def serve_db(req_path):
        abs_path = os.path.abspath(os.path.join(DB_DIR, req_path))
        db_dir_abs = os.path.abspath(DB_DIR)
        if os.path.commonpath([db_dir_abs, abs_path]) != db_dir_abs:
            return abort(403)

        if not os.path.exists(abs_path):
            return abort(404)

        if os.path.isfile(abs_path):
            return send_file(abs_path)

        files = []
        for file in os.listdir(abs_path):
            file_path = os.path.join(abs_path, file)
            stats = os.stat(file_path)
            files.append({
                'name': file,
                'size': stats.st_size,
                'modified': datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            })

        return render_template('directory.html', 
                             path=f'/db/{req_path}',
                             files=files,
                             is_public=True)

