import sqlite3
import os
from uuid import uuid4

DB_FILE = 'db.sqlite'
DB_DIR = 'db'
DATA_DIR = 'data'

os.makedirs(DB_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        uuid TEXT PRIMARY KEY,
                        username TEXT UNIQUE,
                        email TEXT,
                        phone_number TEXT,
                        password TEXT,
                        role TEXT
                    )''')
        
        c.execute('''CREATE TABLE articles (
                uuid TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                author_uuid TEXT NOT NULL,
                collaborator_uuid TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (author_uuid) REFERENCES users(uuid),
                FOREIGN KEY (collaborator_uuid) REFERENCES users(uuid)
            )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS collab_requests (
            uuid TEXT PRIMARY KEY,
            article_uuid TEXT,
            title TEXT,
            content TEXT,
            from_uuid TEXT,
            to_uuid TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (from_uuid) REFERENCES users(uuid),
            FOREIGN KEY (to_uuid) REFERENCES users(uuid)
        )''')
        
        c.execute("SELECT COUNT(*) FROM users WHERE username='admin'")
        if c.fetchone()[0] == 0:
            admin_uuid = str(uuid4())
            password = 'somepass'
            c.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)", 
                     (admin_uuid, 'admin', 'admin@securinets.tn', '77777777', password, '0'))

        conn.commit()

def get_user_by_username(username):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT uuid, username, email, phone_number, password, role FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if row:
            return {
                'uuid': row[0],
                'username': row[1],
                'email': row[2],
                'phone_number': row[3],
                'password': row[4],
                'role': row[5]
            }
        return None

def get_user_by_uuid(uuid_):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT uuid, username, email, phone_number, password, role FROM users WHERE uuid=?", (uuid_,))
        row = c.fetchone()
        if row:
            return {
                'uuid': row[0],
                'username': row[1],
                'email': row[2],
                'phone_number': row[3],
                'password': row[4],
                'role': row[5]
            }
        return None