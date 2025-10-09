from flask import Flask
import os
from models import init_db, DB_FILE
from auth import create_auth_routes
from routes import create_main_routes

app = Flask(__name__)
app.secret_key = 'somesecret'


create_auth_routes(app)
create_main_routes(app)

if __name__ == '__main__':
    if not os.path.exists(DB_FILE):
        init_db()
    app.run(debug=False, host='0.0.0.0')
