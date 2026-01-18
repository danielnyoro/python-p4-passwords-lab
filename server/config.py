# server/config.py

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_restful import Api
from flask_cors import CORS
from flask_bcrypt import Bcrypt

# Initialize extensions BEFORE create_app function so they can be imported
db = SQLAlchemy()
migrate = Migrate()
api = Api()
bcrypt = Bcrypt()

def create_app():
    app = Flask(__name__)
    app.secret_key = b'a\xdb\xd2\x13\x93\xc1\xe9\x97\xef2\xe3\x004U\xd1Z'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.json.compact = False
    
    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    api.init_app(app)
    bcrypt.init_app(app)
    CORS(app, supports_credentials=True)
    
    return app

# Create app instance
app = create_app()
