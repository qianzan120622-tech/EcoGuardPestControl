# app/__init__.py
from flask import Flask
from flask_cors import CORS
from app.config import Config
from app.extensions import bcrypt, jwt
from app.db_service import init_db_services  # 导入新的服务初始化函数
from app.routes.auth import auth_bp
from app.routes.core import core_bp
from app.utils import create_initial_admin, create_indexes


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app, resources={r"/*": {"origins": "*"}})  # 确保CORS开放
    bcrypt.init_app(app)
    jwt.init_app(app)

    init_db_services(app)

    with app.app_context():
        create_initial_admin()
        create_indexes()

    app.register_blueprint(auth_bp, url_prefix='/api')
    app.register_blueprint(core_bp, url_prefix='/api')

    return app