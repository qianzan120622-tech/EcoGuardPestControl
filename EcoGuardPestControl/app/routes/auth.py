# app/routes/auth.py
from flask import Blueprint, request, jsonify
from app.db_service import get_mongo_db
from app.extensions import bcrypt
from flask_jwt_extended import create_access_token
from datetime import datetime

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/register', methods=['POST'])
def register():
    db = get_mongo_db()
    if db is None:  # 优雅地处理连接失败
        return jsonify({"message": "数据库连接失败"}), 500

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'Technician')
    if not username or not password:
        return jsonify({"message": "用户名和密码必填"}), 400

    if db.users.find_one({"username": username}):
        return jsonify({"message": "用户已存在"}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    db.users.insert_one(
        {"username": username, "password": hashed_password, "role": role, "created_at": datetime.utcnow()})
    return jsonify({"message": "注册成功"}), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    db = get_mongo_db()
    if db is None:
        return jsonify({"message": "数据库连接失败"}), 500

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = db.users.find_one({"username": username})

    if user and bcrypt.check_password_hash(user['password'], password):
        access_token = create_access_token(identity=username, additional_claims={"role": user['role']})
        return jsonify({"message": "登录成功", "token": access_token, "role": user['role'], "username": username}), 200
    else:
        return jsonify({"message": "用户名或密码错误"}), 401