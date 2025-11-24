# app/utils.py
from functools import wraps
from flask_jwt_extended import verify_jwt_in_request, get_jwt
from flask import jsonify, current_app
from bson.objectid import ObjectId
from pymongo import TEXT
from app.db_service import get_mongo_db
import logging
from contextlib import suppress

TASK_STATUS = {
    "CREATED": "Created",
    "ASSIGNED": "Assigned",
    "IN_PROGRESS": "In Progress",
    "COMPLETED": "Completed",
    "CANCELED": "Canceled"
}

def create_initial_admin():
    db = get_mongo_db()
    if db is None:
        return

    from app.config import Config
    from app.extensions import bcrypt

    if db.users.find_one({"username": Config.DEFAULT_ADMIN_USER}) is None:
        hashed_password = bcrypt.generate_password_hash(Config.DEFAULT_ADMIN_PASS).decode('utf-8')
        db.users.insert_one({"username": Config.DEFAULT_ADMIN_USER, "password": hashed_password, "role": "Admin"})
        logging.info("⭐ 初始管理员用户已创建")


def create_indexes():
    db = get_mongo_db()
    if db is None:
        return

    with suppress(Exception):
        db.pests.create_index([("name", TEXT), ("description", TEXT)], name="pest_search_index")
        db.prevention_plans.create_index([("plan_title", TEXT), ("control_measures", TEXT)], name="plan_search_index")
        db.knowledge_base.create_index([("title", TEXT), ("content", TEXT), ("tags", TEXT)],
                                       name="knowledge_search_index")
        logging.info("⭐ MongoDB 全文搜索索引已创建")

def role_required(required_roles):

    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            try:
                verify_jwt_in_request()
                claims = get_jwt()
                user_role = claims.get("role")
                if user_role not in required_roles:
                    return jsonify({"message": "权限不足", "role": user_role}), 403
            except Exception as e:
                return jsonify({"message": f"JWT 验证失败或缺失"}), 401
            return fn(*args, **kwargs)

        return decorator

    return wrapper

def update_document(collection_name, doc_id, data, allowed_fields):
    db = get_mongo_db()
    if db is None: return jsonify({"message": "数据库连接失败"}), 500

    try:
        object_id = ObjectId(doc_id)
    except:
        return jsonify({"message": "无效ID"}), 400

    update_data = {k: v for k, v in data.items() if k in allowed_fields}

    if not update_data:
        return jsonify({"message": "没有提供可更新的字段"}), 400

    result = db[collection_name].update_one({"_id": object_id}, {"$set": update_data})

    if result.matched_count == 0:
        return jsonify({"message": "文档不存在"}), 404

    return None


def delete_document(collection_name, doc_id):
    db = get_mongo_db()
    if db is None: return jsonify({"message": "数据库连接失败"}), 500

    try:
        object_id = ObjectId(doc_id)
    except:
        return jsonify({"message": "无效ID"}), 400

    result = db[collection_name].delete_one({"_id": object_id})

    if result.deleted_count == 0:
        return jsonify({"message": "文档不存在"}), 404

    return None