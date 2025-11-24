from flask import Blueprint, request, jsonify
from app.db_service import get_mongo_db, get_redis_client, get_neo4j_driver
from app.utils import role_required, TASK_STATUS, update_document, delete_document
from app.extensions import bcrypt
from flask_jwt_extended import get_jwt_identity
from bson.objectid import ObjectId
from datetime import datetime
import json
import logging
from app.config import Config
from pymongo import TEXT
from neo4j.exceptions import ServiceUnavailable

core_bp = Blueprint('core', __name__)


# --- 通用辅助函数 ---

def _get_db_or_error():
    """统一获取 MongoDB 对象，失败时返回错误响应"""
    db = get_mongo_db()
    if db is None:
        return None, jsonify({"message": "数据库连接失败"}), 500
    return db, None, None


def create_initial_graph_nodes(pest_data):
    """Neo4j: 创建病虫害和宿主植物节点"""
    driver = get_neo4j_driver()  # 获取驱动
    if driver:
        try:
            # 使用会话上下文管理器
            with driver.session() as session:
                pest_name = pest_data.get('name')
                host_plant = pest_data.get('host_plant')
                session.run("MERGE (p:Pest {name: $name})", name=pest_name)
                session.run("MERGE (t:Plant {name: $name})", name=host_plant)
                session.run("""
                    MATCH (p:Pest {name: $pest_name}), (t:Plant {name: $host_plant}) 
                    MERGE (p)-[:CAUSES {type: 'Damage'}]->(t)
                """, pest_name=pest_name, host_plant=host_plant)
            logging.info(f"Neo4j: 创建 {pest_name} 节点成功")
        except Exception as e:
            logging.error(f"Neo4j 节点创建失败: {e}")


def update_region_relationship(pest_name, region_name):
    """Neo4j: 更新病虫害影响区域的关系"""
    driver = get_neo4j_driver()
    if driver:
        try:
            with driver.session() as session:
                session.run("MERGE (r:Region {name: $name})", name=region_name)
                session.run("""
                    MATCH (p:Pest {name: $pest_name}), (r:Region {name: $region_name}) 
                    MERGE (p)-[a:AFFECTS]->(r) 
                    ON CREATE SET a.count = 1, a.last_updated = timestamp() 
                    ON MATCH SET a.count = a.count + 1, a.last_updated = timestamp()
                """, pest_name=pest_name, region_name=region_name)
            logging.info(f"Neo4j: 更新 {pest_name} 与 {region_name} 关系成功")
        except Exception as e:
            logging.error(f"Neo4j 关系更新失败: {e}")


# --- 用户管理 ---
@core_bp.route('/users', methods=['GET'])
@role_required(['Admin'])
def get_user_info():
    db, err, status = _get_db_or_error()
    if err: return err, status
    users = list(db.users.find({}))
    user_list = [{**user, '_id': str(user['_id']), 'password': '***'} for user in users]
    return jsonify({"count": len(user_list), "data": user_list}), 200


@core_bp.route('/users/<username>', methods=['PUT'])
@role_required(['Admin'])
def update_user(username):
    db, err, status = _get_db_or_error()
    if err: return err, status
    data = request.get_json()
    update_fields = {}
    if 'role' in data:
        update_fields['role'] = data['role']
    if 'password' in data:
        update_fields['password'] = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    if not update_fields:
        return jsonify({"message": "没有提供可更新的字段"}), 400
    result = db.users.update_one({"username": username}, {"$set": update_fields})
    if result.matched_count == 0:
        return jsonify({"message": "用户不存在"}), 404
    return jsonify({"message": f"用户 {username} 更新成功"}), 200


@core_bp.route('/users/<username>', methods=['DELETE'])
@role_required(['Admin'])
def delete_user(username):
    db, err, status = _get_db_or_error()
    if err: return err, status
    result = db.users.delete_one({"username": username})
    if result.deleted_count == 0:
        return jsonify({"message": "用户不存在"}), 404
    return jsonify({"message": f"用户 {username} 已删除"}), 200


# --- 病虫害管理 ---
@core_bp.route('/pests', methods=['POST'])
@role_required(['Admin', 'Expert'])
def add_pest_info():
    db, err, status = _get_db_or_error()
    if err: return err, status
    data = request.get_json()
    required_fields = ['name']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "缺少必要字段"}), 400
    if db.pests.find_one({"name": data['name']}):
        return jsonify({"message": "病虫害已存在"}), 409
    data['created_at'] = datetime.utcnow()
    result = db.pests.insert_one(data)
    create_initial_graph_nodes(data)
    return jsonify({"message": "病虫害新增成功", "id": str(result.inserted_id)}), 201


@core_bp.route('/pests', methods=['GET'])
@role_required(['Admin', 'Expert', 'Technician'])
def get_pest_info():
    db, err, status = _get_db_or_error()
    if err: return err, status
    name_query = request.args.get('name')
    query = {}
    if name_query:
        query['name'] = {"$regex": name_query, "$options": "i"}
    limit = int(request.args.get('limit', 100))
    skip = int(request.args.get('skip', 0))
    pests = list(db.pests.find(query).skip(skip).limit(limit))
    pest_list = [{**item, '_id': str(item['_id'])} for item in pests]
    return jsonify({"count": len(pest_list), "data": pest_list}), 200


@core_bp.route('/pests/<pest_name>', methods=['PUT'])
@role_required(['Admin', 'Expert'])
def update_pest(pest_name):
    db, err, status = _get_db_or_error()
    if err: return err, status
    data = request.get_json()
    allowed_fields = ['type', 'host_plant', 'control_methods', 'description']
    result = db.pests.update_one({"name": pest_name}, {"$set": {k: v for k, v in data.items() if k in allowed_fields}})
    if result.matched_count == 0:
        return jsonify({"message": "病虫害不存在"}), 404
    return jsonify({"message": f"病虫害 {pest_name} 更新成功"}), 200


@core_bp.route('/pests/<pest_name>', methods=['DELETE'])
@role_required(['Admin'])
def delete_pest(pest_name):
    db, err, status = _get_db_or_error()
    if err: return err, status

    result = db.pests.delete_one({"name": pest_name})
    if result.deleted_count == 0:
        return jsonify({"message": "病虫害不存在"}), 404

    # 同样更新 Neo4j 删除逻辑
    driver = get_neo4j_driver()
    if driver:
        try:
            with driver.session() as session:
                session.run("MATCH (p:Pest {name: $name}) DETACH DELETE p", name=pest_name)
        except Exception as e:
            logging.error(f"Neo4j 删除节点失败: {e}")

    return jsonify({"message": f"病虫害 {pest_name} 已删除"}), 200


# --- 防治方案 (CRUD) ---
@core_bp.route('/prevention_plans', methods=['POST'])
@role_required(['Admin', 'Expert'])
def add_plan():
    db, err, status = _get_db_or_error()
    if err: return err, status
    data = request.get_json()
    required_fields = ['pest_name', 'plan_title', 'control_measures', 'guidance']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "缺少必要字段"}), 400
    if db.prevention_plans.find_one({"plan_title": data['plan_title']}):
        return jsonify({"message": "方案标题已存在"}), 409
    data['created_at'] = datetime.utcnow()
    result = db.prevention_plans.insert_one(data)
    return jsonify({"message": "方案新增成功", "id": str(result.inserted_id)}), 201


@core_bp.route('/prevention_plans', methods=['GET'])
@role_required(['Admin', 'Expert', 'Technician'])
def get_plans():
    db, err, status = _get_db_or_error()
    if err: return err, status
    pest_name = request.args.get('pest_name')
    title = request.args.get('title')
    query = {}
    if pest_name:
        query['pest_name'] = {"$regex": pest_name, "$options": "i"}
    if title:
        query['plan_title'] = {"$regex": title, "$options": "i"}
    limit = int(request.args.get('limit', 100))
    skip = int(request.args.get('skip', 0))
    plans = list(db.prevention_plans.find(query).skip(skip).limit(limit))
    plan_list = [{**item, '_id': str(item['_id'])} for item in plans]
    return jsonify({"count": len(plan_list), "data": plan_list}), 200


@core_bp.route('/prevention_plans/<plan_id>', methods=['PUT'])
@role_required(['Admin', 'Expert'])
def update_plan(plan_id):
    err = update_document('prevention_plans', plan_id, request.get_json(),
                          ['pest_name', 'plan_title', 'control_measures', 'guidance', 'evaluation'])
    if err: return err
    return jsonify({"message": f"方案 {plan_id} 更新成功"}), 200


@core_bp.route('/prevention_plans/<plan_id>', methods=['DELETE'])
@role_required(['Admin'])
def delete_plan(plan_id):
    err = delete_document('prevention_plans', plan_id)
    if err: return err
    return jsonify({"message": f"方案 {plan_id} 已删除"}), 200


# --- 监测数据 ---
@core_bp.route('/monitoring/data', methods=['POST'])
@role_required(['Admin', 'Technician'])
def submit_monitoring_data():
    db, err, status = _get_db_or_error()
    if err: return err, status
    redis_client = get_redis_client()

    data = request.get_json()
    required_fields = ['disease_name', 'location_lat', 'location_lon', 'severity_level', 'region_name']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "缺少必要字段"}), 400
    try:
        severity = int(data['severity_level'])
        if not 1 <= severity <= 5:
            return jsonify({"message": "危害等级必须在1-5之间"}), 400
    except ValueError:
        return jsonify({"message": "危害等级必须是数字"}), 400

    data['timestamp'] = datetime.utcnow().timestamp()
    data['reporter'] = get_jwt_identity()
    result = db.monitoring_data.insert_one(data)

    alert_status = "未达到预警阈值"
    if severity >= Config.ALERT_THRESHOLD:
        alert_message = {
            "type": "SEVERE_OUTBREAK", "disease": data['disease_name'], "severity": severity,
            "location": f"{data['location_lat']},{data['location_lon']}", "time": data['timestamp'],
            "source_id": str(result.inserted_id)
        }
        if redis_client:
            redis_client.publish("pest_alert_channel", json.dumps(alert_message))
        db.alerts.insert_one(alert_message)
        update_region_relationship(data['disease_name'], data['region_name'])
        alert_status = "已触发预警"

    # Redis Realtime Stream Update
    redis_key = "realtime_monitoring_stream"
    data_for_redis = {**data, '_id': str(result.inserted_id)}
    if redis_client:
        redis_client.lpush(redis_key, json.dumps(data_for_redis))
        redis_client.ltrim(redis_key, 0, 99)

    return jsonify({"message": "监测数据提交成功", "id": str(result.inserted_id), "status": alert_status}), 201


@core_bp.route('/monitoring/data', methods=['GET'])
@role_required(['Admin', 'Expert', 'Technician'])
def get_monitoring_data():
    db, err, status = _get_db_or_error()
    if err: return err, status

    data_id = request.args.get('id')
    query = {}
    if data_id:
        try:
            query['_id'] = ObjectId(data_id)
        except:
            return jsonify({"message": "无效ID"}), 400

    limit = int(request.args.get('limit', 100))
    skip = int(request.args.get('skip', 0))
    records = list(db.monitoring_data.find(query).sort("timestamp", -1).skip(skip).limit(limit))
    record_list = [{**r, '_id': str(r['_id'])} for r in records]
    return jsonify({"count": len(record_list), "data": record_list}), 200


@core_bp.route('/monitoring/data/<data_id>', methods=['PUT'])
@role_required(['Admin', 'Expert'])
def update_monitoring_data(data_id):
    db, err, status = _get_db_or_error()
    if err: return err, status
    data = request.get_json()
    allowed_fields = ['disease_name', 'location_lat', 'location_lon', 'severity_level', 'region_name', 'reporter']
    err = update_document(db.monitoring_data, data_id, data, allowed_fields)
    if err:
        return err
    return jsonify({"message": f"监测数据 {data_id} 更新成功"}), 200


@core_bp.route('/monitoring/data/<data_id>', methods=['DELETE'])
@role_required(['Admin'])
def delete_monitoring_data(data_id):
    db, err, status = _get_db_or_error()
    if err: return err, status
    err = delete_document(db.monitoring_data, data_id)
    if err:
        return err
    return jsonify({"message": f"监测数据 {data_id} 已删除"}), 200


@core_bp.route('/monitoring/realtime', methods=['GET'])
@role_required(['Admin', 'Expert', 'Technician'])
def get_realtime_data():
    redis_client = get_redis_client()
    if not redis_client: return jsonify({"message": "Redis 不可用"}), 500

    redis_key = "realtime_monitoring_stream"
    data_list = redis_client.lrange(redis_key, 0, -1)
    realtime_data = [json.loads(item) for item in data_list]
    return jsonify({"count": len(realtime_data), "data": realtime_data}), 200


# --- Neo4j 查询 ---
@core_bp.route('/neo4j/query_plants', methods=['GET'])
@role_required(['Admin', 'Expert'])
def query_plants_by_pest():
    driver = get_neo4j_driver()
    if not driver:
        return jsonify({"message": "Neo4j 不可用"}), 500

    pest_name = request.args.get('pest_name')
    if not pest_name:
        return jsonify({"message": "请提供pest_name"}), 400

    # 使用 Session 上下文管理器
    try:
        with driver.session() as session:
            query = "MATCH (p:Pest {name: $pest_name})-[:CAUSES]->(t:Plant) RETURN t.name AS plant_name"
            result = session.run(query, pest_name=pest_name)
            plant_list = [record['plant_name'] for record in result]
        return jsonify({"pest": pest_name, "plants": plant_list}), 200
    except Exception as e:
        logging.error(f"Neo4j Query Error: {e}")
        return jsonify({"message": "查询失败"}), 500


@core_bp.route('/neo4j/query_regions', methods=['GET'])
@role_required(['Admin', 'Expert'])
def query_regions_affected():
    driver = get_neo4j_driver()
    if not driver:
        return jsonify({"message": "Neo4j 不可用"}), 500
    pest_name = request.args.get('pest_name')
    if not pest_name:
        return jsonify({"message": "请提供pest_name"}), 400

    try:
        with driver.session() as session:
            query = "MATCH (p:Pest {name: $pest_name})-[a:AFFECTS]->(r:Region) RETURN r.name AS region_name, a.count AS affect_count, a.last_updated AS last_updated_time ORDER BY affect_count DESC LIMIT 5"
            result = session.run(query, pest_name=pest_name)
            region_data = [dict(record) for record in result]
        return jsonify({"pest": pest_name, "regions": region_data}), 200
    except Exception as e:
        logging.error(f"Neo4j Query Error: {e}")
        return jsonify({"message": "查询失败"}), 500


# --- 任务管理 (CRUD) ---
@core_bp.route('/tasks', methods=['POST'])
@role_required(['Admin', 'Expert'])
def create_task():
    db, err, status = _get_db_or_error()
    if err: return err, status
    redis_client = get_redis_client()

    data = request.get_json()
    required_fields = ['title', 'priority', 'pest_name']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "缺少必要字段"}), 400

    new_task = {
        "title": data['title'], "pest_name": data['pest_name'], "priority": data['priority'],
        "description": data.get('description', '无描述'), "created_by": get_jwt_identity(),
        "created_at": datetime.utcnow(), "assigned_to": None, "due_date": data.get('due_date'),
        "status": TASK_STATUS["CREATED"], "plan_id": data.get('plan_id'),
        "monitoring_data_id": data.get('monitoring_data_id')
    }
    result = db.tasks.insert_one(new_task)
    task_id = str(result.inserted_id)

    if redis_client:
        redis_client.hmset(f"task:{task_id}", {
            "status": new_task["status"], "priority": new_task["priority"],
            "pest": new_task["pest_name"], "assigned_to": "None"
        })

    return jsonify({"message": "任务创建成功", "task_id": task_id}), 201


@core_bp.route('/tasks/<task_id>/assign', methods=['PUT'])
@role_required(['Admin', 'Expert'])
def assign_task(task_id):
    db, err, status = _get_db_or_error()
    if err: return err, status
    redis_client = get_redis_client()

    data = request.get_json()
    assignee = data.get('assignee_username')
    if not assignee:
        return jsonify({"message": "请指定分配用户"}), 400
    try:
        object_id = ObjectId(task_id)
    except:
        return jsonify({"message": "无效ID"}), 400

    task = db.tasks.find_one({"_id": object_id})
    if not task:
        return jsonify({"message": "任务不存在"}), 404

    assignee_user = db.users.find_one({"username": assignee, "role": "Technician"})
    if not assignee_user:
        return jsonify({"message": "分配用户不合法"}), 400

    update_result = db.tasks.update_one({"_id": object_id, "status": TASK_STATUS["CREATED"]}, {
        "$set": {"assigned_to": assignee, "status": TASK_STATUS["ASSIGNED"], "assigned_at": datetime.utcnow()}
    })

    if update_result.matched_count == 0:
        return jsonify({"message": "任务状态不正确"}), 400

    if redis_client:
        redis_client.hmset(f"task:{task_id}", {"status": TASK_STATUS["ASSIGNED"], "assigned_to": assignee})

    return jsonify({"message": "任务分配成功"}), 200


@core_bp.route('/tasks/<task_id>/status', methods=['PUT'])
@role_required(['Technician', 'Admin', 'Expert'])
def update_task_status(task_id):
    db, err, status = _get_db_or_error()
    if err: return err, status
    redis_client = get_redis_client()

    data = request.get_json()
    new_status_key = data.get('new_status_key')
    if not new_status_key or new_status_key not in TASK_STATUS:
        return jsonify({"message": "无效状态"}), 400

    new_status = TASK_STATUS[new_status_key]

    try:
        object_id = ObjectId(task_id)
    except:
        return jsonify({"message": "无效ID"}), 400

    update_data = {"status": new_status, "updated_at": datetime.utcnow()}
    if new_status_key == 'COMPLETED':
        update_data["completed_at"] = datetime.utcnow()
        update_data["completion_notes"] = data.get('completion_notes')

    result = db.tasks.update_one({"_id": object_id}, {"$set": update_data})

    if result.matched_count == 0:
        return jsonify({"message": "任务不存在"}), 404

    if redis_client:
        redis_client.hset(f"task:{task_id}", "status", new_status)

    return jsonify({"message": "状态更新成功", "new_status": new_status}), 200


@core_bp.route('/tasks', methods=['GET'])
@role_required(['Admin', 'Expert', 'Technician'])
def get_tasks():
    db, err, status = _get_db_or_error()
    if err: return err, status

    status_arg = request.args.get('status')
    assignee = request.args.get('assignee')
    creator = request.args.get('creator')

    query = {}
    if status_arg and status_arg in TASK_STATUS.values():
        query['status'] = status_arg
    if assignee:
        query['assigned_to'] = assignee
    if creator:
        query['created_by'] = creator

    limit = int(request.args.get('limit', 100))
    skip = int(request.args.get('skip', 0))

    tasks = list(db.tasks.find(query).sort("created_at", -1).skip(skip).limit(limit))
    task_list = [{**item, '_id': str(item['_id'])} for item in tasks]
    return jsonify({"count": len(task_list), "data": task_list}), 200


@core_bp.route('/tasks/<task_id>', methods=['DELETE'])
@role_required(['Admin'])
def delete_task(task_id):
    redis_client = get_redis_client()

    err = delete_document('tasks', task_id)
    if err: return err

    if redis_client:
        redis_client.delete(f"task:{task_id}")

    return jsonify({"message": f"任务 {task_id} 已删除"}), 200


# --- 分析 ---
@core_bp.route('/analysis/regional_risk', methods=['GET'])
@role_required(['Admin', 'Expert'])
def analyze_regional_risk():
    db, err, status = _get_db_or_error()
    if err: return err, status

    pipeline = [
        {"$match": {"severity_level": {"$exists": True}, "region_name": {"$exists": True}}},
        {"$group": {"_id": "$region_name", "avg_severity": {"$avg": "$severity_level"},
                    "max_severity": {"$max": "$severity_level"}, "report_count": {"$sum": 1}}},
        {"$sort": {"avg_severity": -1}}
    ]
    results = list(db.monitoring_data.aggregate(pipeline))

    for res in results:
        res['avg_severity'] = round(res['avg_severity'], 2)
        res['region'] = res['_id']
        del res['_id']

    return jsonify({"message": "区域风险分析", "data": results}), 200


@core_bp.route('/analysis/pest_ranking', methods=['GET'])
@role_required(['Admin', 'Expert'])
def analyze_pest_ranking():
    db, err, status = _get_db_or_error()
    if err: return err, status

    pipeline = [
        {"$group": {"_id": "$disease_name", "total_reports": {"$sum": 1}, "avg_severity": {"$avg": "$severity_level"}}},
        {"$sort": {"total_reports": -1}}, {"$limit": 10}
    ]
    results = list(db.monitoring_data.aggregate(pipeline))

    for res in results:
        res['pest_name'] = res['_id']
        res['avg_severity'] = round(res['avg_severity'], 2)
        del res['_id']

    return jsonify({"message": "病虫害排名 (Top 10)", "data": results}), 200


# --- 知识库 ---
@core_bp.route('/knowledge', methods=['POST'])
@role_required(['Admin', 'Expert'])
def add_knowledge():
    db, err, status = _get_db_or_error()
    if err: return err, status
    data = request.get_json()
    required = ['title', 'category', 'content', 'author']
    if not all(k in data for k in required):
        return jsonify({"message": "缺少必要字段"}), 400

    data['created_at'] = datetime.utcnow()
    data['tags'] = data.get('tags', [])
    result = db.knowledge_base.insert_one(data)
    return jsonify({"message": "知识添加成功", "id": str(result.inserted_id)}), 201


@core_bp.route('/knowledge', methods=['GET'])
@role_required(['Admin', 'Expert', 'Technician'])
def get_knowledge_list():
    db, err, status = _get_db_or_error()
    if err: return err, status

    category = request.args.get('category')
    query = {"category": category} if category else {}
    limit = int(request.args.get('limit', 100))
    skip = int(request.args.get('skip', 0))

    docs = list(db.knowledge_base.find(query).sort("created_at", -1).skip(skip).limit(limit))
    doc_list = [{**d, '_id': str(d['_id'])} for d in docs]
    return jsonify({"count": len(doc_list), "data": doc_list}), 200


@core_bp.route('/knowledge/<doc_id>', methods=['DELETE'])
@role_required(['Admin'])
def delete_knowledge(doc_id):
    err = delete_document('knowledge_base', doc_id)
    if err: return err
    return jsonify({"message": "知识已删除"}), 200


# --- 全文搜索 ---
@core_bp.route('/search/fulltext', methods=['GET'])
@role_required(['Admin', 'Expert', 'Technician'])
def fulltext_search():
    db, err, status = _get_db_or_error()
    if err: return err, status

    keyword = request.args.get('q')
    if not keyword:
        return jsonify({"message": "请提供关键字q"}), 400

    results = {"pests": [], "plans": [], "knowledge": []}

    try:
        cursor = db.pests.find({"$text": {"$search": keyword}}, {"score": {"$meta": "textScore"}}).sort(
            [("score", {"$meta": "textScore"})])
        results['pests'] = [{**d, '_id': str(d['_id'])} for d in cursor]
    except Exception as e:
        logging.warning(f"Pests搜索失败 (可能索引缺失): {e}")

    try:
        cursor = db.prevention_plans.find({"$text": {"$search": keyword}}, {"score": {"$meta": "textScore"}}).sort(
            [("score", {"$meta": "textScore"})])
        results['plans'] = [{**d, '_id': str(d['_id'])} for d in cursor]
    except Exception as e:
        logging.warning(f"Plans搜索失败 (可能索引缺失): {e}")

    try:
        cursor = db.knowledge_base.find({"$text": {"$search": keyword}}, {"score": {"$meta": "textScore"}}).sort(
            [("score", {"$meta": "textScore"})])
        results['knowledge'] = [{**d, '_id': str(d['_id'])} for d in cursor]
    except Exception as e:
        logging.warning(f"Knowledge搜索失败 (可能索引缺失): {e}")

    total = sum(len(v) for v in results.values())
    return jsonify({"message": f"找到 {total} 条结果", "keyword": keyword, "results": results}), 200