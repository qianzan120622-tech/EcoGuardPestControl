import time
import random
import logging
from datetime import datetime, timedelta
from pymongo import MongoClient
from neo4j import GraphDatabase
from flask import Flask
from flask_bcrypt import Bcrypt

# --- 配置区域 ---
MONGO_URI = "mongodb://localhost:27017/"
MONGO_DB_NAME = "forest_pest_control"
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "itcast"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
bcrypt = Bcrypt(app)


def get_mongo_db():
    client = MongoClient(MONGO_URI)
    return client[MONGO_DB_NAME]


def get_neo4j_driver():
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
        driver.verify_connectivity()
        return driver
    except Exception as e:
        logging.warning(f"Neo4j 连接失败: {e}")
        return None


def clean_database(db, driver):
    logging.info("正在清空 MongoDB...")
    db.users.drop()
    db.pests.drop()
    db.prevention_plans.drop()
    db.monitoring_data.drop()
    db.tasks.drop()
    db.alerts.drop()
    db.knowledge_base.drop()

    if driver:
        logging.info("正在清空 Neo4j...")
        with driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")


def generate_users(db):
    users = [
        {"username": "admin", "password": "123", "role": "Admin"},
        {"username": "expert", "password": "123", "role": "Expert"},
        {"username": "tech", "password": "123", "role": "Technician"},
        {"username": "tech_hunan", "password": "123", "role": "Technician"},
        {"username": "tech_sichuan", "password": "123", "role": "Technician"}
    ]
    for u in users:
        hashed = bcrypt.generate_password_hash(u['password']).decode('utf-8')
        db.users.insert_one({
            "username": u['username'], "password": hashed, "role": u['role'], "created_at": datetime.utcnow()
        })
    logging.info(f"已生成 {len(users)} 个用户")


def generate_pests_and_graph(db, driver):
    pests = [
        {"name": "松材线虫", "host_plant": "马尾松", "type": "线虫", "description": "毁灭性病害，传播迅速",
         "control_methods": "伐除病株"},
        {"name": "红蜘蛛", "host_plant": "棉花", "type": "螨类", "description": "吸食叶片汁液",
         "control_methods": "阿维菌素"},
        {"name": "草地贪夜蛾", "host_plant": "玉米", "type": "昆虫", "description": "暴食性害虫",
         "control_methods": "生物农药"},
        {"name": "樟树天牛", "host_plant": "樟树", "type": "昆虫", "description": "蛀干害虫",
         "control_methods": "绿色威雷"},
        {"name": "美国白蛾", "host_plant": "阔叶树", "type": "昆虫", "description": "食叶害虫",
         "control_methods": "剪除网幕"}
    ]
    for p in pests:
        p['created_at'] = datetime.utcnow()
        db.pests.insert_one(p)
        if driver:
            with driver.session() as session:
                session.run("MERGE (p:Pest {name: $name})", name=p['name'])
                session.run("MERGE (t:Plant {name: $name})", name=p['host_plant'])
                session.run("MATCH (p:Pest {name: $p}), (t:Plant {name: $h}) MERGE (p)-[:CAUSES {type: 'Damage'}]->(t)",
                            p=p['name'], h=p['host_plant'])
    logging.info(f"已生成 {len(pests)} 种病虫害")
    return pests


def generate_tasks(db):
    """生成防治任务数据"""
    tasks = [
        {
            "title": "湖南松材线虫疫点清理", "pest_name": "松材线虫", "priority": "High",
            "description": "清理病死木，并在周围设置诱捕器。", "created_by": "admin",
            "created_at": datetime.utcnow(), "assigned_to": "tech_hunan",
            "status": "ASSIGNED", "assigned_at": datetime.utcnow(), "due_date": "2025-12-31"
        },
        {
            "title": "A区红蜘蛛药物喷洒", "pest_name": "红蜘蛛", "priority": "Medium",
            "description": "重点对果园区域进行阿维菌素喷洒。", "created_by": "expert",
            "created_at": datetime.utcnow(), "assigned_to": None,
            "status": "CREATED", "due_date": "2025-11-30"
        },
        {
            "title": "四川草地贪夜蛾监测", "pest_name": "草地贪夜蛾", "priority": "High",
            "description": "夜间开启高空测报灯。", "created_by": "admin",
            "created_at": datetime.utcnow() - timedelta(days=2), "assigned_to": "tech_sichuan",
            "status": "COMPLETED", "assigned_at": datetime.utcnow() - timedelta(days=2),
            "completed_at": datetime.utcnow(), "completion_notes": "监测完成，虫口密度下降。"
        }
    ]
    db.tasks.insert_many(tasks)
    logging.info(f"✅ 已生成 {len(tasks)} 条防治任务")


def generate_knowledge(db):
    """生成知识库数据"""
    articles = [
        {
            "title": "松材线虫病识别技术手册", "category": "诊断技术", "author": "专家组",
            "content": "松材线虫病（Pine Wilt Disease）被称为松树的癌症。主要症状包括针叶失水灰绿、褐变下垂...",
            "tags": ["松树", "检疫", "识别"], "created_at": datetime.utcnow() - timedelta(days=10)
        },
        {
            "title": "无人机在林业病虫害防治中的应用", "category": "防治技术", "author": "科技部",
            "content": "利用植保无人机进行低空喷洒，具有效率高、成本低、人药分离等优点...",
            "tags": ["无人机", "新技术"], "created_at": datetime.utcnow() - timedelta(days=5)
        },
        {
            "title": "生物防治：以虫治虫", "category": "生物防治", "author": "生防所",
            "content": "利用管氏肿腿蜂防治天牛，利用赤眼蜂防治鳞翅目害虫...",
            "tags": ["天敌", "绿色防控"], "created_at": datetime.utcnow() - timedelta(days=20)
        }
    ]
    db.knowledge_base.insert_many(articles)
    logging.info(f"已生成 {len(articles)} 条知识库文章")


def generate_monitoring_data(db, driver, pests, count=500):
    regions = ["湖南省", "湖北省", "广东省", "四川省", "江西省"]
    logging.info(f"正在生成 {count} 条监测数据...")
    bulk_data = []
    for _ in range(count):
        pest = random.choice(pests)
        region = random.choice(regions)
        severity = random.choices([1, 2, 3, 4, 5], weights=[30, 30, 20, 15, 5])[0]

        record = {
            "disease_name": pest['name'], "region_name": region,
            "location_lat": round(28.0 + random.uniform(-2, 2), 4),
            "location_lon": round(113.0 + random.uniform(-2, 2), 4),
            "severity_level": severity, "reporter": "tech",
            "timestamp": (datetime.utcnow() - timedelta(seconds=random.randint(0, 30 * 86400))).timestamp()
        }
        bulk_data.append(record)

        if severity >= 4 and driver:
            with driver.session() as session:
                session.run("MERGE (r:Region {name: $name})", name=region)
                session.run("""
                    MATCH (p:Pest {name: $p}), (r:Region {name: $r})
                    MERGE (p)-[a:AFFECTS]->(r)
                    ON CREATE SET a.count = 1 ON MATCH SET a.count = a.count + 1
                """, p=pest['name'], r=region)
    db.monitoring_data.insert_many(bulk_data)
    logging.info(f"已导入 {count} 条监测数据")


def main():
    print("EcoGuard 全功能测试数据生成器")
    if input("确认清空并重置数据库? (y/n): ").lower() != 'y': return

    db = get_mongo_db()
    driver = get_neo4j_driver()

    clean_database(db, driver)
    generate_users(db)
    pests = generate_pests_and_graph(db, driver)
    generate_tasks(db)
    generate_knowledge(db)
    generate_monitoring_data(db, driver, pests)

    if driver: driver.close()
    print("\n所有模块数据生成完毕！请重启后端服务并刷新前端页面。")


if __name__ == "__main__":
    main()