from pymongo import MongoClient
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable # ❗ 修正导入位置
import redis
import logging
from contextlib import suppress
import time

class DBServices:
    def __init__(self):
        self.mongo_client = None
        self.mongo_db = None
        self.redis_client = None
        self.neo4j_driver = None 

# 创建服务的单例实例
services = DBServices()

def init_db_services(app):
    config = app.config
    logging.getLogger('neo4j').setLevel(logging.WARNING) # 抑制 Neo4j 驱动冗余日志

    # --- 1. MongoDB ---
    try:
        client = MongoClient(config['MONGO_URI'], serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        services.mongo_client = client
        services.mongo_db = client.get_database(config['MONGO_DB_NAME'])
        logging.info("MongoDB 连接成功")
    except Exception as e:
        logging.error(f"MongoDB 连接失败: {e}")
        services.mongo_db = None

    # --- 2. Redis ---
    with suppress(Exception):
        r_client = redis.Redis(host=config['REDIS_HOST'], port=config['REDIS_PORT'], decode_responses=True)
        r_client.ping()
        services.redis_client = r_client
        logging.info("Redis 连接成功")

    # --- 3. Neo4j ---
    try:
        graph_driver = GraphDatabase.driver(
            config['NEO4J_URI'],
            auth=(config['NEO4J_USER'], config['NEO4J_PASSWORD']),
            connection_timeout=5.0
        )
        graph_driver.verify_connectivity()
        services.neo4j_driver = graph_driver 
        logging.info("Neo4j 连接成功")
    except ServiceUnavailable as e:
        logging.error(f"Neo4j 连接失败 (ServiceUnavailable): {e}")
        services.neo4j_driver = None
    except Exception as e:
        logging.error(f"Neo4j 连接失败 (其他异常): {e}")
        services.neo4j_driver = None


def get_mongo_db():
    return services.mongo_db


def get_redis_client():
    return services.redis_client

def get_neo4j_driver():
    return services.neo4j_driver