import os

class Config:
    # --- Flask 核心配置 ---
    SECRET_KEY = os.environ.get('SECRET_KEY', 'my_ultra_secure_secret_key_v3')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt_secret_v3')

    # --- MongoDB 配置 ---
    MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
    MONGO_DB_NAME = 'forest_pest_control'  # 您的数据库名称

    # --- Redis 配置 ---
    REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))

    # --- Neo4j 配置 ---
    NEO4J_URI = os.environ.get('NEO4J_URI', 'bolt://localhost:7687')
    NEO4J_USER = os.environ.get('NEO4J_USER', 'neo4j')
    NEO4J_PASSWORD = os.environ.get('NEO4J_PASSWORD', 'itcast')

    # --- 应用业务配置 ---
    DEFAULT_ADMIN_USER = 'admin'
    DEFAULT_ADMIN_PASS = 'admin123'
    ALERT_THRESHOLD = 4  # 危害等级阈值 (1-5)