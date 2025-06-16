"""
配置文件，包含数据库和Ollama模型的配置信息
"""

import os
from dotenv import load_dotenv

# 尝试加载.env文件，如果存在的话
load_dotenv()

# 数据库配置
DB_HOST = os.getenv("DB_HOST", "60.204.219.247")
DB_PORT = os.getenv("DB_PORT", "15432")
DB_NAME = os.getenv("DB_NAME", "ai-rag-knowledge")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")
# 服务器配置
SERVER_PORT = 8090
# 数据库连接池配置
DB_POOL_MIN_CONNECTIONS = 5
DB_POOL_MAX_CONNECTIONS = 10
DB_POOL_MAX_LIFETIME = 1800000  # 毫秒
DB_POOL_IDLE_TIMEOUT = 600000  # 毫秒
DB_POOL_CONNECTION_TIMEOUT = 30000  # 毫秒
# 安全配置
SECRET_KEY = "your-secret-key-change-in-production"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24
# Ollama配置
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://60.204.219.247:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "deepseek-r1:1.5b")

# 向量嵌入模型
EMBEDDING_MODEL = "nomic-embed-text"
EMBEDDING_BATCH_SIZE = 512
# 文件存储配置
UPLOAD_MAX_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {'.pdf', '.doc', '.docx', '.txt', '.png', '.jpg', '.jpeg'}
# Redis配置
REDIS_HOST = os.getenv("REDIS_HOST", "60.204.219.247")
REDIS_PORT = os.getenv("REDIS_PORT", "16379")
REDIS_POOL_SIZE = 10
REDIS_MIN_IDLE_SIZE = 5
REDIS_IDLE_TIMEOUT = 30000
REDIS_CONNECT_TIMEOUT = 5000
REDIS_RETRY_ATTEMPTS = 3
REDIS_RETRY_INTERVAL = 1000
REDIS_PING_INTERVAL = 60000
REDIS_KEEP_ALIVE = True

# 数据配置
DOCUMENTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "documents")

# 加密配置
ENCRYPTION_ALGORITHM = "AES"
ENCRYPTION_MODE = "CBC" 