"""
向量存储模块，负责文档嵌入和向量数据库操作
"""

import os
from typing import List, Dict, Any
import psycopg2
from langchain.schema import Document
from langchain_community.vectorstores import PGVector
from langchain_ollama import OllamaEmbeddings
from tqdm import tqdm

from config import (
    DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, 
    EMBEDDING_MODEL, OLLAMA_HOST, EMBEDDING_BATCH_SIZE
)

def get_connection_string() -> str:
    """获取数据库连接字符串"""
    return f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

def init_db():
    """初始化数据库，包括创建扩展和表"""
    try:
        # 连接到默认数据库以创建我们的数据库
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
        )
        conn.autocommit = True
        cursor = conn.cursor()
        
        # 检查数据库是否存在，如不存在则创建
        cursor.execute(f"SELECT 1 FROM pg_database WHERE datname = '{DB_NAME}'")
        if not cursor.fetchone():
            cursor.execute(f"CREATE DATABASE {DB_NAME}")
            print(f"数据库 {DB_NAME} 创建成功")
        else:
            print(f"数据库 {DB_NAME} 已存在")
        
        cursor.close()
        conn.close()
        
        # 连接到我们的数据库
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        conn.autocommit = True
        cursor = conn.cursor()
        
        # 创建pgvector扩展
        cursor.execute("CREATE EXTENSION IF NOT EXISTS vector")
        print("pgvector扩展安装成功")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"初始化数据库时出错: {e}")

def get_embeddings_model():
    """获取嵌入模型实例"""
    # 如果使用Ollama提供的嵌入模型
    if EMBEDDING_MODEL == "nomic-embed-text":
        return OllamaEmbeddings(
            base_url=OLLAMA_HOST,
            model=EMBEDDING_MODEL
        )
    else:
        # 默认使用HuggingFace的嵌入模型
        from langchain_community.embeddings import HuggingFaceEmbeddings
        return HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)

def create_vector_store(documents: List[Document] = None):
    """创建向量存储"""
    try:
        embeddings = get_embeddings_model()
        connection_string = get_connection_string()
        
        # 设置额外的选项，使用JSONB而不是JSON
        pgvector_options = {
            "use_jsonb": True  # 使用JSONB类型存储元数据
        }
        
        if documents:
            vector_store = PGVector.from_documents(
                documents=documents,
                embedding=embeddings,
                connection_string=connection_string,
                collection_name="security_docs",
                pre_delete_collection=True,
                **pgvector_options
            )
            print("向量存储创建成功并填充了文档")
            return vector_store
        else:
            vector_store = PGVector(
                connection_string=connection_string,
                embedding_function=embeddings,
                collection_name="security_docs",
                **pgvector_options
            )
            print("连接到现有向量存储")
            return vector_store
    except Exception as e:
        print(f"创建向量存储时出错: {e}")
        return None

def query_vector_store(query: str, k: int = 4):
    """查询向量存储"""
    try:
        vector_store = create_vector_store()
        if vector_store:
            results = vector_store.similarity_search_with_score(query, k=k)
            return results
        return []
    except Exception as e:
        print(f"查询向量存储时出错: {e}")
        return [] 