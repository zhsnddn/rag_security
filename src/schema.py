"""
数据库模型定义
"""

import os
import enum
import datetime
import psycopg2
from passlib.hash import pbkdf2_sha256
from config import (
    DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
)

# 定义用户角色枚举
class UserRole(enum.Enum):
    ADMIN = "admin"      # 管理员
    NORMAL = "normal"    # 普通用户

# 定义文档安全级别枚举
class DocumentLevel(enum.Enum):
    CONFIDENTIAL = "confidential"  # 机密文档
    NORMAL = "normal"              # 普通文档

class Database:
    """数据库连接和操作类"""
    
    def __init__(self):
        """初始化数据库连接"""
        self.conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        self.conn.autocommit = True
    
    def initialize_tables(self):
        """初始化数据表"""
        with self.conn.cursor() as cursor:
            # 创建用户表
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
            """)
            
            # 创建文档表
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id SERIAL PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                original_filename VARCHAR(255) NOT NULL,
                file_type VARCHAR(50) NOT NULL,
                file_size INTEGER NOT NULL,
                level VARCHAR(20) NOT NULL,
                encryption_key VARCHAR(255) NOT NULL,
                encryption_iv VARCHAR(255) NOT NULL,
                uploaded_by INTEGER REFERENCES users(id) ON DELETE CASCADE,
                upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                description TEXT
            )
            """)
            
            # 添加默认管理员账户
            try:
                cursor.execute("""
                INSERT INTO users (username, password_hash, role)
                VALUES ('admin', %s, 'admin')
                ON CONFLICT (username) DO NOTHING
                """, (pbkdf2_sha256.hash('admin123'),))
            except Exception as e:
                print(f"创建默认管理员账户出错: {e}")
            
            print("数据库表初始化完成")
    
    def add_user(self, username, password, role=UserRole.NORMAL.value):
        """添加用户"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s) RETURNING id",
                    (username, pbkdf2_sha256.hash(password), role)
                )
                return cursor.fetchone()[0]
        except Exception as e:
            print(f"添加用户失败: {e}")
            return None
    
    def verify_user(self, username, password):
        """验证用户"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id, password_hash, role FROM users WHERE username = %s",
                    (username,)
                )
                user = cursor.fetchone()
                if user and pbkdf2_sha256.verify(password, user[1]):
                    # 更新最后登录时间
                    cursor.execute(
                        "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s",
                        (user[0],)
                    )
                    return {"id": user[0], "role": user[2]}
                else:
                    return None
        except Exception as e:
            print(f"验证用户失败: {e}")
            return None
    
    def add_document(self, filename, original_filename, file_type, file_size, level, 
                     encryption_key, encryption_iv, user_id, description=""):
        """添加文档记录"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                INSERT INTO documents 
                (filename, original_filename, file_type, file_size, level, 
                 encryption_key, encryption_iv, uploaded_by, description)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """, (filename, original_filename, file_type, file_size, level, 
                      encryption_key, encryption_iv, user_id, description))
                return cursor.fetchone()[0]
        except Exception as e:
            print(f"添加文档记录失败: {e}")
            return None
    
    def get_documents(self, user_id=None, level=None):
        """获取文档列表"""
        try:
            with self.conn.cursor() as cursor:
                query = """
                SELECT d.id, d.original_filename, d.file_type, d.file_size, 
                       d.level, u.username, d.upload_time, d.description, d.uploaded_by
                FROM documents d
                JOIN users u ON d.uploaded_by = u.id
                """
                
                conditions = []
                params = []
                
                if user_id is not None:
                    conditions.append("d.uploaded_by = %s")
                    params.append(user_id)
                
                if level is not None:
                    conditions.append("d.level = %s")
                    params.append(level)
                
                if conditions:
                    query += " WHERE " + " AND ".join(conditions)
                
                query += " ORDER BY d.upload_time DESC"
                
                cursor.execute(query, params)
                columns = [desc[0] for desc in cursor.description]
                
                documents = []
                for row in cursor.fetchall():
                    document = dict(zip(columns, row))
                    documents.append(document)
                
                return documents
        except Exception as e:
            print(f"获取文档列表失败: {e}")
            return []
    
    def get_document(self, doc_id):
        """获取单个文档信息"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                SELECT d.id, d.filename, d.original_filename, d.file_type, 
                       d.file_size, d.level, d.encryption_key, d.encryption_iv,
                       d.uploaded_by, u.username, d.upload_time, d.description
                FROM documents d
                JOIN users u ON d.uploaded_by = u.id
                WHERE d.id = %s
                """, (doc_id,))
                
                row = cursor.fetchone()
                if row:
                    columns = [desc[0] for desc in cursor.description]
                    document = dict(zip(columns, row))
                    return document
                return None
        except Exception as e:
            print(f"获取文档信息失败: {e}")
            return None
    
    def delete_document(self, doc_id):
        """删除文档记录"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("SELECT filename FROM documents WHERE id = %s", (doc_id,))
                result = cursor.fetchone()
                if not result:
                    return False, "文档不存在"
                
                filename = result[0]
                
                cursor.execute("DELETE FROM documents WHERE id = %s", (doc_id,))
                return True, filename
        except Exception as e:
            print(f"删除文档记录失败: {e}")
            return False, str(e)
    
    def get_user_role(self, user_id):
        """获取用户角色"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("SELECT role FROM users WHERE id = %s", (user_id,))
                result = cursor.fetchone()
                if result:
                    return result[0]
                return None
        except Exception as e:
            print(f"获取用户角色失败: {e}")
            return None
    
    def close(self):
        """关闭数据库连接"""
        self.conn.close()

# 创建数据库实例并初始化
def init_database():
    db = Database()
    db.initialize_tables()
    return db

if __name__ == "__main__":
    init_database() 