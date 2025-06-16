"""
安全加密模块，处理文件加密与解密
"""

import os
import base64
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import jwt
from datetime import datetime, timedelta

# JWT密钥
JWT_SECRET = os.environ.get("JWT_SECRET", "dev_secret_key_please_change_in_production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION = 24  # 小时

# 配置不同安全级别的加密强度
ENCRYPTION_LEVELS = {
    "confidential": {
        "key_size": 32,  # AES-256
        "algorithm": algorithms.AES,
        "mode_class": modes.CBC
    },
    "normal": {
        "key_size": 16,  # AES-128
        "algorithm": algorithms.AES,
        "mode_class": modes.CBC
    }
}

# 安全存储根目录
DOCUMENTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "secure_documents")

# 确保文档目录存在
os.makedirs(DOCUMENTS_DIR, exist_ok=True)

def generate_encryption_params(level="normal"):
    """生成加密参数"""
    config = ENCRYPTION_LEVELS.get(level, ENCRYPTION_LEVELS["normal"])
    key = secrets.token_bytes(config["key_size"])
    iv = secrets.token_bytes(16)  # 固定使用16字节IV
    
    return {
        "key": base64.b64encode(key).decode(),
        "iv": base64.b64encode(iv).decode()
    }

def encrypt_file(file_data, key_b64, iv_b64, level="normal"):
    """
    加密文件内容
    
    参数:
        file_data: 要加密的文件数据
        key_b64: Base64编码的加密密钥
        iv_b64: Base64编码的初始化向量
        level: 安全级别
    
    返回:
        加密后的数据
    """
    config = ENCRYPTION_LEVELS.get(level, ENCRYPTION_LEVELS["normal"])
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    
    # 创建加密器
    cipher = Cipher(
        config["algorithm"](key),
        config["mode_class"](iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # 使用PKCS7填充
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()
    
    # 加密
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    return encrypted_data

def decrypt_file(encrypted_data, key_b64, iv_b64, level="normal"):
    """
    解密文件内容
    
    参数:
        encrypted_data: 加密的文件数据
        key_b64: Base64编码的加密密钥
        iv_b64: Base64编码的初始化向量
        level: 安全级别
    
    返回:
        解密后的文件数据
    """
    config = ENCRYPTION_LEVELS.get(level, ENCRYPTION_LEVELS["normal"])
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    
    # 创建解密器
    cipher = Cipher(
        config["algorithm"](key),
        config["mode_class"](iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # 解密
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # 解除填充
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data

def save_encrypted_file(file_data, level="normal"):
    """
    加密并保存文件
    
    参数:
        file_data: 文件数据
        level: 安全级别
    
    返回:
        (存储的文件名, 加密密钥, 初始化向量)
    """
    # 生成唯一文件名
    filename = f"{secrets.token_hex(8)}_{int(datetime.now().timestamp())}"
    
    # 生成加密参数
    enc_params = generate_encryption_params(level)
    
    # 加密文件
    encrypted_data = encrypt_file(
        file_data, 
        enc_params["key"],
        enc_params["iv"],
        level
    )
    
    # 确定存储路径
    file_path = os.path.join(DOCUMENTS_DIR, filename)
    
    # 保存加密文件
    with open(file_path, "wb") as f:
        f.write(encrypted_data)
    
    return filename, enc_params["key"], enc_params["iv"]

def read_encrypted_file(filename, key_b64, iv_b64, level="normal"):
    """读取并解密文件"""
    file_path = os.path.join(DOCUMENTS_DIR, filename)
    
    try:
        # 读取加密文件
        with open(file_path, "rb") as f:
            encrypted_data = f.read()
        
        # 解密文件
        decrypted_data = decrypt_file(encrypted_data, key_b64, iv_b64, level)
        
        return decrypted_data
    except Exception as e:
        print(f"解密文件失败: {e}")
        return None

def delete_file(filename):
    """删除文件"""
    file_path = os.path.join(DOCUMENTS_DIR, filename)
    
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
        else:
            return False
    except Exception as e:
        print(f"删除文件失败: {e}")
        return False

def generate_token(user_id, role):
    """生成JWT令牌"""
    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token):
    """验证JWT令牌"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return {
            "user_id": int(payload["sub"]),
            "role": payload["role"]
        }
    except jwt.ExpiredSignatureError:
        return None  # 令牌已过期
    except jwt.InvalidTokenError:
        return None  # 无效令牌
    except Exception as e:
        print(f"令牌验证错误: {e}")
        return None 