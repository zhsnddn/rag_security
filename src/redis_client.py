"""
Redis客户端工具类，提供Redis缓存功能
"""

import json
import redis
from typing import Any, Dict, List, Optional, Union

from config import (
    REDIS_HOST, REDIS_PORT, REDIS_POOL_SIZE, REDIS_MIN_IDLE_SIZE,
    REDIS_IDLE_TIMEOUT, REDIS_CONNECT_TIMEOUT, REDIS_RETRY_ATTEMPTS,
    REDIS_RETRY_INTERVAL, REDIS_PING_INTERVAL, REDIS_KEEP_ALIVE
)

class RedisClient:
    """Redis客户端工具类"""
    
    _instance = None
    
    def __new__(cls):
        """单例模式"""
        if cls._instance is None:
            cls._instance = super(RedisClient, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """初始化Redis连接池"""
        self.pool = redis.ConnectionPool(
            host=REDIS_HOST,
            port=int(REDIS_PORT),
            max_connections=REDIS_POOL_SIZE,
            socket_timeout=REDIS_CONNECT_TIMEOUT / 1000,  # 转换为秒
            socket_keepalive=REDIS_KEEP_ALIVE,
            retry_on_timeout=True,
            health_check_interval=REDIS_PING_INTERVAL / 1000  # 转换为秒
        )
        self.client = redis.Redis(connection_pool=self.pool)
        print(f"Redis连接池已初始化: {REDIS_HOST}:{REDIS_PORT}")
    
    def set(self, key: str, value: Any, expiration: Optional[int] = None) -> bool:
        """
        设置缓存
        
        参数:
            key: 键名
            value: 键值
            expiration: 过期时间（秒）
        """
        try:
            if isinstance(value, (dict, list)):
                value = json.dumps(value, ensure_ascii=False)
            self.client.set(key, value, ex=expiration)
            return True
        except Exception as e:
            print(f"设置缓存失败: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        获取缓存
        
        参数:
            key: 键名
            default: 默认值
        """
        try:
            value = self.client.get(key)
            if value is None:
                return default
            
            # 尝试解析为JSON
            try:
                return json.loads(value)
            except:
                # 如果不是JSON格式，则返回原值
                return value.decode('utf-8')
        except Exception as e:
            print(f"获取缓存失败: {e}")
            return default
    
    def delete(self, key: str) -> bool:
        """删除缓存"""
        try:
            self.client.delete(key)
            return True
        except Exception as e:
            print(f"删除缓存失败: {e}")
            return False
    
    def exists(self, key: str) -> bool:
        """检查缓存是否存在"""
        try:
            return self.client.exists(key) > 0
        except Exception as e:
            print(f"检查缓存存在失败: {e}")
            return False
    
    def expire(self, key: str, expiration: int) -> bool:
        """设置缓存过期时间"""
        try:
            return self.client.expire(key, expiration)
        except Exception as e:
            print(f"设置缓存过期时间失败: {e}")
            return False
    
    def close(self):
        """关闭连接池"""
        try:
            self.pool.disconnect()
            print("Redis连接池已关闭")
        except Exception as e:
            print(f"关闭Redis连接池失败: {e}") 