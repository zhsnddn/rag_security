#!/usr/bin/env python3
"""
安全文档管理系统主启动程序
"""

import os
import sys
import threading
import time
from pathlib import Path

# 添加src目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 导入模块
from server import run_server
from schema import init_database

def print_banner():
    """打印系统横幅"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                  安全文档管理系统                               ║
    ║                  Security Document Management System           ║
    ║                                                               ║
    ║  功能特性:                                                     ║
    ║  • 用户认证与权限管理                                           ║
    ║  • 文档分级加密存储                                             ║
    ║  • 管理员/普通用户角色控制                                       ║
    ║  • 机密/普通文档分级管理                                         ║
    ║  • 基于AES的数据加密传输                                         ║
    ║  • 现代化Web界面                                               ║
    ║                                                               ║
    ║  默认管理员账户:                                                ║
    ║  用户名: admin                                                ║
    ║  密码: admin123                                               ║
    ║                                                               ║
    ║  系统端口: 8090                                               ║
    ║  访问地址: http://localhost:8090                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_dependencies():
    """检查系统依赖"""
    try:
        import psycopg2
        import cryptography
        import passlib
        import jwt
        print("✓ 所有依赖包已安装")
        return True
    except ImportError as e:
        print(f"✗ 缺少依赖包: {e}")
        print("请运行: pip install -r requirements.txt")
        return False

def check_database_config():
    """检查数据库配置"""
    try:
        from config import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
        print(f"✓ 数据库配置已加载: {DB_HOST}:{DB_PORT}/{DB_NAME}")
        return True
    except ImportError as e:
        print(f"✗ 数据库配置错误: {e}")
        print("请检查 config.py 文件")
        return False

def initialize_system():
    """初始化系统"""
    print("\n正在初始化系统...")
    
    # 检查依赖
    if not check_dependencies():
        return False
    
    # 检查数据库配置
    if not check_database_config():
        return False
    
    try:
        # 初始化数据库
        print("正在初始化数据库...")
        init_database()
        print("✓ 数据库初始化完成")
        
        # 创建必要的目录
        directories = [
            "secure_documents",
            "temp_uploads"
        ]
        
        for directory in directories:
            dir_path = Path(directory)
            dir_path.mkdir(exist_ok=True)
            print(f"✓ 目录创建完成: {directory}")
        
        return True
    except Exception as e:
        print(f"✗ 系统初始化失败: {e}")
        return False

def main():
    """主函数"""
    print_banner()
    
    # 初始化系统
    if not initialize_system():
        print("\n系统初始化失败，程序退出")
        sys.exit(1)
    
    print("\n系统初始化完成！")
    print("正在启动Web服务器...")
    
    try:
        # 启动Web服务器
        run_server(host='localhost', port=8090)
    except KeyboardInterrupt:
        print("\n\n收到退出信号，正在关闭服务器...")
        print("感谢使用安全文档管理系统！")
    except Exception as e:
        print(f"\n服务器启动失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 