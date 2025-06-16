#!/usr/bin/env python3
"""
安全文档管理系统启动脚本
"""

import os
import sys
import subprocess

def main():
    print("🚀 启动安全文档管理系统...")
    print("=" * 50)
    
    # 检查依赖
    try:
        import flask
        import jwt
        print("✅ 依赖检查通过")
    except ImportError as e:
        print(f"❌ 缺少依赖: {e}")
        print("正在安装依赖...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    
    # 启动服务器
    print("\n📡 启动Web服务器...")
    print("访问地址: http://localhost:8090/static/index.html")
    print("管理员登录: admin / admin123")
    print("按 Ctrl+C 停止服务器")
    print("-" * 50)
    
    try:
        subprocess.run([sys.executable, "simple_server.py"])
    except KeyboardInterrupt:
        print("\n👋 服务器已停止")

if __name__ == "__main__":
    main() 