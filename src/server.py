"""
Web服务器
"""

import os
import time
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

from schema import Database, init_database
from docs_api import DocumentAPI

# 静态文件目录
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")

# MIME类型映射
MIME_TYPES = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon'
}

class RequestHandler(BaseHTTPRequestHandler):
    """HTTP请求处理器"""
    
    protocol_version = 'HTTP/1.1'  # 使用HTTP/1.1以支持持久连接
    
    def do_OPTIONS(self):
        """处理OPTIONS请求，用于CORS预检请求"""
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()
    
    def do_GET(self):
        """处理GET请求"""
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        
        # 根路径重定向到index.html
        if path == '/':
            self.send_response(301)
            self.send_header('Location', '/index.html')
            self.end_headers()
            return
            
        # API请求
        if path.startswith('/api/'):
            path_parts = path.strip('/').split('/')
            api = DocumentAPI(self)
            api.handle_request('GET', path_parts)
            return
            
        # 静态文件
        file_path = os.path.join(STATIC_DIR, path.lstrip('/'))
        
        if os.path.isfile(file_path):
            # 获取文件的MIME类型
            _, ext = os.path.splitext(file_path)
            content_type = MIME_TYPES.get(ext.lower(), 'application/octet-stream')
            
            # 读取文件内容
            with open(file_path, 'rb') as f:
                content = f.read()
                
            # 发送响应
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', len(content))
            self.send_header('Cache-Control', 'public, max-age=86400')  # 缓存1天
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_error(404, "文件未找到")
    
    def do_POST(self):
        """处理POST请求"""
        if self.path.startswith('/api/'):
            path_parts = self.path.strip('/').split('/')
            api = DocumentAPI(self)
            api.handle_request('POST', path_parts)
        else:
            self.send_error(404, "API端点不存在")
    
    def do_DELETE(self):
        """处理DELETE请求"""
        if self.path.startswith('/api/'):
            path_parts = self.path.strip('/').split('/')
            api = DocumentAPI(self)
            api.handle_request('DELETE', path_parts)
        else:
            self.send_error(404, "API端点不存在")
    
    def send_cors_headers(self):
        """发送CORS相关的响应头"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Authorization')
        self.send_header('Access-Control-Max-Age', '86400')  # 预检请求缓存1天
    
    def log_message(self, format, *args):
        """自定义日志格式"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] {self.address_string()} - {format % args}")


def run_server(host='localhost', port=8090):
    """启动Web服务器"""
    # 初始化数据库
    init_database()
    
    # 创建HTTP服务器
    server = HTTPServer((host, port), RequestHandler)
    print(f"服务器启动在 http://{host}:{port}")
    
    try:
        # 启动服务器
        server.serve_forever()
    except KeyboardInterrupt:
        # 优雅地关闭服务器
        print("接收到退出信号，关闭服务器...")
        server.shutdown()


if __name__ == "__main__":
    run_server() 