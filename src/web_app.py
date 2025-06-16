"""
Web应用接口，提供HTTP访问
"""

import os
import sys
import json
import mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# 添加当前目录到sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.app import rag_query
from src.redis_client import RedisClient
from src.config import SERVER_PORT

# 初始化Redis客户端
redis_client = RedisClient()

# 静态文件目录
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")

class RAGHandler(BaseHTTPRequestHandler):
    """处理RAG HTTP请求的处理器"""
    
    def _set_headers(self, status_code=200, content_type="application/json"):
        self.send_response(status_code)
        self.send_header("Content-type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_OPTIONS(self):
        """处理OPTIONS请求"""
        self._set_headers()
    
    def serve_static_file(self, file_path, content_type=None):
        """提供静态文件"""
        try:
            with open(file_path, 'rb') as file:
                content = file.read()
                
            if content_type is None:
                content_type, _ = mimetypes.guess_type(file_path)
                if content_type is None:
                    content_type = 'application/octet-stream'
                    
            self._set_headers(200, content_type)
            self.wfile.write(content)
        except FileNotFoundError:
            self._set_headers(404)
            response = {"status": "error", "message": "文件未找到"}
            self.wfile.write(json.dumps(response, ensure_ascii=False).encode("utf-8"))
    
    def do_GET(self):
        """处理GET请求"""
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query_params = parse_qs(parsed_url.query)
        
        # 处理根路径，返回index.html
        if path == "/" or path == "":
            self.serve_static_file(os.path.join(STATIC_DIR, "index.html"), "text/html")
            return
            
        # 处理静态文件请求
        if path.startswith("/static/"):
            file_path = os.path.join(STATIC_DIR, os.path.basename(path))
            self.serve_static_file(file_path)
            return
            
        # 处理CSS、JS和图片文件请求
        if path.endswith(".css") or path.endswith(".js") or path.endswith(".png") or path.endswith(".jpg") or path.endswith(".svg"):
            file_path = os.path.join(STATIC_DIR, os.path.basename(path))
            self.serve_static_file(file_path)
            return
        
        if path == "/health":
            # 健康检查端点
            response = {"status": "ok", "message": "服务运行正常"}
            self._set_headers()
            self.wfile.write(json.dumps(response, ensure_ascii=False).encode("utf-8"))
            return
            
        elif path == "/rag/query":
            # 查询端点
            if "q" not in query_params:
                self._set_headers(400)
                response = {"status": "error", "message": "缺少查询参数 'q'"}
                self.wfile.write(json.dumps(response, ensure_ascii=False).encode("utf-8"))
                return
            
            question = query_params["q"][0]
            top_k = int(query_params.get("top_k", [4])[0])
            
            # 检查缓存
            cache_key = f"rag:query:{hash(question)}"
            cached_result = redis_client.get(cache_key)
            
            if cached_result:
                print(f"从缓存中获取结果: {cache_key}")
                response = {"status": "success", "question": question, "answer": cached_result, "cached": True}
                self._set_headers()
                self.wfile.write(json.dumps(response, ensure_ascii=False).encode("utf-8"))
                return
                
            # 执行RAG查询
            try:
                answer = rag_query(question, top_k)
                
                # 缓存结果（1小时）
                redis_client.set(cache_key, answer, 3600)
                
                response = {"status": "success", "question": question, "answer": answer, "cached": False}
                self._set_headers()
                self.wfile.write(json.dumps(response, ensure_ascii=False).encode("utf-8"))
            except Exception as e:
                self._set_headers(500)
                response = {"status": "error", "message": f"处理查询时出错: {str(e)}"}
                self.wfile.write(json.dumps(response, ensure_ascii=False).encode("utf-8"))
        else:
            # 未找到路径
            self._set_headers(404)
            response = {"status": "error", "message": "未找到请求的路径"}
            self.wfile.write(json.dumps(response, ensure_ascii=False).encode("utf-8"))
    
    def do_POST(self):
        """处理POST请求"""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self._set_headers(400)
            response = {"status": "error", "message": "请求体不能为空"}
            self.wfile.write(json.dumps(response, ensure_ascii=False).encode("utf-8"))
            return
            
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data.decode("utf-8"))
        except json.JSONDecodeError:
            self._set_headers(400)
            response = {"status": "error", "message": "无效的JSON格式"}
            self.wfile.write(json.dumps(response, ensure_ascii=False).encode("utf-8"))
            return
            
        if self.path == "/rag/query":
            if "question" not in data:
                self._set_headers(400)
                response = {"status": "error", "message": "缺少'question'参数"}
                self.wfile.write(json.dumps(response, ensure_ascii=False).encode("utf-8"))
                return
                
            question = data["question"]
            top_k = data.get("top_k", 4)
            
            # 检查缓存
            cache_key = f"rag:query:{hash(question)}"
            cached_result = redis_client.get(cache_key)
            
            if cached_result and not data.get("skip_cache", False):
                print(f"从缓存中获取结果: {cache_key}")
                response = {"status": "success", "question": question, "answer": cached_result, "cached": True}
                self._set_headers()
                self.wfile.write(json.dumps(response, ensure_ascii=False).encode("utf-8"))
                return
                
            # 执行RAG查询
            try:
                answer = rag_query(question, top_k)
                
                # 缓存结果（1小时）
                redis_client.set(cache_key, answer, 3600)
                
                response = {"status": "success", "question": question, "answer": answer, "cached": False}
                self._set_headers()
                self.wfile.write(json.dumps(response, ensure_ascii=False).encode("utf-8"))
            except Exception as e:
                self._set_headers(500)
                response = {"status": "error", "message": f"处理查询时出错: {str(e)}"}
                self.wfile.write(json.dumps(response, ensure_ascii=False).encode("utf-8"))
        else:
            # 未找到路径
            self._set_headers(404)
            response = {"status": "error", "message": "未找到请求的路径"}
            self.wfile.write(json.dumps(response, ensure_ascii=False).encode("utf-8"))

def run_server(port=SERVER_PORT):
    """运行Web服务器"""
    server_address = ("", port)
    httpd = HTTPServer(server_address, RAGHandler)
    print(f"启动服务器，监听端口 {port}...")
    print(f"访问 http://localhost:{port} 来使用Web界面")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("关闭服务器...")
        httpd.server_close()

if __name__ == "__main__":
    run_server() 