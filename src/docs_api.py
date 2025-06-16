"""
文档管理API
"""

import os
import json
import base64
import mimetypes
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs
import uuid
import io

from schema import Database, UserRole, DocumentLevel
from security import (
    save_encrypted_file, read_encrypted_file, delete_file,
    generate_token, verify_token
)

# 创建临时上传目录
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "temp_uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 允许的文件类型
ALLOWED_EXTENSIONS = {
    '.pdf': 'application/pdf',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.txt': 'text/plain',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg'
}

class DocumentAPI:
    """文档管理API处理器"""
    
    def __init__(self, request_handler):
        self.handler = request_handler
        self.db = Database()
        self.session_user = None
    
    def parse_multipart(self):
        """解析multipart/form-data请求"""
        content_type = self.handler.headers['Content-Type']
        if not content_type or not content_type.startswith('multipart/form-data'):
            return None, 'Invalid content type'
            
        # 从Content-Type获取boundary
        boundary = content_type.split('=')[1]
        boundary = boundary.encode()
        
        # 读取请求体
        content_length = int(self.handler.headers['Content-Length'])
        post_data = self.handler.rfile.read(content_length)
        
        # 分割请求体为各个部分
        parts = post_data.split(b'--' + boundary)
        
        # 解析每个部分
        form_data = {}
        files = {}
        
        for part in parts:
            if not part or part == b'--\r\n' or part == b'--':
                continue
                
            # 移除开头的\r\n
            if part.startswith(b'\r\n'):
                part = part[2:]
                
            # 分离头部和内容
            try:
                headers_raw, body = part.split(b'\r\n\r\n', 1)
                headers = {}
                
                # 解析headers
                for header_line in headers_raw.split(b'\r\n'):
                    if not header_line:
                        continue
                    key, value = header_line.decode('utf-8').split(':', 1)
                    headers[key.strip().lower()] = value.strip()
                
                # 获取Content-Disposition
                if 'content-disposition' not in headers:
                    continue
                    
                content_disp = headers['content-disposition']
                parts_disp = content_disp.split(';')
                
                if parts_disp[0].strip() != 'form-data':
                    continue
                
                name = None
                filename = None
                
                for part_disp in parts_disp[1:]:
                    part_disp = part_disp.strip()
                    if part_disp.startswith('name='):
                        name = part_disp[5:].strip('"\'')
                    elif part_disp.startswith('filename='):
                        filename = part_disp[9:].strip('"\'')
                
                if not name:
                    continue
                
                # 移除结尾的\r\n
                if body.endswith(b'\r\n'):
                    body = body[:-2]
                
                # 如果有文件名，则是文件上传
                if filename:
                    content_type = headers.get('content-type', 'application/octet-stream')
                    files[name] = {
                        'filename': filename,
                        'content_type': content_type,
                        'data': body
                    }
                else:
                    # 否则是表单字段
                    form_data[name] = body.decode('utf-8')
            
            except Exception as e:
                print(f"解析multipart数据错误: {e}")
        
        return form_data, files
    
    def _authenticate(self):
        """从请求头或cookie中提取并验证令牌"""
        # 从Authorization头获取令牌
        auth_header = self.handler.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]
            user_data = verify_token(token)
            if user_data:
                self.session_user = user_data
                return True
        
        # 从Cookie获取令牌
        cookie = self.handler.headers.get('Cookie')
        if cookie:
            cookies = {c.split('=')[0].strip(): c.split('=')[1].strip() for c in cookie.split(';') if '=' in c}
            if 'auth_token' in cookies:
                user_data = verify_token(cookies['auth_token'])
                if user_data:
                    self.session_user = user_data
                    return True
        
        return False
    
    def _require_auth(self, require_admin=False):
        """检查用户认证和权限"""
        if not self._authenticate():
            self.handler.send_error(401, "未认证")
            return False
        
        if require_admin and self.session_user["role"] != UserRole.ADMIN.value:
            self.handler.send_error(403, "权限不足")
            return False
        
        return True
    
    def login(self):
        """用户登录"""
        try:
            content_length = int(self.handler.headers['Content-Length'])
            post_data = self.handler.rfile.read(content_length)
            request = json.loads(post_data.decode('utf-8'))
            
            username = request.get('username')
            password = request.get('password')
            
            if not username or not password:
                self._send_json_response(400, {"error": "用户名和密码不能为空"})
                return
            
            user = self.db.verify_user(username, password)
            if user:
                token = generate_token(user["id"], user["role"])
                self._send_json_response(200, {
                    "success": True,
                    "token": token,
                    "user": {
                        "id": user["id"],
                        "role": user["role"]
                    }
                })
                
                # 设置Cookie
                self.handler.send_header('Set-Cookie', f'auth_token={token}; Path=/; HttpOnly')
            else:
                self._send_json_response(401, {"error": "用户名或密码错误"})
        except json.JSONDecodeError:
            self._send_json_response(400, {"error": "无效的JSON格式"})
        except Exception as e:
            self._send_json_response(500, {"error": str(e)})
    
    def register(self):
        """用户注册"""
        try:
            content_length = int(self.handler.headers['Content-Length'])
            post_data = self.handler.rfile.read(content_length)
            request = json.loads(post_data.decode('utf-8'))
            
            username = request.get('username')
            password = request.get('password')
            role = request.get('role', UserRole.NORMAL.value)
            
            if not username or not password:
                self._send_json_response(400, {"error": "用户名和密码不能为空"})
                return
                
            # 非管理员只能注册为普通用户
            if not self._authenticate() or self.session_user["role"] != UserRole.ADMIN.value:
                role = UserRole.NORMAL.value
            
            user_id = self.db.add_user(username, password, role)
            
            if user_id:
                token = generate_token(user_id, role)
                self._send_json_response(201, {
                    "success": True,
                    "message": "用户注册成功",
                    "token": token,
                    "user": {
                        "id": user_id,
                        "role": role
                    }
                })
                
                # 设置Cookie
                self.handler.send_header('Set-Cookie', f'auth_token={token}; Path=/; HttpOnly')
            else:
                self._send_json_response(400, {"error": "用户注册失败，用户名可能已存在"})
        except json.JSONDecodeError:
            self._send_json_response(400, {"error": "无效的JSON格式"})
        except Exception as e:
            self._send_json_response(500, {"error": str(e)})
    
    def upload_document(self):
        """上传文档"""
        if not self._require_auth():
            return
            
        try:
            form_data, files = self.parse_multipart()
            
            if not form_data or not files:
                self._send_json_response(400, {"error": "未找到上传的文件"})
                return
                
            if 'file' not in files:
                self._send_json_response(400, {"error": "请提供文件"})
                return
                
            file_info = files['file']
            file_data = file_info['data']
            original_filename = file_info['filename']
            content_type = file_info['content_type']
            
            # 检查文件类型
            _, file_ext = os.path.splitext(original_filename.lower())
            if file_ext not in ALLOWED_EXTENSIONS:
                self._send_json_response(400, {"error": f"不支持的文件类型: {file_ext}"})
                return
                
            # 获取文件级别
            level = form_data.get('level', DocumentLevel.NORMAL.value)
            
            # 检查级别权限
            if level == DocumentLevel.CONFIDENTIAL.value and self.session_user["role"] != UserRole.ADMIN.value:
                self._send_json_response(403, {"error": "您没有权限上传机密文件"})
                return
                
            # 获取文件描述
            description = form_data.get('description', '')
                
            # 加密并保存文件
            filename, key, iv = save_encrypted_file(file_data, level)
            
            # 记录到数据库
            doc_id = self.db.add_document(
                filename=filename,
                original_filename=original_filename,
                file_type=content_type,
                file_size=len(file_data),
                level=level,
                encryption_key=key,
                encryption_iv=iv,
                user_id=self.session_user["user_id"],
                description=description
            )
            
            if doc_id:
                self._send_json_response(201, {
                    "success": True,
                    "message": "文件上传成功",
                    "document": {
                        "id": doc_id,
                        "filename": original_filename,
                        "level": level
                    }
                })
            else:
                # 清理临时文件
                delete_file(filename)
                self._send_json_response(500, {"error": "文件上传失败"})
        
        except Exception as e:
            print(f"文件上传错误: {e}")
            self._send_json_response(500, {"error": f"服务器错误: {str(e)}"})
    
    def get_documents(self):
        """获取文档列表"""
        if not self._require_auth():
            return
            
        # 检查查询参数
        query_params = {}
        if self.handler.path.find('?') > 0:
            query_string = self.handler.path.split('?', 1)[1]
            query_params = parse_qs(query_string)
            
        # 管理员可以看所有文件，普通用户只能看普通文件和自己上传的文件
        documents = []
        if self.session_user["role"] == UserRole.ADMIN.value:
            # 可选按级别过滤
            level = query_params.get('level', [None])[0]
            documents = self.db.get_documents(level=level)
        else:
            # 普通用户只能看普通文件或自己上传的文件
            own_docs = self.db.get_documents(user_id=self.session_user["user_id"])
            normal_docs = self.db.get_documents(level=DocumentLevel.NORMAL.value)
            
            # 合并并去重
            doc_ids = set()
            for doc in own_docs:
                doc_ids.add(doc["id"])
                documents.append(doc)
                
            for doc in normal_docs:
                if doc["id"] not in doc_ids:
                    documents.append(doc)
        
        self._send_json_response(200, {
            "success": True,
            "documents": documents
        })
    
    def download_document(self, doc_id):
        """下载文档"""
        if not self._require_auth():
            return
            
        # 获取文档信息
        document = self.db.get_document(doc_id)
        
        if not document:
            self._send_json_response(404, {"error": "文档不存在"})
            return
            
        # 检查权限
        if document["level"] == DocumentLevel.CONFIDENTIAL.value and self.session_user["role"] != UserRole.ADMIN.value:
            if document["uploaded_by"] != self.session_user["user_id"]:
                self._send_json_response(403, {"error": "您没有权限下载此文件"})
                return
                
        # 解密并读取文件
        decrypted_data = read_encrypted_file(
            document["filename"],
            document["encryption_key"],
            document["encryption_iv"],
            document["level"]
        )
        
        if not decrypted_data:
            self._send_json_response(500, {"error": "文件解密失败"})
            return
            
        # 设置响应头
        self.handler.send_response(200)
        self.handler.send_header('Content-Type', document["file_type"])
        self.handler.send_header('Content-Disposition', f'attachment; filename="{document["original_filename"]}"')
        self.handler.send_header('Content-Length', len(decrypted_data))
        self.handler.end_headers()
        
        # 发送文件内容
        self.handler.wfile.write(decrypted_data)
    
    def delete_document(self, doc_id):
        """删除文档"""
        if not self._require_auth():
            return
            
        # 获取文档信息
        document = self.db.get_document(doc_id)
        
        if not document:
            self._send_json_response(404, {"error": "文档不存在"})
            return
            
        # 检查权限
        if self.session_user["role"] != UserRole.ADMIN.value:
            if document["level"] == DocumentLevel.CONFIDENTIAL.value or document["uploaded_by"] != self.session_user["user_id"]:
                self._send_json_response(403, {"error": "您没有权限删除此文件"})
                return
                
        # 删除文档
        success, filename = self.db.delete_document(doc_id)
        if success:
            # 删除物理文件
            delete_file(filename)
            self._send_json_response(200, {"success": True, "message": "文档删除成功"})
        else:
            self._send_json_response(500, {"error": f"删除文档失败: {filename}"})
    
    def _send_json_response(self, status_code, data):
        """发送JSON响应"""
        self.handler.send_response(status_code)
        self.handler.send_header('Content-Type', 'application/json')
        self.handler.end_headers()
        
        response = json.dumps(data, ensure_ascii=False)
        self.handler.wfile.write(response.encode('utf-8'))
    
    def handle_request(self, method, path_parts):
        """处理API请求"""
        if len(path_parts) < 2:
            self.handler.send_error(400, "无效的API路径")
            return
            
        api_path = path_parts[1]
        
        # 认证相关API
        if api_path == "login" and method == "POST":
            self.login()
        elif api_path == "register" and method == "POST":
            self.register()
            
        # 文档相关API
        elif api_path == "documents":
            if method == "GET":
                self.get_documents()
            elif method == "POST":
                self.upload_document()
            else:
                self.handler.send_error(405, "不支持的请求方法")
                
        # 单个文档操作
        elif api_path == "document" and len(path_parts) > 2:
            doc_id = path_parts[2]
            if not doc_id.isdigit():
                self.handler.send_error(400, "无效的文档ID")
                return
                
            if method == "GET":
                self.download_document(doc_id)
            elif method == "DELETE":
                self.delete_document(doc_id)
            else:
                self.handler.send_error(405, "不支持的请求方法")
        else:
            self.handler.send_error(404, "API端点不存在") 