#!/usr/bin/env python3
"""
简单的Web服务器，用于测试前端界面
"""

from flask import Flask, request, jsonify, send_from_directory, send_file, Response, stream_template
import jwt
import json
import hashlib
from datetime import datetime, timedelta
import os
import sys

# 添加src目录到路径
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# 导入RAG功能
try:
    from src.app import rag_query
    RAG_AVAILABLE = True
    print("RAG模块导入成功")
except ImportError as e:
    print(f"RAG模块导入失败: {e}")
    RAG_AVAILABLE = False

# 导入安全过滤模块
try:
    from src.prompt_security import check_prompt_security
    SECURITY_FILTER_AVAILABLE = True
    print("提示词安全过滤模块加载成功")
except ImportError as e:
    print(f"提示词安全过滤模块加载失败: {e}")
    SECURITY_FILTER_AVAILABLE = False

# 导入输出内容过滤模块
try:
    from src.output_filter import filter_rag_output
    OUTPUT_FILTER_AVAILABLE = True
    print("输出内容过滤模块加载成功")
except ImportError as e:
    print(f"输出内容过滤模块加载失败: {e}")
    OUTPUT_FILTER_AVAILABLE = False

app = Flask(__name__)

# 简单的CORS处理
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# 简单配置
SECRET_KEY = "test_secret_key_123"
app.config['SECRET_KEY'] = SECRET_KEY

# 模拟用户数据
users = {
    "admin": {
        "id": 1,
        "username": "admin",
        "password_hash": hashlib.sha256("admin123".encode()).hexdigest(),
        "role": "admin"
    }
}

# 文档存储目录
DOCUMENTS_DIR = "documents"
SECURE_DOCUMENTS_DIR = "secure_documents"

def load_documents_from_filesystem():
    """从文件系统加载文档列表"""
    documents = []
    doc_id = 1
    
    # 加载普通文档
    if os.path.exists(DOCUMENTS_DIR):
        for filename in os.listdir(DOCUMENTS_DIR):
            filepath = os.path.join(DOCUMENTS_DIR, filename)
            if os.path.isfile(filepath):
                stat = os.stat(filepath)
                documents.append({
                    "id": doc_id,
                    "original_filename": filename,
                    "file_size": stat.st_size,
                    "level": "normal",
                    "description": f"普通文档：{filename}",
                    "username": "admin",
                    "uploaded_by": 1,
                    "upload_time": datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                    "file_path": filepath
                })
                doc_id += 1
    
    # 加载机密文档
    if os.path.exists(SECURE_DOCUMENTS_DIR):
        for filename in os.listdir(SECURE_DOCUMENTS_DIR):
            filepath = os.path.join(SECURE_DOCUMENTS_DIR, filename)
            if os.path.isfile(filepath):
                stat = os.stat(filepath)
                documents.append({
                    "id": doc_id,
                    "original_filename": filename,
                    "file_size": stat.st_size,
                    "level": "confidential",
                    "description": f"机密文档：{filename}",
                    "username": "admin",
                    "uploaded_by": 1,
                    "upload_time": datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                    "file_path": filepath
                })
                doc_id += 1
    
    return documents

@app.route('/')
def index():
    return "简单测试服务器正在运行"

@app.route('/static/<path:filename>')
def static_files(filename):
    """提供静态文件"""
    return send_from_directory('static', filename)

@app.route('/api/login', methods=['POST'])
def login():
    """登录接口"""
    print("收到登录请求")
    
    try:
        data = request.get_json()
        print(f"请求数据: {data}")
        
        username = data.get('username')
        password = data.get('password')
        
        print(f"用户名: {username}, 密码: {password}")
        
        if not username or not password:
            return jsonify({"error": "用户名和密码不能为空"}), 400
        
        # 检查用户
        user = users.get(username)
        if not user:
            return jsonify({"error": "用户不存在"}), 401
        
        # 验证密码
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if password_hash != user['password_hash']:
            return jsonify({"error": "密码错误"}), 401
        
        # 生成token
        payload = {
            'user_id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'exp': datetime.utcnow() + timedelta(days=7)
        }
        
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        
        response_data = {
            "message": "登录成功",
            "token": token,
            "user": {
                "id": user['id'],
                "username": user['username'],
                "role": user['role']
            }
        }
        
        print(f"登录成功，返回: {response_data}")
        return jsonify(response_data)
        
    except Exception as e:
        print(f"登录错误: {str(e)}")
        return jsonify({"error": "服务器内部错误"}), 500

@app.route('/api/register', methods=['POST'])
def register():
    """注册接口"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({"error": "用户名和密码不能为空"}), 400
        
        if username in users:
            return jsonify({"error": "用户名已存在"}), 400
        
        # 创建新用户
        user_id = len(users) + 1
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        users[username] = {
            "id": user_id,
            "username": username,
            "password_hash": password_hash,
            "role": "user"
        }
        
        return jsonify({"message": "注册成功"})
        
    except Exception as e:
        print(f"注册错误: {str(e)}")
        return jsonify({"error": "服务器内部错误"}), 500

def verify_token():
    """验证token"""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None
    
    try:
        token = auth_header.split(' ')[1]  # Bearer <token>
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except:
        return None

@app.route('/api/documents', methods=['GET'])
def get_documents():
    """获取文档列表"""
    user_info = verify_token()
    if not user_info:
        return jsonify({"error": "未授权"}), 401
    
    try:
        # 从文件系统动态加载文档列表
        documents = load_documents_from_filesystem()
        print(f"加载到 {len(documents)} 个文档")
        return jsonify({"documents": documents})
    except Exception as e:
        print(f"加载文档列表失败: {e}")
        return jsonify({"error": "加载文档列表失败"}), 500

@app.route('/api/documents', methods=['POST'])
def upload_document():
    """上传文档"""
    user_info = verify_token()
    if not user_info:
        return jsonify({"error": "未授权"}), 401
    
    try:
        # 检查是否有文件
        if 'file' not in request.files:
            return jsonify({"error": "没有选择文件"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "没有选择文件"}), 400
        
        # 获取文档级别
        level = request.form.get('level', 'normal')
        description = request.form.get('description', '')
        
        # 确定保存目录
        if level == 'confidential':
            save_dir = SECURE_DOCUMENTS_DIR
        else:
            save_dir = DOCUMENTS_DIR
        
        # 创建目录（如果不存在）
        os.makedirs(save_dir, exist_ok=True)
        
        # 保存文件
        filename = file.filename
        file_path = os.path.join(save_dir, filename)
        
        # 如果文件已存在，添加时间戳
        if os.path.exists(file_path):
            name, ext = os.path.splitext(filename)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{name}_{timestamp}{ext}"
            file_path = os.path.join(save_dir, filename)
        
        file.save(file_path)
        
        print(f"文件已保存到: {file_path}")
        
        # 获取新的文档ID
        documents = load_documents_from_filesystem()
        new_id = max([doc['id'] for doc in documents], default=0) + 1
        
        return jsonify({
            "message": "上传成功",
            "id": new_id,
            "filename": filename,
            "level": level
        })
        
    except Exception as e:
        print(f"上传文档失败: {e}")
        return jsonify({"error": f"上传失败: {str(e)}"}), 500

@app.route('/api/document/<int:doc_id>', methods=['GET'])
def download_document(doc_id):
    """下载文档"""
    user_info = verify_token()
    if not user_info:
        return jsonify({"error": "未授权"}), 401
    
    try:
        # 获取文档列表，找到对应的文档
        documents = load_documents_from_filesystem()
        document = None
        for doc in documents:
            if doc['id'] == doc_id:
                document = doc
                break
        
        if not document:
            return jsonify({"error": "文档不存在"}), 404
        
        # 检查文件是否存在
        file_path = document['file_path']
        if not os.path.exists(file_path):
            return jsonify({"error": "文件不存在"}), 404
        
        # 返回文件
        return send_file(
            file_path,
            as_attachment=True,
            download_name=document['original_filename']
        )
        
    except Exception as e:
        print(f"下载文档失败: {e}")
        return jsonify({"error": "下载失败"}), 500

@app.route('/api/document/<int:doc_id>', methods=['DELETE'])
def delete_document(doc_id):
    """删除文档"""
    user_info = verify_token()
    if not user_info:
        return jsonify({"error": "未授权"}), 401
    
    try:
        # 获取文档列表，找到对应的文档
        documents = load_documents_from_filesystem()
        document = None
        for doc in documents:
            if doc['id'] == doc_id:
                document = doc
                break
        
        if not document:
            return jsonify({"error": "文档不存在"}), 404
        
        # 删除文件
        file_path = document['file_path']
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"已删除文件: {file_path}")
        
        return jsonify({"message": "删除成功"})
        
    except Exception as e:
        print(f"删除文档失败: {e}")
        return jsonify({"error": "删除失败"}), 500

@app.route('/api/chat', methods=['POST'])
def chat():
    """RAG对话接口 - 流式输出"""
    user_info = verify_token()
    if not user_info:
        return jsonify({"error": "未授权"}), 401
    
    try:
        data = request.get_json()
        question = data.get('question', '').strip()
        top_k = data.get('top_k', 4)
        stream = data.get('stream', True)  # 默认使用流式输出
        
        if not question:
            return jsonify({"error": "问题不能为空"}), 400
        
        print(f"收到RAG问题: {question}")
        
        if stream:
            # 获取用户IP
            user_ip = request.remote_addr or "unknown"
            # 返回流式响应
            return Response(
                generate_rag_stream(question, top_k, user_ip),
                content_type='text/plain; charset=utf-8',
                headers={
                    'Cache-Control': 'no-cache',
                    'Connection': 'keep-alive',
                    'X-Accel-Buffering': 'no'
                }
            )
        else:
            # 非流式响应（兼容旧版本）
            user_ip = request.remote_addr or "unknown"
            return get_rag_response(question, top_k, user_ip)
            
    except Exception as e:
        print(f"对话接口错误: {str(e)}")
        return jsonify({"error": f"服务器内部错误: {str(e)}"}), 500

def generate_rag_stream(question, top_k, user_ip="unknown"):
    """生成RAG流式响应"""
    import time
    
    # 首先进行安全检查
    if SECURITY_FILTER_AVAILABLE:
        yield f"data: {json.dumps({'type': 'thinking', 'message': '🛡️ 进行安全检查...'})}\n\n"
        time.sleep(0.2)
        
        security_result = check_prompt_security(question, user_ip)
        
        if not security_result["allowed"]:
            reason = security_result["reason"]
            yield f"data: {json.dumps({'type': 'error', 'message': f'⚠️ 安全检查失败: {reason}'})}\n\n"
            return
        
        if security_result["risk_score"] > 30:
            risk_score = security_result["risk_score"]
            yield f"data: {json.dumps({'type': 'thinking', 'message': f'⚡ 检测到中等风险（评分: {risk_score}），继续处理...'})}\n\n"
            time.sleep(0.1)
        else:
            yield f"data: {json.dumps({'type': 'thinking', 'message': '✅ 安全检查通过'})}\n\n"
            time.sleep(0.1)
    
    # 发送开始标记
    yield f"data: {json.dumps({'type': 'start', 'message': '正在分析问题...'})}\n\n"
    time.sleep(0.1)
    
    yield f"data: {json.dumps({'type': 'thinking', 'message': '🔍 检索相关文档...'})}\n\n"
    time.sleep(0.5)
    
    try:
        if RAG_AVAILABLE:
            yield f"data: {json.dumps({'type': 'thinking', 'message': '📖 正在理解文档内容...'})}\n\n"
            time.sleep(0.3)
            
            yield f"data: {json.dumps({'type': 'thinking', 'message': '🤔 生成回答...'})}\n\n"
            time.sleep(0.3)
            
            # 调用RAG模型
            raw_answer = rag_query(question, top_k=top_k)
            
            # 输出内容安全过滤
            if OUTPUT_FILTER_AVAILABLE:
                yield f"data: {json.dumps({'type': 'thinking', 'message': '🔍 正在进行内容安全检查...'})}\n\n"
                time.sleep(0.2)
                
                filter_result = filter_rag_output(raw_answer)
                answer = filter_result["filtered_text"]
                
                if filter_result["has_sensitive_content"]:
                    risk_score = filter_result["risk_score"]
                    yield f"data: {json.dumps({'type': 'thinking', 'message': f'⚠️ 检测到敏感内容已自动过滤（风险评分: {risk_score}）'})}\n\n"
                    time.sleep(0.1)
                else:
                    yield f"data: {json.dumps({'type': 'thinking', 'message': '✅ 内容安全检查通过'})}\n\n"
                    time.sleep(0.1)
            else:
                answer = raw_answer
            
            # 流式输出答案（模拟逐字输出）
            yield f"data: {json.dumps({'type': 'answer_start', 'message': ''})}\n\n"
            
            # 将答案按句子分割，逐句输出
            sentences = answer.split('。')
            for i, sentence in enumerate(sentences):
                if sentence.strip():
                    if i == len(sentences) - 1 and not sentence.endswith('。'):
                        # 最后一句如果不以句号结尾，直接输出
                        content = sentence.strip()
                    else:
                        content = sentence.strip() + '。'
                    
                    yield f"data: {json.dumps({'type': 'answer_chunk', 'message': content})}\n\n"
                    time.sleep(0.2)  # 模拟思考时间
            
            yield f"data: {json.dumps({'type': 'complete', 'message': 'RAG回答完成', 'rag_status': 'success'})}\n\n"
            
        else:
            # RAG不可用，使用模拟回答
            yield f"data: {json.dumps({'type': 'thinking', 'message': '⚠️ RAG模块不可用，使用模拟回答...'})}\n\n"
            raw_answer = simulate_rag_answer(question)
            
            # 输出内容安全过滤
            if OUTPUT_FILTER_AVAILABLE:
                yield f"data: {json.dumps({'type': 'thinking', 'message': '🔍 正在进行内容安全检查...'})}\n\n"
                time.sleep(0.2)
                
                filter_result = filter_rag_output(raw_answer)
                answer = filter_result["filtered_text"]
                
                if filter_result["has_sensitive_content"]:
                    risk_score = filter_result["risk_score"]
                    yield f"data: {json.dumps({'type': 'thinking', 'message': f'⚠️ 检测到敏感内容已自动过滤（风险评分: {risk_score}）'})}\n\n"
                    time.sleep(0.1)
                else:
                    yield f"data: {json.dumps({'type': 'thinking', 'message': '✅ 内容安全检查通过'})}\n\n"
                    time.sleep(0.1)
            else:
                answer = raw_answer
            
            yield f"data: {json.dumps({'type': 'answer_start', 'message': ''})}\n\n"
            yield f"data: {json.dumps({'type': 'answer_chunk', 'message': answer})}\n\n"
            yield f"data: {json.dumps({'type': 'complete', 'message': '模拟回答完成', 'rag_status': 'fallback'})}\n\n"
            
    except Exception as e:
        print(f"RAG流式处理错误: {e}")
        yield f"data: {json.dumps({'type': 'error', 'message': f'处理过程中出现错误: {str(e)}'})}\n\n"

def get_rag_response(question, top_k, user_ip="unknown"):
    """获取非流式RAG响应"""
    # 安全检查
    if SECURITY_FILTER_AVAILABLE:
        security_result = check_prompt_security(question, user_ip)
        if not security_result["allowed"]:
            return jsonify({
                "error": f"安全检查失败: {security_result['reason']}",
                "risk_score": security_result["risk_score"],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 400
    
    if RAG_AVAILABLE:
        try:
            raw_answer = rag_query(question, top_k=top_k)
            
            # 输出内容安全过滤
            if OUTPUT_FILTER_AVAILABLE:
                filter_result = filter_rag_output(raw_answer)
                answer = filter_result["filtered_text"]
                
                response_data = {
                    "question": question,
                    "answer": answer,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "rag_status": "success",
                    "sources": [],
                    "content_filter": {
                        "has_sensitive_content": filter_result["has_sensitive_content"],
                        "risk_score": filter_result["risk_score"],
                        "detection_count": len(filter_result["detection_results"])
                    }
                }
            else:
                answer = raw_answer
                response_data = {
                    "question": question,
                    "answer": answer,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "rag_status": "success",
                    "sources": []
                }
            
            return jsonify(response_data)
        except Exception as rag_error:
            print(f"RAG模型调用失败: {rag_error}")
            raw_answer = simulate_rag_answer(question)
            
            # 输出内容安全过滤
            if OUTPUT_FILTER_AVAILABLE:
                filter_result = filter_rag_output(raw_answer)
                answer = filter_result["filtered_text"]
                
                response_data = {
                    "question": question,
                    "answer": f"RAG模型暂时不可用，提供模拟回答：\n\n{answer}",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "rag_status": "fallback",
                    "sources": [],
                    "error": str(rag_error),
                    "content_filter": {
                        "has_sensitive_content": filter_result["has_sensitive_content"],
                        "risk_score": filter_result["risk_score"],
                        "detection_count": len(filter_result["detection_results"])
                    }
                }
            else:
                answer = raw_answer
                response_data = {
                    "question": question,
                    "answer": f"RAG模型暂时不可用，提供模拟回答：\n\n{answer}",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "rag_status": "fallback",
                    "sources": [],
                    "error": str(rag_error)
                }
            
            return jsonify(response_data)
    else:
        raw_answer = simulate_rag_answer(question)
        
        # 输出内容安全过滤
        if OUTPUT_FILTER_AVAILABLE:
            filter_result = filter_rag_output(raw_answer)
            answer = filter_result["filtered_text"]
            
            response_data = {
                "question": question,
                "answer": f"RAG模块未加载，提供模拟回答：\n\n{answer}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "rag_status": "unavailable",
                "sources": [],
                "content_filter": {
                    "has_sensitive_content": filter_result["has_sensitive_content"],
                    "risk_score": filter_result["risk_score"],
                    "detection_count": len(filter_result["detection_results"])
                }
            }
        else:
            answer = raw_answer
            response_data = {
                "question": question,
                "answer": f"RAG模块未加载，提供模拟回答：\n\n{answer}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "rag_status": "unavailable",
                "sources": []
            }
        
        return jsonify(response_data)

def simulate_rag_answer(question):
    """模拟RAG回答 - 返回Markdown格式"""
    question_lower = question.lower()
    
    if any(word in question_lower for word in ['安全', '密码', '登录', '权限']):
        return """## 🔐 安全管理功能

根据系统文档，我们的安全管理包括以下几个方面：

### 身份验证
- **JWT令牌认证**：使用JSON Web Token进行用户身份验证
- **多因素认证**：支持额外的安全验证措施
- **密码策略**：强制使用复杂密码，定期更换

### 权限控制
- **角色管理**：区分管理员和普通用户角色
- **文档分级**：`普通文档` 和 `机密文档` 的访问控制
- **最小权限原则**：用户只能访问其权限范围内的资源

### 安全特性
- 🛡️ 数据加密存储
- 🔍 操作审计日志
- 🚫 防止未授权访问"""
    
    elif any(word in question_lower for word in ['文档', '上传', '下载', '管理']):
        return """## 📁 文档管理功能

我们的文档管理系统提供完整的文件操作功能：

### 核心功能
1. **文档上传**
   - 支持多种格式：TXT, MD, PDF, DOC等
   - 自动分类存储到相应目录
   - 重复文件自动重命名

2. **文档下载**
   - 安全的文件下载机制
   - 支持原文件名保持
   - 权限验证保护

3. **文档分级**
   - `documents/` - 普通文档存储
   - `secure_documents/` - 机密文档存储
   - 基于用户角色的访问控制

### 存储策略
```
📂 文档存储结构
├── documents/          # 普通文档
│   ├── sample.txt
│   ├── README.md
│   └── 系统说明.txt
└── secure_documents/   # 机密文档
    └── 密码管理策略.txt
```

> **注意**：机密文档仅管理员可访问"""
    
    elif any(word in question_lower for word in ['用户', '注册', '角色']):
        return """## 👥 用户管理系统

### 用户角色
- **管理员** (`admin`)
  - 访问所有文档（包括机密文档）
  - 用户管理权限
  - 系统配置权限

- **普通用户** (`user`)
  - 仅访问普通文档
  - 管理自己上传的文档
  - 基础问答功能

### 默认账户
```bash
用户名: admin  
密码: [密码已隐藏，请联系管理员获取]
角色: 管理员
```

### 注册流程
1. 填写用户名和密码
2. 系统自动分配普通用户角色
3. 管理员可后续调整用户权限

**安全提醒**：系统采用安全的身份认证机制！"""
    
    elif any(word in question_lower for word in ['测试', 'test', '敏感', '安全测试']):
        # 故意包含敏感信息用于测试输出过滤功能
        return """## 🧪 系统测试信息

### 测试配置
- 数据库连接：mysql://root:password123@192.168.1.100:3306/testdb
- 管理员密码：admin123456
- API密钥：sk-1234567890abcdefghijklmnop
- 系统管理员邮箱：admin@company.com
- 测试用户手机号：13812345678

### 系统路径
- 配置文件：/etc/myapp/config.json
- 日志目录：/var/log/myapp/
- 备份路径：C:\\backup\\system\\

**注意**：这些是测试用的敏感信息，应该被安全过滤系统自动屏蔽。"""
    
    elif any(word in question_lower for word in ['系统', '功能', '特性', 'rag']):
        return """## 🤖 RAG智能文档管理系统

### 系统概述
本系统是一个基于**检索增强生成(RAG)**技术的智能文档管理平台。

### 核心功能

#### 1. 智能问答 🧠
- **实时流式输出**：模拟真实AI思考过程
- **Markdown渲染**：支持富文本格式显示
- **文档检索**：基于上传文档内容回答问题
- **多轮对话**：保持对话上下文

#### 2. 文档管理 📚
- 多格式文档支持
- 安全分级存储
- 实时文档列表
- 完整CRUD操作

#### 3. 用户系统 🔑
- JWT身份验证
- 角色权限控制
- 安全登录注册

### 技术架构
```mermaid
graph TB
    A[前端界面] --> B[Flask后端]
    B --> C[文档存储]
    B --> D[RAG模型]
    D --> E[向量数据库]
    D --> F[LLM模型]
```

### 特色功能
- ✨ **流式输出**：实时显示AI思考过程
- 🎨 **Markdown支持**：美观的富文本渲染
- 🔐 **安全可靠**：企业级安全保障
- 📱 **响应式设计**：支持各种设备"""
    
    else:
        return f"""## 💬 智能问答助手

感谢您的问题：**{question}**

### 📖 基于文档库的回答
这是一个**安全文档管理系统**，集成了先进的RAG技术，可以基于您上传的文档内容进行智能问答。

### 🔍 建议询问的内容
- **系统功能**：了解平台的各项功能特性
- **安全管理**：用户权限、数据安全等话题  
- **文档操作**：上传、下载、管理文档的方法
- **用户管理**：账户注册、角色权限等问题

### 💡 使用提示
1. 先在"文档管理"页面上传相关文档
2. 然后在此处基于文档内容进行提问
3. 系统会检索相关文档并生成智能回答

---
*如需了解更多信息，请查看系统中的文档或询问更具体的问题。*"""

if __name__ == '__main__':
    print("启动简单测试服务器...")
    print("访问地址: http://localhost:8090")
    print("静态文件: http://localhost:8090/static/index.html")
    print("测试页面: http://localhost:8090/static/test_final.html")
    app.run(host='0.0.0.0', port=8090, debug=True) 