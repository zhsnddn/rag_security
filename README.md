# 安全文档管理系统

一个基于数据分级加密存储与传输机制的安全文档管理系统，支持用户认证、权限控制和文档安全分级管理。

## 系统特性

### 🔐 安全特性
- **数据分级加密**: 机密文档使用AES-256加密，普通文档使用AES-128加密
- **用户认证**: 基于JWT的用户认证机制
- **权限控制**: 管理员和普通用户角色分离
- **安全传输**: HTTPS支持和数据加密传输

### 👥 用户管理
- **管理员**: 可上传、删除机密文件和普通文件
- **普通用户**: 只能管理普通文件，无法访问机密文档

### 📁 文档管理
- **文档分级**: 机密文档和普通文档两个安全级别
- **文件类型**: 支持PDF、DOC、DOCX、TXT、图片等多种格式
- **文档操作**: 上传、下载、删除、搜索、预览

### 🎨 用户界面
- **现代化设计**: 响应式Web界面，支持桌面和移动设备
- **直观操作**: 拖拽上传、实时搜索、模态框预览
- **状态显示**: 实时显示系统状态和文档统计

## 系统架构

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   前端界面      │    │   后端API       │    │   数据存储      │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ HTML/CSS/JS     │ -> │ Python HTTP     │ -> │ PostgreSQL      │
│ 用户认证界面    │    │ 用户认证API     │    │ 用户数据表      │
│ 文档管理界面    │    │ 文档管理API     │    │ 文档元数据表    │
│ 管理员面板      │    │ 文件加密/解密   │    │ 加密文件存储    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 快速开始

### 环境要求

- Python 3.8+
- PostgreSQL 12+
- 现代浏览器 (Chrome, Firefox, Safari, Edge)

### 安装步骤

1. **克隆项目**
   ```bash
   git clone <repository-url>
   cd RAG_Security
   ```

2. **安装依赖**
   ```bash
   pip install -r requirements.txt
   ```

3. **配置数据库**
   - 确保PostgreSQL服务运行
   - 检查 `src/config.py` 中的数据库配置
   - 默认配置:
     ```python
     DB_HOST = "localhost"
     DB_PORT = 5432
     DB_NAME = "rag_security"
     DB_USER = "postgres"
     DB_PASSWORD = "postgres"
     ```

4. **启动系统**
   
   **一键启动（推荐）**:
   ```bash
   python start.py
   ```
   
   **手动启动**:
   ```bash
   python simple_server.py
   ```

5. **访问系统**
   - 主界面: http://localhost:8090/static/index.html  
   - 测试页面: http://localhost:8090/static/test_markdown.html
   - 默认管理员账户: `admin` / `admin123`

## 使用指南

### 登录系统

1. 打开系统首页
2. 使用默认管理员账户登录: `admin` / `admin123`
3. 或点击"注册"创建新的普通用户账户

### 文档上传

1. 点击侧边栏"上传文件"
2. 拖拽文件到上传区域或点击选择文件
3. 选择文档安全级别:
   - **普通文档**: 所有用户可见
   - **机密文档**: 仅管理员可上传和管理
4. 填写文档描述（可选）
5. 点击"上传文档"

### 文档管理

1. 在"文档管理"页面查看所有可访问的文档
2. 使用搜索框快速查找文档
3. 使用级别过滤器筛选不同安全级别的文档
4. 点击文档查看详细信息
5. 下载或删除文档（需要相应权限）

### 管理员功能

管理员账户具有以下额外功能:
- 上传和管理机密文档
- 删除任何文档
- 查看系统统计信息
- 访问管理面板

## 安全机制

### 数据加密

- **机密文档**: AES-256-CBC加密
- **普通文档**: AES-128-CBC加密
- **密钥管理**: 每个文件独立的加密密钥和初始化向量
- **存储安全**: 密钥与文件分离存储

### 访问控制

```
角色权限矩阵:

                │ 普通文档 │ 机密文档 │
    ────────────┼─────────┼─────────┤
    普通用户    │   读写   │   无权限  │
    管理员      │   读写   │   读写   │
```

### 认证机制

- **JWT令牌**: 基于JSON Web Token的无状态认证
- **密码加密**: 使用PBKDF2-SHA256哈希存储
- **会话管理**: 自动令牌过期和刷新

## 文件结构

```
RAG_Security/
├── src/                    # 源代码目录
│   ├── main.py            # 主启动程序
│   ├── server.py          # Web服务器
│   ├── schema.py          # 数据库模型
│   ├── security.py        # 安全加密模块
│   ├── docs_api.py        # 文档管理API
│   └── config.py          # 配置文件
├── static/                # 静态文件目录
│   ├── index.html         # 主页面
│   ├── styles.css         # 样式表
│   └── script.js          # 前端脚本
├── secure_documents/      # 加密文档存储（自动创建）
├── temp_uploads/          # 临时上传目录（自动创建）
├── requirements.txt       # Python依赖包
├── start_server.bat       # Windows启动脚本
└── README.md             # 说明文档
```

## API接口

### 认证接口

- `POST /api/login` - 用户登录
- `POST /api/register` - 用户注册

### 文档接口

- `GET /api/documents` - 获取文档列表
- `POST /api/documents` - 上传文档
- `GET /api/document/{id}` - 下载文档
- `DELETE /api/document/{id}` - 删除文档

## 配置说明

### 数据库配置 (src/config.py)

```python
# 数据库连接配置
DB_HOST = "localhost"      # 数据库主机
DB_PORT = 5432            # 数据库端口
DB_NAME = "rag_security"  # 数据库名称
DB_USER = "postgres"      # 数据库用户
DB_PASSWORD = "postgres"  # 数据库密码
```

### 安全配置 (src/security.py)

```python
# JWT配置
JWT_SECRET = "your-secret-key"  # JWT密钥
JWT_EXPIRATION = 24            # 令牌过期时间（小时）

# 加密配置
ENCRYPTION_LEVELS = {
    "confidential": {"key_size": 32},  # AES-256
    "normal": {"key_size": 16}         # AES-128
}
```

## 故障排除

### 常见问题

1. **数据库连接失败**
   - 检查PostgreSQL服务是否运行
   - 验证数据库配置信息
   - 确保数据库用户有创建表的权限

2. **依赖包安装失败**
   - 更新pip: `pip install --upgrade pip`
   - 使用国内镜像: `pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt`

3. **文件上传失败**
   - 检查文件大小（限制10MB）
   - 确认文件类型支持
   - 验证用户权限

4. **加密/解密错误**
   - 检查cryptography包版本
   - 确认文件存储目录权限

### 日志调试

系统运行时会在控制台输出详细日志信息，包括:
- 用户认证状态
- 文件操作记录
- 错误信息和堆栈

## 安全建议

1. **生产环境部署**:
   - 修改默认管理员密码
   - 更换JWT密钥
   - 启用HTTPS
   - 配置防火墙

2. **数据备份**:
   - 定期备份数据库
   - 备份加密文件存储目录
   - 保存密钥备份

3. **权限管理**:
   - 定期审查用户权限
   - 监控文档访问日志
   - 及时删除无效用户

## 技术支持

如有问题或建议，请通过以下方式联系:

- 提交Issue到项目仓库
- 发送邮件到技术支持邮箱
- 查看项目Wiki获取更多文档

---

© 2024 安全文档管理系统. 保留所有权利. 