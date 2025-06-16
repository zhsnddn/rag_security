"""
数据加载脚本，用于处理文档并将其存储到向量数据库中
"""

import os
import sys
import time
from pathlib import Path

# 添加当前目录到sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.document_processor import load_documents, split_documents
from src.vector_store import init_db, create_vector_store

def main():
    """主函数，处理文档并存储到向量数据库"""
    print("开始文档处理和向量化...")
    
    # 初始化数据库
    print("初始化数据库...")
    init_db()
    
    # 加载文档
    print("加载文档...")
    documents = load_documents()
    
    # 分割文档
    print("分割文档...")
    chunks = split_documents(documents)
    
    # 创建向量存储
    print("创建向量存储并存储文档...")
    vector_store = create_vector_store(chunks)
    
    print("文档处理和向量化完成！")

if __name__ == "__main__":
    main() 