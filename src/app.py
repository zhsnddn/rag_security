"""
RAG系统主应用程序
"""

import os
import sys

# 添加当前目录到sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.vector_store import query_vector_store
from src.llm_service import answer_question

def rag_query(question: str, top_k: int = 4):
    """
    执行RAG查询流程
    
    参数:
        question: 用户问题
        top_k: 检索的最相关文档数量
    
    返回:
        生成的回答
    """
    print(f"问题: {question}")
    print("正在检索相关文档...")
    
    # 检索相关文档
    docs_with_scores = query_vector_store(question, k=top_k)
    
    if not docs_with_scores:
        return "未找到相关文档，无法回答问题。请确保已经运行了ingest.py来处理和存储文档。"
    
    print(f"找到 {len(docs_with_scores)} 个相关文档")
    
    # 使用检索到的文档回答问题
    print("生成回答...")
    answer = answer_question(question, docs_with_scores)
    
    return answer

def interactive_mode():
    """交互式问答模式"""
    print("="*50)
    print("欢迎使用基于内部文档的RAG问答系统")
    print("输入'退出'或'exit'结束对话")
    print("="*50)
    
    while True:
        question = input("\n请输入您的问题: ")
        if question.lower() in ['退出', 'exit', 'quit', 'q']:
            print("感谢使用，再见！")
            break
        
        answer = rag_query(question)
        print("\n回答:")
        print(answer)
        print("\n" + "-"*50)

if __name__ == "__main__":
    interactive_mode() 