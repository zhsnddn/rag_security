"""
大语言模型服务模块，负责处理与Ollama的交互
"""

from typing import List, Dict, Any
from langchain_ollama import OllamaLLM
from langchain.prompts import PromptTemplate
from langchain.schema import Document
from langchain_core.output_parsers import StrOutputParser

from config import OLLAMA_HOST, OLLAMA_MODEL

def get_ollama_llm():
    """获取Ollama LLM实例"""
    return OllamaLLM(
        base_url=OLLAMA_HOST,
        model=OLLAMA_MODEL,
        temperature=0.1,
    )

def create_prompt_template():
    """创建问答提示模板"""
    template = """基于以下上下文信息，回答用户的问题。
    如果你无法从上下文中找到答案，请直接回答你不知道，不要编造答案。
    
    上下文信息:
    {context}
    
    问题: {question}
    
    回答:"""
    
    return PromptTemplate(
        template=template,
        input_variables=["context", "question"]
    )

def format_docs(docs_with_scores: List[tuple]) -> str:
    """将检索到的文档格式化为上下文字符串"""
    if not docs_with_scores:
        return "没有找到相关文档。"
    
    context_parts = []
    for i, (doc, score) in enumerate(docs_with_scores):
        context_parts.append(f"文档 {i+1}:\n{doc.page_content}\n")
    
    return "\n".join(context_parts)

def answer_question(question: str, docs_with_scores: List[tuple]) -> str:
    """使用检索到的文档回答问题"""
    try:
        if not docs_with_scores:
            return "抱歉，我找不到与您的问题相关的信息。"
        
        llm = get_ollama_llm()
        prompt = create_prompt_template()
        
        # 使用新的API方式：RunnableSequence
        chain = prompt | llm | StrOutputParser()
        
        context = format_docs(docs_with_scores)
        
        # 使用invoke方法替代run
        response = chain.invoke({"context": context, "question": question})
        
        return response
    except Exception as e:
        print(f"在回答问题时出错: {e}")
        return f"生成回答时出现错误: {str(e)}" 