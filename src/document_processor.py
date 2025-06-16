"""
文档处理模块，负责加载和处理文档
"""

import os
from typing import List, Dict, Any
from langchain_community.document_loaders import TextLoader, PyPDFLoader, DirectoryLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema import Document
from tqdm import tqdm

from config import DOCUMENTS_DIR

def load_documents(directory: str = DOCUMENTS_DIR) -> List[Document]:
    """
    从指定目录加载文档
    
    参数:
        directory: 文档目录路径
    
    返回:
        文档对象列表
    """
    loaders = []
    
    # 加载txt文档
    txt_loader = DirectoryLoader(
        directory, 
        glob="**/*.txt",
        loader_cls=TextLoader,
        loader_kwargs={"encoding": "utf-8"}
    )
    loaders.append(txt_loader)
    
    # 加载PDF文档
    pdf_loader = DirectoryLoader(
        directory,
        glob="**/*.pdf",
        loader_cls=PyPDFLoader
    )
    loaders.append(pdf_loader)
    
    documents = []
    for loader in tqdm(loaders, desc="加载文档"):
        try:
            documents.extend(loader.load())
        except Exception as e:
            print(f"加载文档时出错: {e}")
    
    print(f"成功加载 {len(documents)} 个文档")
    return documents

def split_documents(documents: List[Document], 
                    chunk_size: int = 1000, 
                    chunk_overlap: int = 100) -> List[Document]:
    """
    将文档分割成更小的块
    
    参数:
        documents: 要分割的文档列表
        chunk_size: 每个块的最大字符数
        chunk_overlap: 块之间的重叠字符数
    
    返回:
        分割后的文档块列表
    """
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        length_function=len,
        separators=["\n\n", "\n", "。", "，", " ", ""]
    )
    
    chunks = []
    for doc in tqdm(documents, desc="分割文档"):
        try:
            doc_chunks = text_splitter.split_documents([doc])
            chunks.extend(doc_chunks)
        except Exception as e:
            print(f"分割文档时出错: {e}")
    
    print(f"文档被分割成 {len(chunks)} 个块")
    return chunks 