#!/usr/bin/env python3
"""
输出内容审查模块
防范RAG模型输出敏感信息，保护系统和用户隐私
"""

import re
import json
import hashlib
from typing import Dict, List, Tuple, Optional, Union
from datetime import datetime
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OutputContentFilter:
    """RAG输出内容审查过滤器"""
    
    def __init__(self):
        self.sensitive_patterns = self._load_sensitive_patterns()
        self.replacement_rules = self._load_replacement_rules()
        self.semantic_rules = self._load_semantic_rules()
        self.whitelist_patterns = self._load_whitelist_patterns()
        
    def _load_sensitive_patterns(self) -> List[Dict]:
        """加载敏感信息匹配模式"""
        return [
            # 密码和认证信息
            {
                "name": "password_leak",
                "pattern": r"(?i)(password|密码|pwd)[:\s=]*['\"]?([a-zA-Z0-9@#$%^&*]{6,})['\"]?",
                "severity": "critical",
                "description": "检测到密码泄露",
                "replacement": "[密码已隐藏]"
            },
            {
                "name": "api_key_leak",
                "pattern": r"(?i)(api[_-]?key|token|secret)[:\s=]*['\"]?([a-zA-Z0-9_-]{20,})['\"]?",
                "severity": "critical", 
                "description": "检测到API密钥泄露",
                "replacement": "[API密钥已隐藏]"
            },
            {
                "name": "jwt_token",
                "pattern": r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
                "severity": "high",
                "description": "检测到JWT令牌",
                "replacement": "[令牌已隐藏]"
            },
            
            # 个人隐私信息
            {
                "name": "phone_number",
                "pattern": r"(?:\+86[-.\s]?)?1[3-9]\d{9}",
                "severity": "medium",
                "description": "检测到手机号码",
                "replacement": "[手机号已隐藏]"
            },
            {
                "name": "id_card",
                "pattern": r"[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[1-2]\d|3[0-1])\d{3}[\dXx]",
                "severity": "high",
                "description": "检测到身份证号",
                "replacement": "[身份证号已隐藏]"
            },
            {
                "name": "email_address",
                "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "severity": "medium",
                "description": "检测到邮箱地址",
                "replacement": "[邮箱已隐藏]"
            },
            
            # 系统敏感信息
            {
                "name": "ip_address",
                "pattern": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
                "severity": "medium",
                "description": "检测到IP地址",
                "replacement": "[IP地址已隐藏]"
            },
            {
                "name": "database_connection",
                "pattern": r"(?i)(mysql|postgresql|mongodb|redis)://[^\s]+",
                "severity": "critical",
                "description": "检测到数据库连接字符串",
                "replacement": "[数据库连接已隐藏]"
            },
            {
                "name": "file_path_sensitive",
                "pattern": r"(?i)(/etc/|/var/|/root/|C:\\Windows\\|C:\\Users\\)[^\s]*",
                "severity": "medium",
                "description": "检测到敏感文件路径",
                "replacement": "[文件路径已隐藏]"
            },
            
            # 系统配置和命令
            {
                "name": "system_command",
                "pattern": r"(?i)(sudo|rm -rf|del /f|format|fdisk|passwd|useradd|chmod 777)",
                "severity": "high",
                "description": "检测到危险系统命令",
                "replacement": "[系统命令已屏蔽]"
            },
            {
                "name": "config_leak",
                "pattern": r"(?i)(config|configuration)[:\s]*\{[^}]+\}",
                "severity": "medium",
                "description": "检测到配置信息泄露",
                "replacement": "[配置信息已隐藏]"
            },
            
            # 银行和金融信息
            {
                "name": "credit_card",
                "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
                "severity": "critical",
                "description": "检测到信用卡号",
                "replacement": "[信用卡号已隐藏]"
            },
            {
                "name": "bank_account",
                "pattern": r"(?i)(account|账户)[:\s]*[0-9]{10,20}",
                "severity": "high",
                "description": "检测到银行账户",
                "replacement": "[银行账户已隐藏]"
            },
            
            # 中文敏感内容
            {
                "name": "chinese_sensitive_tech",
                "pattern": r"(系统管理员密码|数据库密码|超级用户|root权限|管理员权限)",
                "severity": "critical",
                "description": "检测到中文敏感技术信息",
                "replacement": "[敏感信息已屏蔽]"
            },
            {
                "name": "chinese_personal_info",
                "pattern": r"(真实姓名|家庭住址|工作单位|银行卡号|社保号)",
                "severity": "high",
                "description": "检测到中文个人敏感信息",
                "replacement": "[个人信息已保护]"
            }
        ]
    
    def _load_replacement_rules(self) -> Dict:
        """加载内容替换规则"""
        return {
            "safe_alternatives": {
                "admin": "管理用户",
                "administrator": "系统管理人员", 
                "root": "超级用户",
                "password": "访问凭证",
                "secret": "机密信息",
                "private": "私有信息",
                "confidential": "保密内容"
            },
            "generic_replacements": {
                "具体IP": "网络地址",
                "具体端口": "服务端口",
                "具体路径": "文件位置",
                "具体用户名": "用户标识",
                "具体密码": "安全凭证"
            }
        }
    
    def _load_semantic_rules(self) -> List[Dict]:
        """加载语义分析规则"""
        return [
            {
                "name": "system_internal_discussion",
                "keywords": ["内部", "内网", "内部系统", "后台", "管理后台", "内部接口"],
                "context_keywords": ["访问", "连接", "登录", "进入"],
                "severity": "medium",
                "description": "检测到系统内部信息讨论"
            },
            {
                "name": "vulnerability_discussion", 
                "keywords": ["漏洞", "exploit", "vulnerability", "安全漏洞", "系统漏洞"],
                "context_keywords": ["利用", "攻击", "入侵", "破解"],
                "severity": "high",
                "description": "检测到安全漏洞相关讨论"
            },
            {
                "name": "privilege_escalation",
                "keywords": ["提权", "权限提升", "escalation", "sudo", "root"],
                "context_keywords": ["获取", "提升", "bypass", "绕过"],
                "severity": "high",
                "description": "检测到权限提升相关内容"
            },
            {
                "name": "data_extraction",
                "keywords": ["数据导出", "数据提取", "数据备份", "database dump"],
                "context_keywords": ["下载", "获取", "导出", "备份"],
                "severity": "medium",
                "description": "检测到数据提取相关内容"
            }
        ]
    
    def _load_whitelist_patterns(self) -> List[str]:
        """加载白名单模式（不需要过滤的内容）"""
        return [
            r"示例密码：\*+",  # 示例中的星号密码
            r"password.*示例",  # 示例中的密码说明
            r"IP地址.*例如",  # 举例说明的IP
            r"配置文件.*示例",  # 配置示例
            r"localhost",  # 本地地址
            r"127\.0\.0\.1",  # 本地IP
            r"example\.com",  # 示例域名
            r"测试.*密码",  # 测试密码说明
            r"假设.*账户"  # 假设账户说明
        ]
    
    def is_whitelisted(self, text: str, match_text: str) -> bool:
        """检查是否在白名单中"""
        for pattern in self.whitelist_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def detect_sensitive_patterns(self, text: str) -> List[Dict]:
        """检测敏感内容模式"""
        detected_issues = []
        
        for pattern_rule in self.sensitive_patterns:
            matches = list(re.finditer(pattern_rule["pattern"], text))
            
            for match in matches:
                matched_text = match.group()
                
                # 检查白名单
                if self.is_whitelisted(text, matched_text):
                    continue
                    
                detected_issues.append({
                    "type": "sensitive_pattern",
                    "name": pattern_rule["name"],
                    "severity": pattern_rule["severity"],
                    "description": pattern_rule["description"],
                    "matched_text": matched_text[:50] + "..." if len(matched_text) > 50 else matched_text,
                    "start_pos": match.start(),
                    "end_pos": match.end(),
                    "replacement": pattern_rule["replacement"]
                })
        
        return detected_issues
    
    def analyze_semantic_content(self, text: str) -> List[Dict]:
        """语义内容分析"""
        detected_issues = []
        text_lower = text.lower()
        
        for rule in self.semantic_rules:
            # 检查关键词和上下文
            has_keywords = any(keyword in text_lower for keyword in rule["keywords"])
            has_context = any(context in text_lower for context in rule["context_keywords"])
            
            if has_keywords and has_context:
                detected_issues.append({
                    "type": "semantic_analysis",
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "matched_keywords": [kw for kw in rule["keywords"] if kw in text_lower],
                    "context_keywords": [kw for kw in rule["context_keywords"] if kw in text_lower]
                })
        
        return detected_issues
    
    def check_context_safety(self, text: str) -> Dict:
        """检查上下文安全性"""
        safety_score = 100
        warnings = []
        
        # 检查是否涉及系统管理
        admin_keywords = ["管理员", "administrator", "admin", "root", "sudo"]
        if any(keyword in text.lower() for keyword in admin_keywords):
            safety_score -= 20
            warnings.append("涉及系统管理相关内容")
        
        # 检查是否涉及密码或认证
        auth_keywords = ["密码", "password", "认证", "authentication", "token", "令牌"]
        if any(keyword in text.lower() for keyword in auth_keywords):
            safety_score -= 15
            warnings.append("涉及认证或密码相关内容")
        
        # 检查是否涉及网络配置
        network_keywords = ["IP", "端口", "port", "网络配置", "防火墙", "firewall"]
        if any(keyword in text.lower() for keyword in network_keywords):
            safety_score -= 10
            warnings.append("涉及网络配置相关内容")
        
        # 检查是否涉及文件系统
        file_keywords = ["文件路径", "目录", "文件夹", "/etc/", "/var/", "C:\\"]
        if any(keyword in text.lower() for keyword in file_keywords):
            safety_score -= 10
            warnings.append("涉及文件系统相关内容")
        
        return {
            "safety_score": max(safety_score, 0),
            "warnings": warnings,
            "is_safe": safety_score >= 70
        }
    
    def sanitize_content(self, text: str, detection_results: List[Dict]) -> str:
        """对检测到的敏感内容进行清理"""
        sanitized_text = text
        
        # 按位置倒序排序，避免替换时位置偏移
        pattern_detections = [d for d in detection_results if d["type"] == "sensitive_pattern"]
        pattern_detections.sort(key=lambda x: x["start_pos"], reverse=True)
        
        # 替换敏感内容
        for detection in pattern_detections:
            start_pos = detection["start_pos"]
            end_pos = detection["end_pos"]
            replacement = detection["replacement"]
            
            sanitized_text = (
                sanitized_text[:start_pos] + 
                replacement + 
                sanitized_text[end_pos:]
            )
        
        return sanitized_text
    
    def add_safety_disclaimer(self, text: str, has_sensitive_content: bool) -> str:
        """添加安全声明"""
        if has_sensitive_content:
            disclaimer = "\n\n⚠️ **安全提醒**：以上回答中的敏感信息已被自动屏蔽，以保护系统和用户安全。"
            return text + disclaimer
        return text
    
    def calculate_risk_score(self, detection_results: List[Dict], context_safety: Dict) -> int:
        """计算输出风险评分"""
        severity_scores = {
            "critical": 40,
            "high": 25,
            "medium": 15,
            "low": 5
        }
        
        pattern_score = sum(
            severity_scores.get(result["severity"], 5) 
            for result in detection_results if result["type"] == "sensitive_pattern"
        )
        
        semantic_score = sum(
            severity_scores.get(result["severity"], 5) 
            for result in detection_results if result["type"] == "semantic_analysis"
        )
        
        context_penalty = max(0, 100 - context_safety["safety_score"])
        
        total_risk = pattern_score + semantic_score + (context_penalty * 0.3)
        return min(int(total_risk), 100)
    
    def filter_output(self, text: str, context: Dict = None) -> Dict:
        """主要过滤方法"""
        start_time = datetime.now()
        
        if not text or not isinstance(text, str):
            return {
                "filtered_text": text,
                "is_safe": True,
                "risk_score": 0,
                "detection_results": [],
                "processing_time": 0
            }
        
        # 执行各种检测
        detection_results = []
        detection_results.extend(self.detect_sensitive_patterns(text))
        detection_results.extend(self.analyze_semantic_content(text))
        
        # 上下文安全分析
        context_safety = self.check_context_safety(text)
        
        # 计算风险评分
        risk_score = self.calculate_risk_score(detection_results, context_safety)
        
        # 判断是否需要过滤
        has_sensitive_content = len(detection_results) > 0 or not context_safety["is_safe"]
        
        # 内容清理
        filtered_text = text
        if has_sensitive_content:
            filtered_text = self.sanitize_content(text, detection_results)
            filtered_text = self.add_safety_disclaimer(filtered_text, True)
        
        # 计算处理时间
        processing_time = (datetime.now() - start_time).total_seconds()
        
        # 记录高风险输出
        if risk_score >= 50:
            logger.warning(f"High-risk output detected. Risk score: {risk_score}")
            logger.warning(f"Detection results: {[d.get('name') for d in detection_results]}")
        
        return {
            "filtered_text": filtered_text,
            "original_text": text,
            "is_safe": risk_score < 30,
            "risk_score": risk_score,
            "detection_results": detection_results,
            "context_safety": context_safety,
            "has_sensitive_content": has_sensitive_content,
            "processing_time": processing_time
        }

# 全局实例
output_filter = OutputContentFilter()

def filter_rag_output(text: str, context: Dict = None) -> Dict:
    """过滤RAG输出内容的主要接口"""
    return output_filter.filter_output(text, context)

if __name__ == "__main__":
    # 测试示例
    test_outputs = [
        "网络安全是指保护网络系统免受攻击和数据泄露的技术和措施。",
        "系统管理员密码是admin123，请妥善保管。",
        "数据库连接字符串：mysql://root:password123@192.168.1.100:3306/userdb",
        "用户的手机号是13812345678，邮箱是user@example.com。",
        "要获取root权限，可以使用sudo命令进行权限提升。",
        "API密钥：sk-1234567890abcdef，请在配置文件中设置。",
        "身份证号：110101199001011234，请注意保护个人隐私。"
    ]
    
    print("=== RAG输出内容安全过滤测试 ===\n")
    
    for i, output_text in enumerate(test_outputs, 1):
        print(f"测试 {i}: {output_text}")
        result = filter_rag_output(output_text)
        
        print(f"安全评级: {'✅ 安全' if result['is_safe'] else '⚠️ 有风险'}")
        print(f"风险评分: {result['risk_score']}")
        print(f"敏感内容: {'是' if result['has_sensitive_content'] else '否'}")
        
        if result['detection_results']:
            print("检测结果:")
            for detection in result['detection_results']:
                print(f"  - {detection.get('name', 'unknown')}: {detection.get('description', 'N/A')}")
        
        if result['filtered_text'] != output_text:
            print(f"过滤后: {result['filtered_text']}")
        
        print("-" * 60) 