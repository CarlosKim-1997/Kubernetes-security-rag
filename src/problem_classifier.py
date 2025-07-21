from typing import List, Dict, Any, Optional
# Conditional imports for different execution contexts
try:
    # When running as module
    from .tree_structure import ProblemCategory, ProblemSeverity
    from .llm_integration import GeminiLLM
except ImportError:
    # When running directly
    from tree_structure import ProblemCategory, ProblemSeverity
    from llm_integration import GeminiLLM
import json
import re


class ProblemClassifier:
    """사용자 입력과 에러 로그를 분석하여 문제 카테고리를 분류하는 시스템"""
    
    def __init__(self, llm: Optional[GeminiLLM] = None):
        self.llm = llm or GeminiLLM()
    
    def classify_problem(self, 
                        user_input: str, 
                        error_logs: Optional[str] = None,
                        user_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        사용자 입력과 에러 로그를 분석하여 문제 카테고리 분류
        
        Returns:
            Dict containing:
            - categories: List[ProblemCategory]
            - confidence_scores: Dict[ProblemCategory, float]
            - keywords: List[str]
            - severity_estimate: ProblemSeverity
            - analysis_summary: str
        """
        
        # LLM을 사용한 문제 분류
        classification_result = self._llm_classify_problem(user_input, error_logs, user_context)
        
        # 결과 파싱 및 검증
        categories = self._parse_categories(classification_result.get("categories", []))
        confidence_scores = classification_result.get("confidence_scores", {})
        keywords = classification_result.get("keywords", [])
        severity_estimate = self._parse_severity(classification_result.get("severity", "medium"))
        analysis_summary = classification_result.get("analysis_summary", "")
        
        return {
            "categories": categories,
            "confidence_scores": confidence_scores,
            "keywords": keywords,
            "severity_estimate": severity_estimate,
            "analysis_summary": analysis_summary,
            "raw_llm_response": classification_result
        }
    
    def _llm_classify_problem(self, 
                            user_input: str, 
                            error_logs: Optional[str] = None,
                            user_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """LLM을 사용한 문제 분류"""
        
        context_info = ""
        if user_context:
            context_info = f"""
사용자 환경 정보:
- Kubernetes 버전: {user_context.get('kubernetes_version', '알 수 없음')}
- 클라우드 플랫폼: {user_context.get('cloud_platform', '알 수 없음')}
- 클러스터 타입: {user_context.get('cluster_type', '알 수 없음')}
- 보안 레벨: {user_context.get('security_level', '알 수 없음')}
"""
        
        prompt = f"""
아래는 쿠버네티스 문제 상황에 대한 사용자 입력과 에러 로그입니다. 
이를 분석하여 관련된 문제 카테고리들을 분류해주세요.

사용자 입력: {user_input}

에러 로그: {error_logs or "제공되지 않음"}

{context_info}

분류해야 할 문제 카테고리들:
1. network - 네트워크 문제 (Service, Ingress, Network Policy 등)
2. security - 보안 문제 (RBAC, Security Context, Pod Security Standards 등)
3. resource - 리소스 문제 (CPU, Memory, Storage 등)
4. deployment - 배포 문제 (Rolling Update, Blue-Green, Canary 등)
5. monitoring - 모니터링/로깅 문제 (Prometheus, ELK Stack 등)
6. integration - 통합 문제 (CI/CD, GitOps, Helm 등)

다음 JSON 형식으로 답변해주세요:
{{
    "categories": ["network", "security"],
    "confidence_scores": {{
        "network": 0.8,
        "security": 0.6
    }},
    "keywords": ["service", "connection", "timeout"],
    "severity": "high",
    "analysis_summary": "네트워크 연결 문제로 보이며, 보안 설정도 확인이 필요합니다."
}}

답변은 반드시 유효한 JSON 형식이어야 합니다.
"""
        
        try:
            response = self.llm.answer_security_question(
                question=prompt,
                search_results=[],  # RAG 검색 없이 직접 분류
                policy_level=None
            )
            
            # JSON 파싱 시도
            try:
                # JSON 부분만 추출
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    json_str = json_match.group()
                    return json.loads(json_str)
                else:
                    # JSON이 없으면 기본값 반환
                    return self._default_classification()
                    
            except json.JSONDecodeError:
                # JSON 파싱 실패시 기본값 반환
                return self._default_classification()
                
        except Exception as e:
            print(f"LLM 분류 오류: {e}")
            return self._default_classification()
    
    def _parse_categories(self, category_list: List[str]) -> List[ProblemCategory]:
        """카테고리 문자열을 enum으로 변환"""
        category_mapping = {
            "network": ProblemCategory.NETWORK,
            "security": ProblemCategory.SECURITY,
            "resource": ProblemCategory.RESOURCE,
            "deployment": ProblemCategory.DEPLOYMENT,
            "monitoring": ProblemCategory.MONITORING,
            "integration": ProblemCategory.INTEGRATION
        }
        
        categories = []
        for cat_str in category_list:
            if cat_str.lower() in category_mapping:
                categories.append(category_mapping[cat_str.lower()])
        
        # 카테고리가 없으면 기본값
        if not categories:
            categories = [ProblemCategory.NETWORK, ProblemCategory.SECURITY]
        
        return categories
    
    def _parse_severity(self, severity_str: str) -> ProblemSeverity:
        """심각도 문자열을 enum으로 변환"""
        severity_mapping = {
            "critical": ProblemSeverity.CRITICAL,
            "high": ProblemSeverity.HIGH,
            "medium": ProblemSeverity.MEDIUM,
            "low": ProblemSeverity.LOW
        }
        
        return severity_mapping.get(severity_str.lower(), ProblemSeverity.MEDIUM)
    
    def _default_classification(self) -> Dict[str, Any]:
        """기본 분류 결과"""
        return {
            "categories": ["network", "security"],
            "confidence_scores": {
                "network": 0.5,
                "security": 0.5
            },
            "keywords": ["kubernetes", "problem"],
            "severity": "medium",
            "analysis_summary": "기본 분류: 네트워크 및 보안 문제 확인 필요"
        }
    
    def extract_keywords(self, text: str) -> List[str]:
        """텍스트에서 키워드 추출"""
        # 간단한 키워드 추출 (나중에 더 정교하게 개선 가능)
        kubernetes_keywords = [
            "pod", "service", "deployment", "ingress", "rbac", "security",
            "network", "resource", "cpu", "memory", "storage", "volume",
            "configmap", "secret", "namespace", "node", "cluster",
            "error", "failed", "timeout", "connection", "permission",
            "restart", "crash", "oom", "evicted", "pending", "running"
        ]
        
        found_keywords = []
        text_lower = text.lower()
        
        for keyword in kubernetes_keywords:
            if keyword in text_lower:
                found_keywords.append(keyword)
        
        return found_keywords
    
    def estimate_severity(self, 
                         categories: List[ProblemCategory],
                         error_logs: Optional[str] = None) -> ProblemSeverity:
        """카테고리와 에러 로그를 바탕으로 심각도 추정"""
        
        # 보안 문제가 있으면 Critical
        if ProblemCategory.SECURITY in categories:
            return ProblemSeverity.CRITICAL
        
        # 에러 로그에서 심각도 키워드 확인
        if error_logs:
            critical_keywords = ["fatal", "panic", "crash", "oom", "evicted"]
            high_keywords = ["error", "failed", "timeout", "connection refused"]
            
            error_lower = error_logs.lower()
            
            if any(keyword in error_lower for keyword in critical_keywords):
                return ProblemSeverity.CRITICAL
            elif any(keyword in error_lower for keyword in high_keywords):
                return ProblemSeverity.HIGH
        
        # 네트워크나 리소스 문제면 High
        if ProblemCategory.NETWORK in categories or ProblemCategory.RESOURCE in categories:
            return ProblemSeverity.HIGH
        
        # 기본값
        return ProblemSeverity.MEDIUM


class KeywordBasedClassifier:
    """키워드 기반 빠른 분류 (LLM 없이도 동작)"""
    
    def __init__(self):
        self.category_keywords = {
            ProblemCategory.NETWORK: [
                "service", "ingress", "network", "connection", "timeout",
                "port", "endpoint", "loadbalancer", "clusterip", "nodeport"
            ],
            ProblemCategory.SECURITY: [
                "rbac", "security", "permission", "access", "denied",
                "context", "privileged", "capabilities", "seccomp", "apparmor"
            ],
            ProblemCategory.RESOURCE: [
                "cpu", "memory", "storage", "disk", "volume", "quota",
                "limit", "request", "oom", "evicted", "pending"
            ],
            ProblemCategory.DEPLOYMENT: [
                "deployment", "rolling", "update", "rollback", "replica",
                "scale", "autoscaling", "blue-green", "canary"
            ],
            ProblemCategory.MONITORING: [
                "prometheus", "grafana", "elk", "logging", "metrics",
                "alert", "monitoring", "dashboard", "log"
            ],
            ProblemCategory.INTEGRATION: [
                "ci/cd", "gitops", "helm", "chart", "pipeline",
                "jenkins", "gitlab", "github", "argo"
            ]
        }
    
    def classify_by_keywords(self, text: str) -> List[ProblemCategory]:
        """키워드 기반으로 카테고리 분류"""
        text_lower = text.lower()
        matched_categories = []
        
        for category, keywords in self.category_keywords.items():
            if any(keyword in text_lower for keyword in keywords):
                matched_categories.append(category)
        
        return matched_categories or [ProblemCategory.NETWORK, ProblemCategory.SECURITY] 