from typing import List, Dict, Any, Optional
# Conditional imports for different execution contexts
try:
    # When running as module
    from .tree_structure import ProblemTree, CheckItem, ProblemCategory, ProblemSeverity, TreeBuilder
    from .problem_classifier import ProblemClassifier
    from .vector_store import KubernetesSecurityVectorStore
    from .llm_integration import GeminiLLM
except ImportError:
    # When running directly
    from tree_structure import ProblemTree, CheckItem, ProblemCategory, ProblemSeverity, TreeBuilder
    from problem_classifier import ProblemClassifier
    from vector_store import KubernetesSecurityVectorStore
    from llm_integration import GeminiLLM
import uuid
from datetime import datetime


class ChecklistGenerator:
    """RAG와 LLM을 사용하여 Kubernetes 문제에 대한 상세한 체크리스트를 생성하는 시스템"""
    
    def __init__(self, 
                 vector_store: Optional[KubernetesSecurityVectorStore] = None,
                 llm: Optional[GeminiLLM] = None,
                 classifier: Optional[ProblemClassifier] = None):
        self.vector_store = vector_store or KubernetesSecurityVectorStore()
        self.llm = llm or GeminiLLM()
        self.classifier = classifier or ProblemClassifier(llm)
    
    def generate_checklist(self, 
                          user_input: str,
                          error_logs: Optional[str] = None,
                          user_context: Optional[Dict[str, Any]] = None) -> ProblemTree:
        """
        사용자 입력과 에러 로그를 바탕으로 체크리스트 생성
        
        Args:
            user_input: 사용자 문제 설명
            error_logs: 에러 로그 (선택사항)
            user_context: 사용자 환경 정보 (선택사항)
        
        Returns:
            ProblemTree: 완성된 체크리스트 트리
        """
        
        # 1단계: 문제 분류
        classification = self.classifier.classify_problem(user_input, error_logs, user_context)
        categories = classification["categories"]
        
        # 2단계: 기본 트리 구조 생성
        problem_tree = TreeBuilder.create_problem_tree(
            problem_description=user_input,
            categories=categories,
            user_context=user_context or {}
        )
        
        # 3단계: RAG를 사용한 상세 체크리스트 생성
        detailed_tree = self._expand_tree_with_rag(problem_tree, classification, user_context)
        
        # 4단계: LLM을 사용한 해결 가이드 생성
        final_tree = self._add_solution_guides(detailed_tree, user_input, error_logs)
        
        # 5단계: 메타데이터 설정
        final_tree.created_at = datetime.now().isoformat()
        final_tree.metadata = {
            "original_input": user_input,
            "error_logs": error_logs,
            "classification": classification,
            "generated_at": datetime.now().isoformat()
        }
        
        return final_tree
    
    def _expand_tree_with_rag(self, 
                             tree: ProblemTree, 
                             classification: Dict[str, Any],
                             user_context: Optional[Dict[str, Any]]) -> ProblemTree:
        """RAG를 사용하여 트리를 상세하게 확장"""
        
        for category_node in tree.root.children:
            category = category_node.category
            
            # RAG로 관련 정보 검색
            search_query = f"{category.value} problems troubleshooting kubernetes"
            search_results = self.vector_store.search(
                query=search_query,
                n_results=5
            )
            
            # 카테고리별 체크 항목 생성
            check_items = self._generate_category_check_items(
                category, 
                search_results, 
                classification,
                user_context
            )
            
            # 트리에 추가
            for item in check_items:
                category_node.add_child(item)
        
        return tree
    
    def _generate_category_check_items(self,
                                     category: ProblemCategory,
                                     search_results: List[Dict[str, Any]],
                                     classification: Dict[str, Any],
                                     user_context: Optional[Dict[str, Any]]) -> List[CheckItem]:
        """카테고리별 체크 항목 생성"""
        
        # 카테고리별 기본 체크 항목 템플릿
        category_templates = self._get_category_templates(category)
        
        check_items = []
        
        for template in category_templates:
            # RAG 결과와 결합하여 상세 정보 생성
            detailed_info = self._enrich_with_rag(template, search_results, user_context)
            
            check_item = CheckItem(
                id=str(uuid.uuid4()),
                title=detailed_info["title"],
                description=detailed_info["description"],
                category=category,
                severity=detailed_info["severity"],
                solution_guide=detailed_info["solution_guide"],
                related_docs=detailed_info["related_docs"],
                metadata=detailed_info["metadata"]
            )
            
            # 하위 체크 항목 추가
            sub_items = self._generate_sub_check_items(template, search_results)
            for sub_item in sub_items:
                check_item.add_child(sub_item)
            
            check_items.append(check_item)
        
        return check_items
    
    def _get_category_templates(self, category: ProblemCategory) -> List[Dict[str, Any]]:
        """카테고리별 기본 체크 항목 템플릿"""
        
        templates = {
            ProblemCategory.NETWORK: [
                {
                    "title": "Service 연결 확인",
                    "description": "Service가 올바르게 생성되고 Endpoint가 정상인지 확인",
                    "severity": ProblemSeverity.HIGH,
                    "sub_items": [
                        "Service 정의 확인",
                        "Endpoint 상태 확인", 
                        "Selector 매칭 확인",
                        "Port 설정 확인"
                    ]
                },
                {
                    "title": "Ingress 설정 확인",
                    "description": "Ingress Controller와 Ingress 규칙이 올바른지 확인",
                    "severity": ProblemSeverity.HIGH,
                    "sub_items": [
                        "Ingress Controller 상태 확인",
                        "Ingress 규칙 문법 확인",
                        "SSL 인증서 확인",
                        "Path 설정 확인"
                    ]
                },
                {
                    "title": "Network Policy 확인",
                    "description": "Network Policy가 트래픽을 차단하고 있지 않은지 확인",
                    "severity": ProblemSeverity.MEDIUM,
                    "sub_items": [
                        "Network Policy 규칙 확인",
                        "Pod Selector 확인",
                        "Port 규칙 확인"
                    ]
                }
            ],
            ProblemCategory.SECURITY: [
                {
                    "title": "RBAC 권한 확인",
                    "description": "ServiceAccount, Role, RoleBinding 설정 확인",
                    "severity": ProblemSeverity.CRITICAL,
                    "sub_items": [
                        "ServiceAccount 존재 확인",
                        "Role 권한 확인",
                        "RoleBinding 연결 확인",
                        "Namespace 권한 확인"
                    ]
                },
                {
                    "title": "Security Context 확인",
                    "description": "Pod와 Container Security Context 설정 확인",
                    "severity": ProblemSeverity.CRITICAL,
                    "sub_items": [
                        "runAsNonRoot 설정 확인",
                        "runAsUser 설정 확인",
                        "Capabilities 설정 확인",
                        "readOnlyRootFilesystem 확인"
                    ]
                },
                {
                    "title": "Pod Security Standards 확인",
                    "description": "Pod Security Standards 준수 여부 확인",
                    "severity": ProblemSeverity.HIGH,
                    "sub_items": [
                        "Baseline 정책 준수 확인",
                        "Restricted 정책 준수 확인",
                        "Admission Controller 설정 확인"
                    ]
                }
            ],
            ProblemCategory.RESOURCE: [
                {
                    "title": "리소스 제한 확인",
                    "description": "CPU, Memory 리소스 제한 설정 확인",
                    "severity": ProblemSeverity.HIGH,
                    "sub_items": [
                        "Resource Limits 확인",
                        "Resource Requests 확인",
                        "Node 리소스 가용성 확인",
                        "Quota 설정 확인"
                    ]
                },
                {
                    "title": "Storage 문제 확인",
                    "description": "PVC, StorageClass, Volume 설정 확인",
                    "severity": ProblemSeverity.MEDIUM,
                    "sub_items": [
                        "PVC 상태 확인",
                        "StorageClass 설정 확인",
                        "Volume 권한 확인",
                        "Storage 용량 확인"
                    ]
                }
            ],
            ProblemCategory.DEPLOYMENT: [
                {
                    "title": "배포 전략 확인",
                    "description": "Rolling Update, Blue-Green, Canary 배포 설정 확인",
                    "severity": ProblemSeverity.MEDIUM,
                    "sub_items": [
                        "ReplicaSet 상태 확인",
                        "Rolling Update 설정 확인",
                        "Rollback 가능성 확인",
                        "배포 이력 확인"
                    ]
                }
            ],
            ProblemCategory.MONITORING: [
                {
                    "title": "모니터링 설정 확인",
                    "description": "Prometheus, Grafana, 로깅 설정 확인",
                    "severity": ProblemSeverity.MEDIUM,
                    "sub_items": [
                        "메트릭 수집 확인",
                        "알림 설정 확인",
                        "로그 수집 확인",
                        "대시보드 접근 확인"
                    ]
                }
            ],
            ProblemCategory.INTEGRATION: [
                {
                    "title": "CI/CD 파이프라인 확인",
                    "description": "Jenkins, GitLab, ArgoCD 등 CI/CD 설정 확인",
                    "severity": ProblemSeverity.MEDIUM,
                    "sub_items": [
                        "파이프라인 상태 확인",
                        "빌드 로그 확인",
                        "배포 권한 확인",
                        "Git 연동 확인"
                    ]
                }
            ]
        }
        
        return templates.get(category, [])
    
    def _enrich_with_rag(self, 
                        template: Dict[str, Any],
                        search_results: List[Dict[str, Any]],
                        user_context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """RAG 결과를 사용하여 템플릿을 풍부하게 만듦"""
        
        # 검색 결과에서 관련 정보 추출
        related_content = []
        for result in search_results:
            related_content.append(result.get("content", ""))
        
        # 템플릿 정보와 RAG 결과 결합
        enriched = template.copy()
        enriched["related_docs"] = [result.get("metadata", {}).get("source", "") for result in search_results]
        enriched["metadata"] = {
            "rag_sources": len(search_results),
            "user_context": user_context
        }
        
        # solution_guide가 없으면 빈 문자열로 설정
        if "solution_guide" not in enriched:
            enriched["solution_guide"] = ""
        
        return enriched
    
    def _generate_sub_check_items(self, 
                                 template: Dict[str, Any],
                                 search_results: List[Dict[str, Any]]) -> List[CheckItem]:
        """하위 체크 항목 생성"""
        
        sub_items = []
        for sub_title in template.get("sub_items", []):
            sub_item = CheckItem(
                id=str(uuid.uuid4()),
                title=sub_title,
                description=f"{sub_title}에 대한 상세 확인",
                category=template.get("category", ProblemCategory.NETWORK),
                severity=template.get("severity", ProblemSeverity.MEDIUM)
            )
            sub_items.append(sub_item)
        
        return sub_items
    
    def _add_solution_guides(self, 
                           tree: ProblemTree,
                           user_input: str,
                           error_logs: Optional[str] = None) -> ProblemTree:
        """LLM을 사용하여 해결 가이드 추가"""
        
        for item in tree.get_all_items():
            if not item.solution_guide and item.children:  # 하위 항목이 있는 경우만
                solution_guide = self._generate_solution_guide(item, user_input, error_logs)
                item.solution_guide = solution_guide
        
        return tree
    
    def _generate_solution_guide(self, 
                               item: CheckItem,
                               user_input: str,
                               error_logs: Optional[str] = None) -> str:
        """LLM을 사용하여 해결 가이드 생성"""
        
        prompt = f"""
다음 Kubernetes 문제에 대한 해결 가이드를 한국어로 작성해주세요:

문제 항목: {item.title}
설명: {item.description}
카테고리: {item.category.value}
심각도: {item.severity.value}

사용자 입력: {user_input}
에러 로그: {error_logs or "제공되지 않음"}

다음 형식으로 작성해주세요:
1. 문제 원인 분석
2. 단계별 해결 방법
3. 확인해야 할 명령어
4. 예방 조치

실무자(DevOps, SRE)가 바로 적용할 수 있도록 구체적으로 작성해주세요.
"""
        
        try:
            response = self.llm.answer_security_question(
                question=prompt,
                search_results=[],
                policy_level=None
            )
            return response
        except Exception as e:
            return f"해결 가이드 생성 중 오류 발생: {str(e)}"
    
    def update_checklist_progress(self, 
                                tree: ProblemTree,
                                item_id: str,
                                is_checked: bool,
                                user_notes: str = "") -> ProblemTree:
        """체크리스트 진행 상황 업데이트"""
        
        def update_item_recursive(item: CheckItem) -> bool:
            if item.id == item_id:
                item.is_checked = is_checked
                item.user_notes = user_notes
                return True
            
            for child in item.children:
                if update_item_recursive(child):
                    return True
            
            return False
        
        update_item_recursive(tree.root)
        return tree
    
    def get_next_recommended_item(self, tree: ProblemTree) -> Optional[CheckItem]:
        """다음에 확인해야 할 항목 추천"""
        
        # Critical 항목 중 미확인 항목 우선
        critical_items = tree.get_critical_items()
        unchecked_critical = [item for item in critical_items if not item.is_checked]
        
        if unchecked_critical:
            return unchecked_critical[0]
        
        # High 항목 중 미확인 항목
        high_items = tree.get_items_by_severity(ProblemSeverity.HIGH)
        unchecked_high = [item for item in high_items if not item.is_checked]
        
        if unchecked_high:
            return unchecked_high[0]
        
        # Medium 항목 중 미확인 항목
        medium_items = tree.get_items_by_severity(ProblemSeverity.MEDIUM)
        unchecked_medium = [item for item in medium_items if not item.is_checked]
        
        if unchecked_medium:
            return unchecked_medium[0]
        
        return None 