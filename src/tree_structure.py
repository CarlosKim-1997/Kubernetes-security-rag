from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class ProblemSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ProblemCategory(Enum):
    NETWORK = "network"
    SECURITY = "security"
    RESOURCE = "resource"
    DEPLOYMENT = "deployment"
    MONITORING = "monitoring"
    INTEGRATION = "integration"


@dataclass
class CheckItem:
    """체크리스트의 개별 항목"""
    id: str
    title: str
    description: str
    category: ProblemCategory
    severity: ProblemSeverity
    children: List['CheckItem'] = field(default_factory=list)
    solution_guide: str = ""
    related_docs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_checked: bool = False
    user_notes: str = ""

    def add_child(self, child: 'CheckItem'):
        """자식 항목 추가"""
        self.children.append(child)

    def get_all_children(self) -> List['CheckItem']:
        """모든 하위 항목을 재귀적으로 가져오기"""
        all_children = []
        for child in self.children:
            all_children.append(child)
            all_children.extend(child.get_all_children())
        return all_children

    def get_checked_count(self) -> int:
        """체크된 항목 수 계산"""
        count = 1 if self.is_checked else 0
        for child in self.children:
            count += child.get_checked_count()
        return count

    def get_total_count(self) -> int:
        """전체 항목 수 계산"""
        count = 1
        for child in self.children:
            count += child.get_total_count()
        return count

    def get_progress_percentage(self) -> float:
        """진행률 계산"""
        total = self.get_total_count()
        if total == 0:
            return 0.0
        return (self.get_checked_count() / total) * 100


@dataclass
class ProblemTree:
    """문제 진단을 위한 트리 구조"""
    root: CheckItem
    created_at: str = ""
    user_context: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_all_items(self) -> List[CheckItem]:
        """트리의 모든 항목을 가져오기"""
        return [self.root] + self.root.get_all_children()

    def get_items_by_category(self, category: ProblemCategory) -> List[CheckItem]:
        """카테고리별 항목 필터링"""
        return [item for item in self.get_all_items() if item.category == category]

    def get_items_by_severity(self, severity: ProblemSeverity) -> List[CheckItem]:
        """심각도별 항목 필터링"""
        return [item for item in self.get_all_items() if item.severity == severity]

    def get_critical_items(self) -> List[CheckItem]:
        """Critical 항목만 가져오기"""
        return self.get_items_by_severity(ProblemSeverity.CRITICAL)

    def get_progress_summary(self) -> Dict[str, Any]:
        """전체 진행 상황 요약"""
        total_items = self.root.get_total_count()
        checked_items = self.root.get_checked_count()
        
        return {
            "total_items": total_items,
            "checked_items": checked_items,
            "progress_percentage": self.root.get_progress_percentage(),
            "critical_items": len(self.get_critical_items()),
            "categories": {
                cat.value: len(self.get_items_by_category(cat))
                for cat in ProblemCategory
            }
        }

    def to_dict(self) -> Dict[str, Any]:
        """트리를 딕셔너리로 변환 (JSON 직렬화용)"""
        def item_to_dict(item: CheckItem) -> Dict[str, Any]:
            return {
                "id": item.id,
                "title": item.title,
                "description": item.description,
                "category": item.category.value,
                "severity": item.severity.value,
                "children": [item_to_dict(child) for child in item.children],
                "solution_guide": item.solution_guide,
                "related_docs": item.related_docs,
                "metadata": item.metadata,
                "is_checked": item.is_checked,
                "user_notes": item.user_notes
            }
        
        return {
            "root": item_to_dict(self.root),
            "created_at": self.created_at,
            "user_context": self.user_context,
            "metadata": self.metadata
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProblemTree':
        """딕셔너리에서 트리 생성"""
        def dict_to_item(item_data: Dict[str, Any]) -> CheckItem:
            children = [dict_to_item(child) for child in item_data.get("children", [])]
            return CheckItem(
                id=item_data["id"],
                title=item_data["title"],
                description=item_data["description"],
                category=ProblemCategory(item_data["category"]),
                severity=ProblemSeverity(item_data["severity"]),
                children=children,
                solution_guide=item_data.get("solution_guide", ""),
                related_docs=item_data.get("related_docs", []),
                metadata=item_data.get("metadata", {}),
                is_checked=item_data.get("is_checked", False),
                user_notes=item_data.get("user_notes", "")
            )
        
        return cls(
            root=dict_to_item(data["root"]),
            created_at=data.get("created_at", ""),
            user_context=data.get("user_context", {}),
            metadata=data.get("metadata", {})
        )


class TreeBuilder:
    """트리 구조를 생성하는 빌더 클래스"""
    
    @staticmethod
    def create_problem_tree(problem_description: str, 
                           categories: List[ProblemCategory],
                           user_context: Dict[str, Any]) -> ProblemTree:
        """문제 설명과 카테고리를 바탕으로 트리 생성"""
        
        # 루트 노드 생성
        root = CheckItem(
            id="root",
            title="문제 진단 체크리스트",
            description=f"'{problem_description}'에 대한 종합 진단",
            category=ProblemCategory.NETWORK,  # 루트는 기본값
            severity=ProblemSeverity.MEDIUM
        )
        
        # 각 카테고리별로 하위 노드 생성
        for category in categories:
            category_node = TreeBuilder._create_category_node(category)
            root.add_child(category_node)
        
        return ProblemTree(
            root=root,
            created_at="",  # 생성 시간은 나중에 설정
            user_context=user_context
        )
    
    @staticmethod
    def _create_category_node(category: ProblemCategory) -> CheckItem:
        """카테고리별 기본 노드 생성"""
        category_info = {
            ProblemCategory.NETWORK: {
                "title": "네트워크 문제",
                "description": "Service, Ingress, Network Policy 관련 문제",
                "severity": ProblemSeverity.HIGH
            },
            ProblemCategory.SECURITY: {
                "title": "보안 문제", 
                "description": "RBAC, Security Context, Pod Security Standards 관련 문제",
                "severity": ProblemSeverity.CRITICAL
            },
            ProblemCategory.RESOURCE: {
                "title": "리소스 문제",
                "description": "CPU, Memory, Storage 관련 문제",
                "severity": ProblemSeverity.HIGH
            },
            ProblemCategory.DEPLOYMENT: {
                "title": "배포 문제",
                "description": "Rolling Update, Blue-Green, Canary 배포 관련 문제",
                "severity": ProblemSeverity.MEDIUM
            },
            ProblemCategory.MONITORING: {
                "title": "모니터링/로깅 문제",
                "description": "Prometheus, ELK Stack, 로그 수집 관련 문제",
                "severity": ProblemSeverity.MEDIUM
            },
            ProblemCategory.INTEGRATION: {
                "title": "통합 문제",
                "description": "CI/CD, GitOps, Helm 차트 관련 문제",
                "severity": ProblemSeverity.MEDIUM
            }
        }
        
        info = category_info[category]
        return CheckItem(
            id=f"category_{category.value}",
            title=info["title"],
            description=info["description"],
            category=category,
            severity=info["severity"]
        ) 