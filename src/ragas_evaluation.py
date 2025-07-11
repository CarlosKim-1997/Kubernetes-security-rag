import os
import json
import pandas as pd
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import random

# Conditional imports for different execution contexts
try:
    from .rag_system import KubernetesSecurityRAG
    from .versioned_vector_store import VersionedKubernetesVectorStore
    from .schema import PolicyLevel
except ImportError:
    from rag_system import KubernetesSecurityRAG
    from versioned_vector_store import VersionedKubernetesVectorStore
    from schema import PolicyLevel


@dataclass
class EvaluationExample:
    """RAGAS 평가를 위한 예시 데이터 구조"""
    question: str
    ground_truth: str
    context: List[str]
    answer: str
    metadata: Dict[str, Any]


class RAGASEvaluator:
    """RAGAS를 사용한 RAG 시스템 평가"""
    
    def __init__(self, rag_system: Optional[KubernetesSecurityRAG] = None):
        """Initialize the evaluator"""
        if rag_system is None:
            # 기본 vector_store로 RAG 시스템 초기화
            from .vector_store import KubernetesSecurityVectorStore
            vector_store = KubernetesSecurityVectorStore()
            self.rag_system = KubernetesSecurityRAG(vector_store=vector_store)
        else:
            self.rag_system = rag_system
        self.evaluation_data = []
        
    def generate_test_dataset(self, num_examples: int = 50) -> List[EvaluationExample]:
        """Kubernetes 보안 관련 테스트 데이터셋 생성"""
        
        # 다양한 유형의 질문들
        question_templates = [
            # Pod Security Standards 관련
            "Pod Security Standards의 {} 정책 레벨에서 {}는 어떻게 설정해야 하나요?",
            "{} 버전에서 {} 보안 설정의 권장사항은 무엇인가요?",
            "{} 정책 레벨을 준수하기 위해 {} 필드를 어떻게 구성해야 하나요?",
            
            # 구체적인 보안 필드 관련
            "runAsNonRoot를 true로 설정하는 이유는 무엇인가요?",
            "privileged 컨테이너의 보안 위험은 무엇인가요?",
            "securityContext에서 allowPrivilegeEscalation을 false로 설정하는 이유는?",
            "readOnlyRootFilesystem을 true로 설정하면 어떤 이점이 있나요?",
            
            # 문제 해결 관련
            "Pod가 {} 오류로 시작되지 않을 때 어떻게 해결하나요?",
            "{} 보안 정책 위반을 해결하는 방법은 무엇인가요?",
            "{} 설정으로 인한 보안 취약점을 어떻게 수정하나요?",
            
            # 버전별 차이점
            "Kubernetes {} 버전에서 {}의 변경사항은 무엇인가요?",
            "{} 버전에서 {} 정책이 어떻게 달라졌나요?",
        ]
        
        # 보안 필드들
        security_fields = [
            "runAsNonRoot", "runAsUser", "runAsGroup", "fsGroup",
            "privileged", "allowPrivilegeEscalation", "readOnlyRootFilesystem",
            "capabilities", "seccompProfile", "securityContext"
        ]
        
        # 정책 레벨들
        policy_levels = ["baseline", "restricted"]
        
        # Kubernetes 버전들
        versions = ["1.24", "1.25", "1.26", "1.27", "1.28"]
        
        # 오류 메시지들
        error_messages = [
            "PodSecurityPolicy", "forbidden", "security context", 
            "privileged container", "run as root"
        ]
        
        examples = []
        
        for i in range(num_examples):
            # 랜덤하게 템플릿과 파라미터 선택
            template = random.choice(question_templates)
            
            if "{}" in template:
                if "정책 레벨" in template:
                    question = template.format(
                        random.choice(policy_levels),
                        random.choice(security_fields)
                    )
                elif "버전" in template:
                    question = template.format(
                        random.choice(versions),
                        random.choice(security_fields)
                    )
                elif "오류" in template:
                    question = template.format(
                        random.choice(error_messages)
                    )
                else:
                    question = template.format(
                        random.choice(security_fields),
                        random.choice(policy_levels)
                    )
            else:
                question = template
            
            # Ground truth 생성 (실제로는 전문가가 작성해야 함)
            ground_truth = self._generate_ground_truth(question)
            
            # RAG 시스템으로 답변 생성
            answer_result = self.rag_system.answer_security_question(
                question=question,
                kubernetes_version=random.choice(versions),
                use_llm=True
            )
            
            # 컨텍스트 추출
            context = [result["content"] for result in answer_result.get("sources", [])]
            answer = answer_result.get("llm_answer", answer_result.get("answer", ""))
            
            # 메타데이터
            metadata = {
                "kubernetes_version": answer_result.get("kubernetes_version"),
                "policy_level": answer_result.get("policy_level"),
                "question_type": self._classify_question_type(question),
                "sources_count": len(answer_result.get("sources", []))
            }
            
            example = EvaluationExample(
                question=question,
                ground_truth=ground_truth,
                context=context,
                answer=answer,
                metadata=metadata
            )
            
            examples.append(example)
        
        return examples
    
    def _generate_ground_truth(self, question: str) -> str:
        """질문에 대한 ground truth 답변 생성 (실제로는 전문가가 작성)"""
        # 간단한 규칙 기반 ground truth 생성
        if "runAsNonRoot" in question:
            return "runAsNonRoot를 true로 설정하면 컨테이너가 root 사용자로 실행되는 것을 방지하여 보안을 강화할 수 있습니다. 이는 컨테이너가 호스트 시스템의 민감한 파일에 접근하는 것을 막고, 권한 상승 공격의 위험을 줄입니다."
        elif "privileged" in question:
            return "privileged 컨테이너는 호스트의 모든 기능에 접근할 수 있어 매우 위험합니다. 보안상 privileged: false로 설정하고, 필요한 경우에만 특정 capabilities를 추가하는 것이 좋습니다."
        elif "allowPrivilegeEscalation" in question:
            return "allowPrivilegeEscalation을 false로 설정하면 컨테이너 내에서 권한 상승을 방지할 수 있습니다. 이는 setuid 바이너리나 sudo 명령어 사용을 막아 보안을 강화합니다."
        elif "readOnlyRootFilesystem" in question:
            return "readOnlyRootFilesystem을 true로 설정하면 컨테이너의 루트 파일시스템을 읽기 전용으로 만들어, 악성 코드가 파일을 수정하거나 로그를 조작하는 것을 방지할 수 있습니다."
        else:
            return "이 질문에 대한 정확한 답변을 제공하기 위해서는 Kubernetes 보안 문서를 참조하거나 전문가의 검토가 필요합니다."
    
    def _classify_question_type(self, question: str) -> str:
        """질문 유형 분류"""
        if "어떻게" in question or "방법" in question:
            return "how_to"
        elif "이유" in question or "왜" in question:
            return "why"
        elif "무엇" in question or "뭐" in question:
            return "what"
        elif "오류" in question or "해결" in question:
            return "troubleshooting"
        else:
            return "general"
    
    def prepare_ragas_dataset(self, examples: List[EvaluationExample]) -> pd.DataFrame:
        """RAGAS 형식의 데이터셋 준비"""
        
        data = []
        for example in examples:
            # contexts를 문자열로 결합
            context_text = "\n\n".join(example.context) if example.context else ""
            
            data.append({
                "question": example.question,
                "ground_truth": example.ground_truth,
                "contexts": [context_text],  # RAGAS는 contexts를 리스트의 리스트로 요구하지만, 각 요소는 문자열
                "answer": example.answer,
                "metadata": example.metadata
            })
        
        return pd.DataFrame(data)
    
    def save_evaluation_data(self, examples: List[EvaluationExample], 
                           filepath: str = "evaluation_dataset.json"):
        """평가 데이터를 JSON 파일로 저장"""
        
        data = []
        for example in examples:
            data.append({
                "question": example.question,
                "ground_truth": example.ground_truth,
                "context": example.context,
                "answer": example.answer,
                "metadata": example.metadata
            })
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        print(f"평가 데이터셋이 {filepath}에 저장되었습니다.")
    
    def load_evaluation_data(self, filepath: str) -> List[EvaluationExample]:
        """저장된 평가 데이터 로드"""
        
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        examples = []
        for item in data:
            example = EvaluationExample(
                question=item["question"],
                ground_truth=item["ground_truth"],
                context=item["context"],
                answer=item["answer"],
                metadata=item["metadata"]
            )
            examples.append(example)
        
        return examples


def create_manual_evaluation_dataset() -> List[EvaluationExample]:
    """수동으로 작성된 고품질 평가 데이터셋"""
    
    manual_examples = [
        EvaluationExample(
            question="Pod Security Standards의 restricted 정책 레벨에서 runAsNonRoot는 어떻게 설정해야 하나요?",
            ground_truth="restricted 정책 레벨에서는 runAsNonRoot를 반드시 true로 설정해야 합니다. 이는 컨테이너가 root 사용자(UID 0)로 실행되는 것을 완전히 금지하여 보안을 최대화합니다. 또한 runAsUser를 1000 이상의 값으로 설정하고, fsGroup도 1000 이상으로 설정하는 것이 권장됩니다.",
            context=[],
            answer="",
            metadata={"kubernetes_version": "1.24", "policy_level": "restricted", "question_type": "how_to"}
        ),
        EvaluationExample(
            question="privileged 컨테이너의 보안 위험은 무엇인가요?",
            ground_truth="privileged 컨테이너는 호스트의 모든 기능에 접근할 수 있어 매우 위험합니다. 주요 위험으로는 1) 호스트 파일시스템에 직접 접근 가능, 2) 호스트 네트워크 스택 조작 가능, 3) 호스트 장치에 접근 가능, 4) 호스트 프로세스 조작 가능 등이 있습니다. 따라서 보안상 privileged: false로 설정하고, 필요한 경우에만 특정 capabilities를 추가하는 것이 좋습니다.",
            context=[],
            answer="",
            metadata={"kubernetes_version": "1.24", "policy_level": "any", "question_type": "what"}
        ),
        EvaluationExample(
            question="Kubernetes 1.25 버전에서 Pod Security Standards의 변경사항은 무엇인가요?",
            ground_truth="Kubernetes 1.25에서는 Pod Security Standards가 GA(General Availability) 단계로 승격되었습니다. 주요 변경사항으로는 1) Pod Security Standards가 기본적으로 활성화됨, 2) PodSecurityPolicy(PSP)의 deprecation 경고 추가, 3) 네임스페이스 레벨에서 정책 적용 방식 개선, 4) 보안 컨텍스트 필드들의 검증 강화 등이 있습니다.",
            context=[],
            answer="",
            metadata={"kubernetes_version": "1.25", "policy_level": "any", "question_type": "what"}
        ),
        # 더 많은 수동 예시들 추가 가능
    ]
    
    return manual_examples


if __name__ == "__main__":
    # RAGAS 평가 실행 예시
    print("🚀 RAGAS 평가 데이터셋 생성 시작...")
    
    # RAG 시스템 초기화
    rag_system = KubernetesSecurityRAG()
    evaluator = RAGASEvaluator(rag_system)
    
    # 자동 생성 데이터셋
    print("📝 자동 생성 데이터셋 생성 중...")
    auto_examples = evaluator.generate_test_dataset(num_examples=20)
    evaluator.save_evaluation_data(auto_examples, "auto_evaluation_dataset.json")
    
    # 수동 생성 데이터셋
    print("✍️ 수동 생성 데이터셋 생성 중...")
    manual_examples = create_manual_evaluation_dataset()
    evaluator.save_evaluation_data(manual_examples, "manual_evaluation_dataset.json")
    
    # RAGAS 형식으로 변환
    print("🔄 RAGAS 형식으로 변환 중...")
    ragas_df = evaluator.prepare_ragas_dataset(auto_examples + manual_examples)
    ragas_df.to_csv("ragas_evaluation_dataset.csv", index=False)
    
    print("✅ 평가 데이터셋 생성 완료!")
    print(f"   - 자동 생성: {len(auto_examples)}개")
    print(f"   - 수동 생성: {len(manual_examples)}개")
    print(f"   - 총 예시: {len(auto_examples) + len(manual_examples)}개") 