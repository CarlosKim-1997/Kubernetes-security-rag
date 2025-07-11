from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
# Conditional imports for different execution contexts
try:
    # When running as module (python -m uvicorn api_server:app)
    from .api_models import (
        ChecklistCreateRequest, ChecklistProgressRequest, ChecklistResponse,
        NextItemRequest, NextItemResponse, UserContextModel
    )
    from .checklist_generator import ChecklistGenerator
    from .tree_structure import ProblemTree
    from .rag_system import KubernetesSecurityRAG
    from .schema import PolicyLevel, PolicyType
    from .versioned_vector_store import versioned_vector_store
    from .crawler.version_manager import version_manager
except ImportError:
    # When running directly (python api_server.py)
    from api_models import (
        ChecklistCreateRequest, ChecklistProgressRequest, ChecklistResponse,
        NextItemRequest, NextItemResponse, UserContextModel
    )
    from checklist_generator import ChecklistGenerator
    from tree_structure import ProblemTree
    from rag_system import KubernetesSecurityRAG
    from schema import PolicyLevel
    from versioned_vector_store import versioned_vector_store
    from crawler.version_manager import version_manager
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uvicorn

app = FastAPI(title="Kubernetes RAG Checklist API", version="0.1.0")

# CORS 설정 (React 개발 환경용)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

generator = None
rag_system = None

def get_generator():
    global generator
    if generator is None:
        try:
            generator = ChecklistGenerator()
        except Exception as e:
            print(f"Warning: Failed to initialize ChecklistGenerator: {e}")
            generator = None
    return generator

def get_rag_system():
    global rag_system
    if rag_system is None:
        try:
            rag_system = KubernetesSecurityRAG()
        except Exception as e:
            print(f"Warning: Failed to initialize KubernetesSecurityRAG: {e}")
            rag_system = None
    return rag_system

# New API models for versioned RAG
class PodAnalysisRequest(BaseModel):
    yaml_content: str
    kubernetes_version: str = "1.24"
    target_policy_level: str = "restricted"
    use_llm: bool = True

class SecurityQuestionRequest(BaseModel):
    question: str
    kubernetes_version: str = "1.24"
    policy_level: Optional[str] = None
    use_llm: bool = True

class FieldGuidanceRequest(BaseModel):
    field_name: str
    kubernetes_version: str = "1.24"
    use_llm: bool = True

class VersionInfoResponse(BaseModel):
    available_versions: List[str]
    current_version: str

@app.post("/api/checklist", response_model=ChecklistResponse)
def create_checklist(req: ChecklistCreateRequest):
    """체크리스트 생성"""
    gen = get_generator()
    if gen is None:
        raise HTTPException(status_code=500, detail="체크리스트 생성기가 초기화되지 않았습니다.")
    
    user_context = req.user_context.dict() if req.user_context else {}
    tree = gen.generate_checklist(
        user_input=req.user_input,
        error_logs=req.error_logs,
        user_context=user_context
    )
    return ChecklistResponse(
        checklist=tree.to_dict(),
        progress_summary=tree.get_progress_summary()
    )

@app.post("/api/checklist/progress", response_model=ChecklistResponse)
def update_checklist_progress(req: ChecklistProgressRequest):
    """체크리스트 항목 체크/해제 및 노트 저장"""
    gen = get_generator()
    if gen is None:
        raise HTTPException(status_code=500, detail="체크리스트 생성기가 초기화되지 않았습니다.")
    
    try:
        tree = ProblemTree.from_dict(req.checklist)
        updated_tree = gen.update_checklist_progress(
            tree=tree,
            item_id=req.item_id,
            is_checked=req.is_checked,
            user_notes=req.user_notes or ""
        )
        return ChecklistResponse(
            checklist=updated_tree.to_dict(),
            progress_summary=updated_tree.get_progress_summary()
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"진행 상황 업데이트 실패: {str(e)}")

@app.post("/api/checklist/next", response_model=NextItemResponse)
def get_next_item(req: NextItemRequest):
    """다음 추천 항목 반환"""
    gen = get_generator()
    if gen is None:
        raise HTTPException(status_code=500, detail="체크리스트 생성기가 초기화되지 않았습니다.")
    
    try:
        tree = ProblemTree.from_dict(req.checklist)
        next_item = gen.get_next_recommended_item(tree)
        return NextItemResponse(item=next_item.__dict__ if next_item else None)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"다음 항목 추천 실패: {str(e)}")

# New versioned RAG endpoints
@app.post("/api/rag/analyze-pod")
def analyze_pod_configuration(req: PodAnalysisRequest):
    """버전별 Pod 보안 설정 분석"""
    rag = get_rag_system()
    if rag is None:
        raise HTTPException(status_code=500, detail="RAG 시스템이 초기화되지 않았습니다.")
    
    try:
        # Convert policy level string to enum
        policy_level_str = req.target_policy_level.lower()
        if policy_level_str == "restricted":
            policy_level = PolicyLevel.RESTRICTED
        elif policy_level_str == "baseline":
            policy_level = PolicyLevel.BASELINE
        elif policy_level_str == "privileged":
            policy_level = PolicyLevel.PRIVILEGED
        else:
            raise ValueError(f"Invalid policy level: {req.target_policy_level}")
        
        result = rag.analyze_pod_configuration(
            yaml_content=req.yaml_content,
            kubernetes_version=req.kubernetes_version,
            target_policy_level=policy_level,
            use_llm=req.use_llm
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Pod 분석 실패: {str(e)}")

@app.post("/api/rag/security-question")
def answer_security_question(req: SecurityQuestionRequest):
    """버전별 보안 질문 답변"""
    rag = get_rag_system()
    if rag is None:
        raise HTTPException(status_code=500, detail="RAG 시스템이 초기화되지 않았습니다.")
    
    try:
        policy_level = None
        if req.policy_level:
            policy_level_str = req.policy_level.lower()
            if policy_level_str == "restricted":
                policy_level = PolicyLevel.RESTRICTED
            elif policy_level_str == "baseline":
                policy_level = PolicyLevel.BASELINE
            elif policy_level_str == "privileged":
                policy_level = PolicyLevel.PRIVILEGED
            else:
                raise ValueError(f"Invalid policy level: {req.policy_level}")
        
        result = rag.answer_security_question(
            question=req.question,
            kubernetes_version=req.kubernetes_version,
            policy_level=policy_level,
            use_llm=req.use_llm
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"보안 질문 답변 실패: {str(e)}")

@app.post("/api/rag/field-guidance")
def get_field_guidance(req: FieldGuidanceRequest):
    """버전별 필드 가이드"""
    rag = get_rag_system()
    if rag is None:
        raise HTTPException(status_code=500, detail="RAG 시스템이 초기화되지 않았습니다.")
    
    try:
        result = rag.get_field_guidance(
            field_name=req.field_name,
            kubernetes_version=req.kubernetes_version,
            use_llm=req.use_llm
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"필드 가이드 조회 실패: {str(e)}")

@app.get("/api/versions", response_model=VersionInfoResponse)
def get_available_versions():
    """사용 가능한 Kubernetes 버전 목록"""
    rag = get_rag_system()
    if rag is None:
        # Fallback to default versions if RAG system is not available
        return VersionInfoResponse(
            available_versions=["1.20", "1.21", "1.22", "1.23", "1.24", "1.25", "1.26", "1.27", "1.28"],
            current_version="1.24"
        )
    
    try:
        # Get available versions from versioned vector store
        stats = rag.versioned_vector_store.get_collection_statistics()
        available_versions = list(stats.get("version_collections", {}).keys())
        
        # If no versions are available, provide default versions
        if not available_versions:
            available_versions = ["1.20", "1.21", "1.22", "1.23", "1.24", "1.25", "1.26", "1.27", "1.28"]
        
        return VersionInfoResponse(
            available_versions=available_versions,
            current_version="1.24"  # Default version
        )
    except Exception as e:
        # Fallback to default versions if there's an error
        return VersionInfoResponse(
            available_versions=["1.20", "1.21", "1.22", "1.23", "1.24", "1.25", "1.26", "1.27", "1.28"],
            current_version="1.24"
        )

@app.get("/api/rag/statistics")
def get_rag_statistics():
    """RAG 시스템 통계 정보"""
    rag = get_rag_system()
    if rag is None:
        raise HTTPException(status_code=500, detail="RAG 시스템이 초기화되지 않았습니다.")
    
    try:
        stats = rag.versioned_vector_store.get_collection_statistics()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"통계 정보 조회 실패: {str(e)}")

@app.get("/api/rag/version-compatibility")
def get_version_compatibility(version: str):
    """버전별 정책 타입 및 호환성 정보 제공"""
    try:
        info = versioned_vector_store.get_version_compatibility_info(version)
        return info
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"버전 호환성 정보 조회 실패: {str(e)}")

# Version guidance generation function
def generate_version_guidance(version: str) -> Dict[str, Any]:
    """버전별 안내문 생성"""
    try:
        compat_info = versioned_vector_store.get_version_compatibility_info(version)
        policy_type = compat_info["policy_type"]
        
        guidance = {
            "version": version,
            "policy_type": policy_type,
            "title": "",
            "description": "",
            "key_features": [],
            "limitations": [],
            "recommendations": [],
            "migration_steps": [],
            "examples": []
        }
        
        if policy_type == "PodSecurityPolicy":
            guidance.update({
                "title": "PodSecurityPolicy (PSP) - 레거시 보안 모델",
                "description": "Kubernetes 1.20-1.21에서 사용되는 레거시 보안 정책입니다. PodSecurityPolicy 리소스를 통해 Pod 보안을 제어합니다.",
                "key_features": [
                    "PodSecurityPolicy 리소스 기반 보안 제어",
                    "RBAC과 연동된 정책 적용",
                    "컨테이너 실행 권한 제한",
                    "볼륨 마운트 제한"
                ],
                "limitations": [
                    "runAsNonRoot 필드 미지원",
                    "allowPrivilegeEscalation 필드 미지원", 
                    "readOnlyRootFilesystem 필드 미지원",
                    "seccompProfile 필드 미지원",
                    "apparmorProfile 필드 미지원",
                    "Restricted 정책 레벨 미지원"
                ],
                "recommendations": [
                    "가능한 경우 1.24+로 업그레이드하여 Pod Security Standards 사용",
                    "PSP 정책을 PSS로 마이그레이션 계획 수립",
                    "현재 환경에서는 Baseline 또는 Privileged 정책 사용"
                ],
                "migration_steps": [
                    "1.24+ 클러스터로 업그레이드",
                    "Pod Security Standards 활성화",
                    "기존 PSP 정책을 PSS로 변환",
                    "네임스페이스별 PSS 레이블 적용"
                ],
                "examples": [
                    "apiVersion: policy/v1beta1",
                    "kind: PodSecurityPolicy",
                    "metadata:",
                    "  name: restricted-psp",
                    "spec:",
                    "  privileged: false",
                    "  allowPrivilegeEscalation: false",
                    "  runAsUser:",
                    "    rule: MustRunAsNonRoot"
                ]
            })
            
        elif policy_type == "PodSecurityStandardsAlpha":
            guidance.update({
                "title": "Pod Security Standards (PSS) - Alpha 단계",
                "description": "Kubernetes 1.22-1.23에서 도입된 Pod Security Standards의 Alpha 버전입니다. 일부 기능이 제한적으로 지원됩니다.",
                "key_features": [
                    "Baseline, Restricted, Privileged 정책 레벨 지원",
                    "runAsNonRoot 필드 지원 (Alpha)",
                    "allowPrivilegeEscalation 필드 지원 (Alpha)",
                    "readOnlyRootFilesystem 필드 지원 (Alpha)",
                    "네임스페이스별 정책 적용"
                ],
                "limitations": [
                    "seccompProfile 필드 미지원",
                    "apparmorProfile 필드 미지원",
                    "일부 기능이 Alpha 단계로 불안정할 수 있음",
                    "프로덕션 환경에서 주의 필요"
                ],
                "recommendations": [
                    "프로덕션 환경에서는 1.24+로 업그레이드 권장",
                    "테스트 환경에서 PSS Alpha 기능 검증",
                    "기존 PSP에서 PSS로 점진적 마이그레이션"
                ],
                "migration_steps": [
                    "1.24+ 클러스터로 업그레이드",
                    "Pod Security Standards Stable 활성화",
                    "모든 PSS 기능 활용 가능"
                ],
                "examples": [
                    "apiVersion: v1",
                    "kind: Namespace",
                    "metadata:",
                    "  name: my-app",
                    "  labels:",
                    "    pod-security.kubernetes.io/enforce: baseline",
                    "    pod-security.kubernetes.io/audit: restricted",
                    "    pod-security.kubernetes.io/warn: restricted"
                ]
            })
            
        else:  # PodSecurityStandardsStable
            guidance.update({
                "title": "Pod Security Standards (PSS) - Stable",
                "description": "Kubernetes 1.24+에서 안정화된 Pod Security Standards입니다. 모든 보안 기능을 완전히 지원합니다.",
                "key_features": [
                    "모든 정책 레벨 완전 지원 (Baseline, Restricted, Privileged)",
                    "모든 보안 필드 지원",
                    "seccompProfile 필드 지원",
                    "apparmorProfile 필드 지원",
                    "안정적이고 프로덕션 준비 완료",
                    "네임스페이스별 세밀한 정책 제어"
                ],
                "limitations": [
                    "제한사항 없음 - 모든 기능 지원"
                ],
                "recommendations": [
                    "최신 보안 기능 활용 권장",
                    "Restricted 정책 레벨 사용 권장",
                    "정기적인 보안 정책 검토"
                ],
                "migration_steps": [
                    "이미 최신 버전이므로 마이그레이션 불필요"
                ],
                "examples": [
                    "apiVersion: v1",
                    "kind: Pod",
                    "metadata:",
                    "  name: secure-pod",
                    "spec:",
                    "  securityContext:",
                    "    runAsNonRoot: true",
                    "    runAsUser: 1000",
                    "    runAsGroup: 3000",
                    "    fsGroup: 2000",
                    "    seccompProfile:",
                    "      type: RuntimeDefault",
                    "  containers:",
                    "  - name: app",
                    "    image: nginx:alpine",
                    "    securityContext:",
                    "      allowPrivilegeEscalation: false",
                    "      readOnlyRootFilesystem: true",
                    "      capabilities:",
                    "        drop:",
                    "        - ALL"
                ]
            })
        
        return guidance
        
    except Exception as e:
        return {
            "error": f"버전 안내문 생성 실패: {str(e)}",
            "version": version
        }

@app.get("/api/rag/version-guidance")
def get_version_guidance(version: str):
    """버전별 상세 안내문 제공"""
    try:
        guidance = generate_version_guidance(version)
        return guidance
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"버전 안내문 조회 실패: {str(e)}")

if __name__ == "__main__":
    uvicorn.run("api_server:app", host="0.0.0.0", port=8000, reload=True) 