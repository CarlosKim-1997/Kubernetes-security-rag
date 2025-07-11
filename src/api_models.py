from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class UserContextModel(BaseModel):
    kubernetes_version: Optional[str] = Field(None, description="Kubernetes 버전")
    cloud_platform: Optional[str] = Field(None, description="클라우드 플랫폼")
    cluster_type: Optional[str] = Field(None, description="클러스터 타입")
    security_level: Optional[str] = Field(None, description="보안 레벨")

class ChecklistCreateRequest(BaseModel):
    user_input: str = Field(..., description="문제 설명 또는 질문")
    error_logs: Optional[str] = Field(None, description="에러 로그")
    user_context: Optional[UserContextModel] = Field(None, description="사용자 환경 정보")

class ChecklistProgressRequest(BaseModel):
    checklist: Dict[str, Any] = Field(..., description="진행 중인 체크리스트 트리 (JSON)")
    item_id: str = Field(..., description="체크/해제할 항목의 ID")
    is_checked: bool = Field(..., description="체크 여부")
    user_notes: Optional[str] = Field("", description="사용자 노트")

class ChecklistResponse(BaseModel):
    checklist: Dict[str, Any] = Field(..., description="체크리스트 트리 (JSON)")
    progress_summary: Dict[str, Any] = Field(..., description="진행 상황 요약")

class NextItemRequest(BaseModel):
    checklist: Dict[str, Any] = Field(..., description="진행 중인 체크리스트 트리 (JSON)")

class NextItemResponse(BaseModel):
    item: Optional[Dict[str, Any]] = Field(None, description="다음 추천 항목 (없으면 null)") 