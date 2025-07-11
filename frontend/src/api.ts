import axios from 'axios';
import { 
  CreateChecklistRequest, 
  UpdateProgressRequest, 
  ChecklistResponse, 
  NextItemResponse 
} from './types';

const API_BASE_URL = 'http://localhost:8000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const checklistApi = {
  // 체크리스트 생성
  createChecklist: async (request: CreateChecklistRequest): Promise<ChecklistResponse> => {
    const response = await api.post('/checklist', request);
    return response.data;
  },

  // 체크리스트 진행 상황 업데이트
  updateProgress: async (request: UpdateProgressRequest): Promise<ChecklistResponse> => {
    const response = await api.post('/checklist/progress', request);
    return response.data;
  },

  // 다음 추천 항목 가져오기
  getNextItem: async (checklist: any): Promise<NextItemResponse> => {
    const response = await api.post('/checklist/next', { checklist });
    return response.data;
  },
};

// Versioned RAG API types
export interface PodAnalysisRequest {
  yaml_content: string;
  kubernetes_version: string;
  target_policy_level: string;
  use_llm: boolean;
}

export interface SecurityQuestionRequest {
  question: string;
  kubernetes_version: string;
  policy_level?: string;
  use_llm: boolean;
}

export interface FieldGuidanceRequest {
  field_name: string;
  kubernetes_version: string;
  use_llm: boolean;
}

export interface VersionInfo {
  available_versions: string[];
  current_version: string;
}

export const ragApi = {
  // Pod 보안 설정 분석
  analyzePod: async (request: PodAnalysisRequest): Promise<any> => {
    const response = await api.post('/rag/analyze-pod', request);
    return response.data;
  },

  // 보안 질문 답변
  answerSecurityQuestion: async (request: SecurityQuestionRequest): Promise<any> => {
    const response = await api.post('/rag/security-question', request);
    return response.data;
  },

  // 필드 가이드 조회
  getFieldGuidance: async (request: FieldGuidanceRequest): Promise<any> => {
    const response = await api.post('/rag/field-guidance', request);
    return response.data;
  },

  // 사용 가능한 버전 목록
  getAvailableVersions: async (): Promise<VersionInfo> => {
    const response = await api.get('/versions');
    return response.data;
  },

  // RAG 시스템 통계
  getStatistics: async (): Promise<any> => {
    const response = await api.get('/rag/statistics');
    return response.data;
  },
};

export default api; 