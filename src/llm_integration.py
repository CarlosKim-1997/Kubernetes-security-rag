import os
from typing import List, Dict, Any, Optional
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class GeminiLLM:
    """
    Gemini LLM Integration Module (Korean Response Support)
    Generates all responses in Korean, practically and friendly.
    """
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-1.5-flash"):
        """Initialize Gemini API key and model."""
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("Gemini API key is required. Set GEMINI_API_KEY environment variable or pass api_key parameter.")
        # Initialize Gemini client with safe configuration
        try:
            # Configure Gemini API
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(model)
        except Exception as e:
            print(f"Warning: Gemini client initialization failed: {e}")
            # Create a dummy client for fallback
            self.model = None
        self.model_name = model
    
    def generate_security_advice(self, 
                               analysis_results: List[Dict[str, Any]],
                               security_context: List[Dict[str, Any]],
                               target_policy_level: str,
                               kubernetes_version: str) -> str:
        """
        Generate concise, practical security advice in Korean for Pod security analysis results.
        """
        context_parts = []
        for ctx in security_context[:5]:
            context_parts.append(ctx.get("content", ""))
        context_text = "\n\n".join(context_parts)
        critical_issues = [r for r in analysis_results if r.get("status") == "critical"]
        warnings = [r for r in analysis_results if r.get("status") == "warning"]
        secure_fields = [r for r in analysis_results if r.get("status") == "secure"]
        prompt = f"""
당신은 쿠버네티스 보안 전문가입니다. 아래 Pod 보안 분석 결과를 바탕으로 실무자에게 전문적이고 구체적인 조언을 제공해주세요.

**분석 정보**
- 쿠버네티스 버전: {kubernetes_version}
- 정책 수준: {target_policy_level}
- 치명적 이슈: {len(critical_issues)}개
- 경고: {len(warnings)}개
- 안전 필드: {len(secure_fields)}개

**보안 컨텍스트**
{context_text}

**발견된 문제점들**
{chr(10).join([f"• {issue.get('field_name', '알 수 없음')}: {issue.get('message', '')}" for issue in critical_issues])}

{chr(10).join([f"• {warning.get('field_name', '알 수 없음')}: {warning.get('message', '')}" for warning in warnings])}

이 분석 결과를 바탕으로 전문적이고 구체적인 해결 방안을 제시해주세요. 다음과 같은 내용을 포함하되, 구어체 인삿말이나 마무리 말 없이 핵심 내용만 작성해주세요:

- 전체적인 보안 상황에 대한 평가
- 발견된 문제점들의 구체적인 해결 방법 (YAML 예시 포함)
- 이 버전에서 주의해야 할 점들
- 참고할 만한 공식 문서나 가이드
- 쿠버네티스 버전별 차이점이나 업그레이드 시 주의사항

답변은 전문적이고 실용적이어야 하며, 바로 적용할 수 있는 구체적인 내용을 중심으로 작성해주세요. 구어체 표현이나 불필요한 반복은 피해주세요.
"""
        if not self.model:
            return "[Error] Gemini client is not available. Please check your API key and network connection."
        
        try:
            response = self.model.generate_content(prompt)
            return response.text.strip() if response.text else "[Error] LLM 응답이 비어 있습니다."
        except Exception as e:
            return f"[Error] LLM security advice generation failed: {str(e)}"
    
    def answer_security_question(self, 
                               question: str,
                               search_results: List[Dict[str, Any]],
                               policy_level: Optional[str] = None) -> str:
        """
        Generate concise, practical Korean response to security questions.
        """
        context_parts = []
        for result in search_results[:3]:
            context_parts.append(result.get("content", ""))
        context_text = "\n\n".join(context_parts)
        prompt = f"""
당신은 쿠버네티스 보안 전문가입니다. 아래 질문에 대해 전문적이고 구체적인 답변을 제공해주세요.

**질문**
{question}
정책 수준: {policy_level or '제한 없음'}

**참고 컨텍스트**
{context_text}

이 질문에 대해 전문적이고 구체적인 답변을 제공해주세요. 다음과 같은 내용을 포함하되, 구어체 인삿말이나 마무리 말 없이 핵심 내용만 작성해주세요:

- 질문에 대한 직접적이고 명확한 답변
- 관련된 보안 위험과 그 이유
- 실무에서 바로 적용할 수 있는 구체적인 방법 (YAML 예시 포함)
- 참고할 만한 공식 문서나 가이드
- 쿠버네티스 버전별 차이점이나 업그레이드 시 주의사항

답변은 전문적이고 실용적이어야 하며, 바로 적용할 수 있는 구체적인 내용을 중심으로 작성해주세요. 구어체 표현이나 불필요한 반복은 피해주세요. 컨텍스트에 답이 없는 경우에도 일반적인 보안 베스트 프랙티스를 안내해주세요.
"""
        if not self.model:
            return "[Error] Gemini client is not available. Please check your API key and network connection."
        
        try:
            response = self.model.generate_content(prompt)
            return response.text.strip() if response.text else "[Error] LLM 응답이 비어 있습니다."
        except Exception as e:
            return f"[Error] LLM question response generation failed: {str(e)}"
    
    def generate_field_guidance(self, 
                              field_name: str,
                              field_chunks: Dict[str, List[Dict[str, Any]]],
                              kubernetes_version: str) -> str:
        """
        Generate concise, practical Korean guidance for specific security fields.
        """
        context_parts = []
        for chunk_type, chunks in field_chunks.items():
            if chunks:
                context_parts.append(f"[{chunk_type.upper()}]")
                for chunk in chunks[:2]:
                    context_parts.append(chunk.get("content", ""))
                context_parts.append("")
        context_text = "\n\n".join(context_parts)
        prompt = f"""
당신은 쿠버네티스 보안 전문가입니다. 아래 {field_name} 필드에 대해 전문적이고 구체적으로 설명해주세요.

**쿠버네티스 버전**: {kubernetes_version}

**필드 정보**
{context_text}

이 필드에 대해 전문적이고 구체적으로 설명해주세요. 다음과 같은 내용을 포함하되, 구어체 인삿말이나 마무리 말 없이 핵심 내용만 작성해주세요:

- 이 필드가 무엇이고 어떻게 동작하는지
- 보안상 어떤 의미가 있고 어떤 위험이 있는지
- 실무에서 어떻게 올바르게 사용해야 하는지 (구체적인 YAML 예시 포함)
- 단계별로 어떻게 적용해야 하는지
- 참고할 만한 공식 문서나 가이드
- 쿠버네티스 버전별 차이점이나 업그레이드 시 주의사항

답변은 전문적이고 실용적이어야 하며, 바로 적용할 수 있는 구체적인 내용을 중심으로 작성해주세요. 구어체 표현이나 불필요한 반복은 피해주세요.
"""
        if not self.model:
            return "[Error] Gemini client is not available. Please check your API key and network connection."
        
        try:
            response = self.model.generate_content(prompt)
            return response.text.strip() if response.text else "[Error] LLM 응답이 비어 있습니다."
        except Exception as e:
            return f"[Error] LLM field guidance generation failed: {str(e)}"
    
    def generate_fixed_yaml(self, 
                          original_yaml: str,
                          analysis_results: List[Dict[str, Any]],
                          kubernetes_version: str) -> str:
        """
        Generate fixed YAML with Korean explanations for security issues.
        """
        issues_to_fix = []
        for result in analysis_results:
            if result.get("status") in ["critical", "warning"]:
                issues_to_fix.append({
                    "field": result.get("field_name", ""),
                    "issue": result.get("message", ""),
                    "recommendation": result.get("recommendation", "")
                })
        issues_text = "\n".join([f"- {issue['field']}: {issue['issue']} -> {issue['recommendation']}" for issue in issues_to_fix])
        prompt = f"""
당신은 쿠버네티스 보안 전문가입니다. 아래 보안 이슈가 있는 Pod YAML을 수정해주세요.

**원본 YAML**
{original_yaml}

**수정해야 할 이슈들**
{issues_text}

**쿠버네티스 버전**: {kubernetes_version}

위의 모든 보안 이슈를 해결한 수정된 YAML만 출력해주세요. 설명이나 추가 텍스트 없이 YAML만 깔끔하게 작성해주세요. 실제 적용 가능한 형태로 작성해주세요.
"""
        if not self.model:
            return "[Error] Gemini client is not available. Please check your API key and network connection."
        
        try:
            response = self.model.generate_content(prompt)
            return response.text.strip() if response.text else "[Error] LLM 응답이 비어 있습니다."
        except Exception as e:
            return f"[Error] LLM YAML fix generation failed: {str(e)}"

# Backward compatibility - alias for OpenAILLM
OpenAILLM = GeminiLLM 