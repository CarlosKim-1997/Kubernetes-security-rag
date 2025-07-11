import os
from typing import List, Dict, Any, Optional
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class OpenAILLM:
    """
    OpenAI LLM Integration Module (Korean Response Support)
    Generates all responses in Korean, practically and friendly.
    """
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-3.5-turbo"):
        """Initialize OpenAI API key and model."""
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key is required. Set OPENAI_API_KEY environment variable or pass api_key parameter.")
        # Initialize OpenAI client with safe configuration
        try:
            # Set environment variable for OpenAI client
            os.environ["OPENAI_API_KEY"] = self.api_key
            self.client = OpenAI()
        except Exception as e:
            print(f"Warning: OpenAI client initialization failed: {e}")
            # Create a dummy client for fallback
            self.client = None
        self.model = model
    
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
아래는 쿠버네티스 Pod 보안 분석 결과입니다. 실무자(DevOps, SRE, 보안 담당자)가 바로 적용할 수 있도록, 중복 없이 간결하고 구체적으로 답변하세요.

쿠버네티스 버전: {kubernetes_version}
정책 수준: {target_policy_level}

[보안 컨텍스트]
{context_text}

[분석 요약]
- 치명적 이슈: {len(critical_issues)}
- 경고: {len(warnings)}
- 안전 필드: {len(secure_fields)}

[치명적 이슈]
{chr(10).join([f"- {issue.get('field_name', '알 수 없음')}: {issue.get('message', '')}" for issue in critical_issues])}

[경고]
{chr(10).join([f"- {warning.get('field_name', '알 수 없음')}: {warning.get('message', '')}" for warning in warnings])}

[안전 필드]
{chr(10).join([f"- {secure.get('field_name', '알 수 없음')}: {secure.get('message', '')}" for secure in secure_fields[:5]])}

---

아래 항목을 한국어로, 실무적으로, 중복 없이 간결하게 작성하세요:
1. 종합 보안 평가 (한두 문장)
2. 각 이슈별 구체적 개선 방안 (수정 전/후 YAML을 반드시 코드블록(\`\`\`yaml)으로, 권장 값 등 포함, 중복 설명 X)
3. 정책 수준에 맞는 핵심 보안 베스트 프랙티스 (2~3개, 우선순위 명확히)
4. 예방/운영 팁 (한두 줄, 자동화/검증 도구 등)
5. 참고할 만한 정책/표준(최대 2개, 반드시 공식 문서 링크 포함)
6. 실무에서 자주 하는 실수/주의점(각 항목별로 한 줄씩)
7. (중요) 입력된 쿠버네티스 버전과 주요 구버전(예: 1.21, 1.25, 1.28 등)과의 정책/필드별 차이점, 업그레이드 시 주의사항을 반드시 비교/설명

답변은 실무자가 바로 복사해 쓸 수 있을 정도로 구체적이고, 불필요한 반복/원론적 설명은 피하세요.
"""
        if not self.client:
            return "[Error] OpenAI client is not available. Please check your API key and network connection."
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "당신은 쿠버네티스 보안 전문가입니다. 모든 답변을 실무적으로, 중복 없이 간결하게, 구체적 예시와 우선순위를 강조해서 작성하세요."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.3
            )
            content = response.choices[0].message.content if response.choices[0].message else None
            return content.strip() if content else "[Error] LLM 응답이 비어 있습니다."
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
아래는 쿠버네티스 보안 문서에서 추출한 컨텍스트입니다. 아래 질문에 대해 실무자(DevOps, SRE, 보안 담당자)가 바로 적용할 수 있도록, 중복 없이 간결하고 구체적으로 답변하세요.

[질문]
{question}
정책 수준: {policy_level or '제한 없음'}

[컨텍스트]
{context_text}

---

아래 항목을 한국어로, 실무적으로, 중복 없이 간결하게 작성하세요:
1. 질문에 대한 직접적이고 명확한 답변 (한두 문장)
2. 관련 보안 위험 및 이유 (중복 설명 X, 핵심만)
3. 실무 적용 가이드 (수정 예시, 명령어 등 구체적으로, YAML은 반드시 코드블록(```yaml)으로)
4. 참고할 만한 정책/표준(최대 2개, 반드시 공식 문서 링크 포함)
5. 실무에서 자주 하는 실수/주의점(한 줄)
6. (중요) 입력된 쿠버네티스 버전과 주요 구버전(예: 1.21, 1.25, 1.28 등)과의 정책/필드별 차이점, 업그레이드 시 주의사항을 반드시 비교/설명

컨텍스트에 답이 없으면, 일반적인 보안 베스트 프랙티스도 한두 줄로 안내하세요.
"""
        if not self.client:
            return "[Error] OpenAI client is not available. Please check your API key and network connection."
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "당신은 쿠버네티스 보안 전문가입니다. 모든 답변을 실무적으로, 중복 없이 간결하게, 구체적 예시와 우선순위를 강조해서 작성하세요."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=800,
                temperature=0.3
            )
            content = response.choices[0].message.content if response.choices[0].message else None
            return content.strip() if content else "[Error] LLM 응답이 비어 있습니다."
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
아래는 쿠버네티스 보안 필드({field_name})에 대한 정보입니다. 실무자(DevOps, SRE, 보안 담당자)가 바로 적용할 수 있도록, 중복 없이 간결하고 구체적으로 답변하세요.

쿠버네티스 버전: {kubernetes_version}

[필드 정보]
{context_text}

---

아래 항목을 한국어로, 실무적으로, 중복 없이 간결하게 작성하세요:
1. 이 필드의 역할과 동작 원리 (한두 문장)
2. 보안상 의미와 위험성 (핵심만)
3. 실무 적용 베스트 프랙티스 (구체적 예시, 권장 값 등, YAML은 반드시 코드블록(```yaml)으로)
4. 자주 하는 실수와 주의점 (중복 설명 X, 한 줄)
5. 단계별 적용 가이드 (수정 전/후 YAML 예시 포함, 코드블록(```yaml)으로)
6. 참고할 만한 정책/표준(최대 2개, 반드시 공식 문서 링크 포함)
7. (중요) 입력된 쿠버네티스 버전과 주요 구버전(예: 1.21, 1.25, 1.28 등)과의 정책/필드별 차이점, 업그레이드 시 주의사항을 반드시 비교/설명

답변은 실무자가 바로 복사해 쓸 수 있을 정도로 구체적이고, 불필요한 반복/원론적 설명은 피하세요.
"""
        if not self.client:
            return "[Error] OpenAI client is not available. Please check your API key and network connection."
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "당신은 쿠버네티스 보안 전문가입니다. 모든 답변을 실무적으로, 중복 없이 간결하게, 구체적 예시와 우선순위를 강조해서 작성하세요."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.3
            )
            content = response.choices[0].message.content if response.choices[0].message else None
            return content.strip() if content else "[Error] LLM 응답이 비어 있습니다."
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
아래는 보안 이슈가 있는 쿠버네티스 Pod YAML입니다. 모든 답변을 한국어로, 실무적으로, 친절하게 작성해 주세요.

[원본 YAML]
{original_yaml}

[수정해야 할 이슈]
{issues_text}

쿠버네티스 버전: {kubernetes_version}

---

아래 항목을 모두 한국어로 작성해 주세요:
1. 모든 치명적/경고 이슈를 반영한 수정된 YAML만 출력 (설명 없이 YAML만)
2. YAML은 실제 적용 가능한 형태로 출력
"""
        if not self.client:
            return "[Error] OpenAI client is not available. Please check your API key and network connection."
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "당신은 쿠버네티스 보안 전문가입니다. 모든 답변을 한국어로, 실무적으로, 친절하게 작성하세요."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1500,
                temperature=0.2
            )
            content = response.choices[0].message.content if response.choices[0].message else None
            return content.strip() if content else "[Error] LLM 응답이 비어 있습니다."
        except Exception as e:
            return f"[Error] LLM YAML fix generation failed: {str(e)}" 