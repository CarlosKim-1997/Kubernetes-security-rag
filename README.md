# Kubernetes Security RAG System

쿠버네티스 보안 분석을 위한 RAG (Retrieval-Augmented Generation) 시스템입니다.

## 🚀 주요 기능

- **쿠버네티스 문서 크롤링**: 공식 문서에서 보안 관련 정보 수집
- **벡터 저장소**: ChromaDB를 활용한 효율적인 문서 검색
- **버전별 분석**: 쿠버네티스 버전별 보안 가이드 제공
- **보안 체크리스트 생성**: Pod 설정에 대한 보안 점검
- **RAGAS 평가**: 시스템 성능 측정 및 개선

## 📁 프로젝트 구조

```
├── src/                    # 메인 소스 코드
│   ├── rag_system.py      # RAG 시스템 핵심
│   ├── vector_store.py    # 벡터 저장소 관리
│   ├── versioned_vector_store.py  # 버전별 벡터 저장소
│   ├── llm_integration.py # LLM 통합
│   ├── security_data.py   # 보안 데이터 처리
│   ├── yaml_analyzer.py   # YAML 파일 분석
│   ├── checklist_generator.py # 체크리스트 생성
│   ├── problem_classifier.py # 문제 분류
│   ├── api_server.py      # API 서버
│   └── ragas_evaluation.py # RAGAS 평가
├── frontend/              # 웹 프론트엔드
├── scripts/               # 유틸리티 스크립트
├── extracted_docs/        # 추출된 문서
└── requirements.txt       # Python 의존성
```

## 🛠️ 설치 및 실행

### 1. 의존성 설치
```bash
pip install -r requirements.txt
```

### 2. 환경 설정
```bash
# 가상환경 활성화 (선택사항)
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

### 3. 환경 변수 설정
```bash
# Gemini API 키 설정
export GEMINI_API_KEY="your_gemini_api_key_here"

# Windows의 경우:
# set GEMINI_API_KEY=your_gemini_api_key_here
```

### 4. 벡터 저장소 초기화
```bash
python src/vector_store.py
```

### 5. API 서버 실행
```bash
python src/api_server.py
```

## 📊 사용법

### API 엔드포인트

- `POST /analyze_pod`: Pod YAML 분석
- `POST /generate_checklist`: 보안 체크리스트 생성
- `GET /health`: 서버 상태 확인

### 예시 요청

```python
import requests

# Pod 분석
response = requests.post('http://localhost:8000/analyze_pod', 
    json={'yaml_content': 'your_pod_yaml_here'})

# 체크리스트 생성
response = requests.post('http://localhost:8000/generate_checklist',
    json={'pod_analysis': analysis_result})
```

## 🔧 개발

### 코드 스타일
- Python: PEP 8 준수
- 함수 및 클래스에 docstring 작성
- 타입 힌트 사용

### 테스트
```bash
# RAGAS 평가 실행
python src/ragas_evaluation.py

# 개별 모듈 테스트
python -m pytest tests/
```

## 📈 성능 모니터링

RAGAS를 통한 시스템 성능 평가:
- **Faithfulness**: 생성된 답변의 정확성
- **Answer Relevancy**: 답변의 관련성
- **Context Precision**: 검색된 컨텍스트의 정확성
- **Context Recall**: 검색된 컨텍스트의 완전성

## 🤝 기여하기

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

## 🆘 문제 해결

### 일반적인 문제들

1. **벡터 저장소 초기화 오류**
   ```bash
   rm -rf chroma_db/
   python src/vector_store.py
   ```

2. **메모리 부족**
   - `requirements.txt`에서 배치 크기 조정
   - 가상환경 재설정

3. **API 연결 오류**
   - 포트 8000이 사용 가능한지 확인
   - 방화벽 설정 확인

## 📞 지원

문제가 발생하거나 질문이 있으시면 이슈를 생성해주세요. 