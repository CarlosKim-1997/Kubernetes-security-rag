import os
from typing import List, Dict, Any, Optional
# Conditional imports for different execution contexts
try:
    # When running as module
    from .vector_store import KubernetesSecurityVectorStore
    from .versioned_vector_store import VersionedKubernetesVectorStore
    from .yaml_analyzer import KubernetesYAMLAnalyzer
    from .schema import PolicyLevel, PodSecurityAnalysis, PolicyType
    from .llm_integration import OpenAILLM
    from .crawler.version_manager import version_manager
except ImportError:
    # When running directly
    from vector_store import KubernetesSecurityVectorStore
    from versioned_vector_store import VersionedKubernetesVectorStore
    from yaml_analyzer import KubernetesYAMLAnalyzer
    from schema import PolicyLevel, PodSecurityAnalysis, PolicyType
    from llm_integration import OpenAILLM
    from crawler.version_manager import version_manager
import yaml


class KubernetesSecurityRAG:
    """RAG system for Kubernetes Pod security configuration guidance"""
    
    def __init__(self, vector_store: Optional[KubernetesSecurityVectorStore] = None, 
                 versioned_vector_store: Optional[VersionedKubernetesVectorStore] = None,
                 llm: Optional[OpenAILLM] = None):
        """Initialize the RAG system"""
        self.vector_store = vector_store or KubernetesSecurityVectorStore()
        self.versioned_vector_store = versioned_vector_store or VersionedKubernetesVectorStore()
        self.yaml_analyzer = KubernetesYAMLAnalyzer()
        if llm is None:
            self.llm = OpenAILLM()
        else:
            self.llm = llm  # Optional LLM integration
        
    def analyze_pod_configuration(self, yaml_content: str, 
                                kubernetes_version: str = "1.24",
                                target_policy_level: PolicyLevel = PolicyLevel.RESTRICTED,
                                use_llm: bool = True) -> Dict[str, Any]:
        """Analyze a Pod configuration and provide security guidance"""
        
        # Detect policy type for the version
        policy_type_str = version_manager.get_policy_type_for_version(kubernetes_version)
        policy_type = PolicyType(policy_type_str)
        
        # Parse and analyze YAML
        analysis = self.yaml_analyzer.analyze_pod_yaml(yaml_content, kubernetes_version)
        
        # Get relevant security information from versioned vector store
        security_context = self._get_security_context(analysis, target_policy_level, kubernetes_version)
        
        # Generate comprehensive security advice
        security_advice = self._generate_security_advice(analysis, security_context, target_policy_level)
        
        # Add version-specific notes
        version_note = None
        if policy_type == PolicyType.POD_SECURITY_POLICY:
            version_note = "이 버전(1.20~1.21)은 PodSecurityPolicy(PSP) 기반의 레거시 보안 정책이 적용됩니다. 일부 최신 필드와 정책은 지원되지 않을 수 있습니다. 가능한 경우 1.24+로 업그레이드를 권장합니다."
        elif policy_type == PolicyType.POD_SECURITY_STANDARDS_ALPHA:
            version_note = "이 버전(1.22~1.23)은 Pod Security Standards(PSS) Alpha 단계로, 일부 필드와 정책이 제한적으로 지원됩니다. 프로덕션 환경에서는 1.24+로 업그레이드를 권장합니다."
        elif policy_type == PolicyType.POD_SECURITY_STANDARDS_STABLE:
            version_note = "이 버전(1.24+)은 Pod Security Standards(PSS) Stable이 적용되어, 최신 보안 정책과 필드를 모두 지원합니다."
        
        # Generate LLM-enhanced advice if available
        llm_korean_advice = None
        fixed_yaml = None
        if use_llm and self.llm:
            try:
                llm_korean_advice = self.llm.generate_security_advice(
                    analysis.analysis_results,
                    security_context,
                    target_policy_level.value,
                    kubernetes_version
                )
                
                # Generate fixed YAML
                fixed_yaml = self.llm.generate_fixed_yaml(
                    yaml_content,
                    analysis.analysis_results,
                    kubernetes_version
                )
            except Exception as e:
                print(f"LLM integration error: {e}")
        
        return {
            "analysis": analysis.dict(),
            "security_context": security_context,
            "security_advice": security_advice,
            "llm_korean_advice": llm_korean_advice,
            "fixed_yaml": fixed_yaml,
            "target_policy_level": target_policy_level.value,
            "kubernetes_version": kubernetes_version,
            "policy_type": policy_type.value,
            "version_note": version_note
        }
    
    def answer_security_question(self, question: str, 
                               kubernetes_version: str = "1.24",
                               policy_level: Optional[PolicyLevel] = None,
                               use_llm: bool = True) -> Dict[str, Any]:
        """Answer security-related questions using RAG"""
        
        # Search for relevant information using vector store
        # versioned_vector_store가 있으면 사용, 없으면 기본 vector_store 사용
        if hasattr(self, 'versioned_vector_store') and self.versioned_vector_store:
            try:
                search_results = self.versioned_vector_store.search(
                    query=question,
                    version=kubernetes_version,
                    n_results=5,
                    policy_level=policy_level
                )
            except Exception as e:
                print(f"Versioned vector store search failed, falling back to basic vector store: {e}")
                search_results = self.vector_store.search(
                    query=question,
                    n_results=5
                )
        else:
            # 기본 vector store 사용
            search_results = self.vector_store.search(
                query=question,
                n_results=5
            )
        
        # Generate contextual answer
        answer = self._generate_contextual_answer(question, search_results, policy_level)
        
        # Generate LLM-enhanced answer if available
        llm_answer = None
        if use_llm and self.llm:
            try:
                llm_answer = self.llm.answer_security_question(
                    question,
                    search_results,
                    policy_level.value if policy_level else None
                )
            except Exception as e:
                print(f"LLM integration error: {e}")
        
        return {
            "question": question,
            "answer": answer,
            "llm_answer": llm_answer,
            "sources": search_results,
            "policy_level": policy_level.value if policy_level else "Any",
            "kubernetes_version": kubernetes_version
        }
    
    def get_field_guidance(self, field_name: str, 
                          kubernetes_version: str = "1.24",
                          use_llm: bool = True) -> Dict[str, Any]:
        """Get detailed guidance for a specific security field"""
        
        # Get all chunks for the field from versioned vector store
        field_chunks = self.versioned_vector_store.get_by_field_name(field_name, kubernetes_version)
        
        if not field_chunks:
            return {
                "field_name": field_name,
                "error": "Field not found in security database",
                "available_fields": list(self.yaml_analyzer.security_fields.keys())
            }
        
        # Organize chunks by type
        organized_chunks = {
            "description": [],
            "example": [],
            "pitfalls": [],
            "remediation": []
        }
        
        for chunk in field_chunks:
            chunk_type = chunk["metadata"].get("chunk_type", "description")
            if chunk_type in organized_chunks:
                organized_chunks[chunk_type].append(chunk)
        
        # Generate comprehensive guidance
        guidance = self._generate_field_guidance(field_name, organized_chunks, kubernetes_version)
        
        # Generate LLM-enhanced guidance if available
        llm_guidance = None
        if use_llm and self.llm and organized_chunks["description"]:  # Only if we have description chunks
            try:
                llm_guidance = self.llm.generate_field_guidance(
                    field_name,
                    organized_chunks,
                    kubernetes_version
                )
            except Exception as e:
                print(f"LLM integration error for field guidance: {e}")
                llm_guidance = f"Error generating LLM guidance: {str(e)}"
        
        return {
            "field_name": field_name,
            "kubernetes_version": kubernetes_version,
            "guidance": guidance,
            "llm_guidance": llm_guidance,
            "chunks": organized_chunks,
            "chunk_count": len(field_chunks)
        }
    
    def _get_security_context(self, analysis: PodSecurityAnalysis, 
                            target_policy_level: PolicyLevel,
                            kubernetes_version: str) -> List[Dict[str, Any]]:
        """Get relevant security context for the analysis"""
        context = []
        
        # Get context for each analyzed field
        for result in analysis.analysis_results:
            if "field_name" in result:
                field_name = result["field_name"]
                
                # Search for relevant information using versioned vector store
                search_results = self.versioned_vector_store.search(
                    query=f"security guidance for {field_name}",
                    version=kubernetes_version,
                    n_results=3,
                    field_name=field_name
                )
                
                context.extend(search_results)
        
        # Get general policy-level guidance
        policy_results = self.versioned_vector_store.search(
            query=f"{target_policy_level.value} policy level requirements",
            version=kubernetes_version,
            n_results=3,
            policy_level=target_policy_level
        )
        
        context.extend(policy_results)
        
        return context
    
    def _generate_security_advice(self, analysis: PodSecurityAnalysis, 
                                security_context: List[Dict[str, Any]],
                                target_policy_level: PolicyLevel) -> Dict[str, Any]:
        """Generate comprehensive security advice"""
        
        advice = {
            "summary": self._generate_summary(analysis, target_policy_level),
            "critical_issues": self._generate_critical_issues_advice(analysis),
            "warnings": self._generate_warnings_advice(analysis),
            "recommendations": self._generate_detailed_recommendations(analysis, security_context),
            "compliance_status": self._generate_compliance_status(analysis, target_policy_level),
            "next_steps": self._generate_next_steps(analysis, target_policy_level)
        }
        
        return advice
    
    def _generate_summary(self, analysis: PodSecurityAnalysis, 
                         target_policy_level: PolicyLevel) -> str:
        """Generate a summary of the security analysis"""
        
        score = analysis.overall_score
        critical_count = len(analysis.critical_issues)
        warning_count = len(analysis.warnings)
        
        if score >= 90:
            status = "Excellent"
        elif score >= 70:
            status = "Good"
        elif score >= 50:
            status = "Fair"
        else:
            status = "Poor"
        
        summary = f"""
Security Analysis Summary:
- Overall Security Score: {score:.1f}/100 ({status})
- Critical Issues: {critical_count}
- Warnings: {warning_count}
- Target Policy Level: {target_policy_level.value}
- Policy Compliance: {'✅ Compliant' if analysis.policy_compliance[target_policy_level] else '❌ Non-compliant'}
        """.strip()
        
        return summary
    
    def _generate_critical_issues_advice(self, analysis: PodSecurityAnalysis) -> List[Dict[str, str]]:
        """Generate advice for critical issues"""
        advice = []
        
        for issue in analysis.critical_issues:
            # Find relevant security context for this issue
            search_results = self.vector_store.search(
                query=issue,
                n_results=2
            )
            
            context = ""
            if search_results:
                context = search_results[0]["content"]
            
            advice.append({
                "issue": issue,
                "priority": "Critical",
                "context": context,
                "action": "Fix immediately before deployment"
            })
        
        return advice
    
    def _generate_warnings_advice(self, analysis: PodSecurityAnalysis) -> List[Dict[str, str]]:
        """Generate advice for warnings"""
        advice = []
        
        for warning in analysis.warnings:
            # Find relevant security context for this warning
            search_results = self.vector_store.search(
                query=warning,
                n_results=2
            )
            
            context = ""
            if search_results:
                context = search_results[0]["content"]
            
            advice.append({
                "warning": warning,
                "priority": "Medium",
                "context": context,
                "action": "Address before production deployment"
            })
        
        return advice
    
    def _generate_detailed_recommendations(self, analysis: PodSecurityAnalysis,
                                         security_context: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Generate detailed recommendations with context"""
        recommendations = []
        
        for rec in analysis.recommendations:
            # Find relevant context for this recommendation
            search_results = self.vector_store.search(
                query=rec,
                n_results=1
            )
            
            context = ""
            if search_results:
                context = search_results[0]["content"]
            
            recommendations.append({
                "recommendation": rec,
                "context": context,
                "implementation": "Review the context above for implementation details"
            })
        
        return recommendations
    
    def _generate_compliance_status(self, analysis: PodSecurityAnalysis,
                                  target_policy_level: PolicyLevel) -> Dict[str, Any]:
        """Generate detailed compliance status"""
        
        compliance = analysis.policy_compliance[target_policy_level]
        
        if compliance:
            status = "✅ Compliant"
            message = f"Pod configuration meets {target_policy_level.value} policy requirements"
        else:
            status = "❌ Non-compliant"
            message = f"Pod configuration does not meet {target_policy_level.value} policy requirements"
        
        return {
            "status": status,
            "message": message,
            "target_level": target_policy_level.value,
            "baseline_compliant": analysis.policy_compliance[PolicyLevel.BASELINE],
            "restricted_compliant": analysis.policy_compliance[PolicyLevel.RESTRICTED]
        }
    
    def _generate_next_steps(self, analysis: PodSecurityAnalysis,
                           target_policy_level: PolicyLevel) -> List[str]:
        """Generate next steps for improving security"""
        steps = []
        
        if not analysis.policy_compliance[target_policy_level]:
            steps.append(f"Address all critical issues and warnings to achieve {target_policy_level.value} compliance")
        
        if analysis.critical_issues:
            steps.append("Fix critical security issues immediately")
        
        if analysis.warnings:
            steps.append("Address security warnings before production deployment")
        
        steps.append("Review and implement all security recommendations")
        steps.append("Test the configuration in a staging environment")
        steps.append("Consider implementing additional security measures like network policies")
        
        return steps
    
    def _generate_contextual_answer(self, question: str, 
                                  search_results: List[Dict[str, Any]],
                                  policy_level: Optional[PolicyLevel]) -> str:
        """Generate a contextual answer based on search results"""
        
        if not search_results:
            return "I couldn't find specific information about that question in the Kubernetes security database."
        
        # Combine relevant information from search results
        context_parts = []
        for result in search_results[:3]:  # Use top 3 results
            context_parts.append(result["content"])
        
        context = "\n\n".join(context_parts)
        
        # Generate a structured answer
        answer = f"""
Based on the Kubernetes security documentation, here's what I found:

{context}

This information is sourced from the Kubernetes Pod Security Standards and related security documentation.
        """.strip()
        
        return answer
    
    def _generate_field_guidance(self, field_name: str, 
                               organized_chunks: Dict[str, List[Dict[str, Any]]],
                               kubernetes_version: str) -> Dict[str, Any]:
        """Generate comprehensive guidance for a specific field"""
        
        guidance = {
            "field_name": field_name,
            "kubernetes_version": kubernetes_version,
            "description": "",
            "examples": [],
            "pitfalls": [],
            "remediation": [],
            "best_practices": []
        }
        
        # Extract description
        if organized_chunks["description"]:
            guidance["description"] = organized_chunks["description"][0]["content"]
        
        # Extract examples
        for chunk in organized_chunks["example"]:
            guidance["examples"].append(chunk["content"])
        
        # Extract pitfalls
        for chunk in organized_chunks["pitfalls"]:
            guidance["pitfalls"].append(chunk["content"])
        
        # Extract remediation
        for chunk in organized_chunks["remediation"]:
            guidance["remediation"].append(chunk["content"])
        
        # Generate best practices summary
        if organized_chunks["description"]:
            guidance["best_practices"] = self._extract_best_practices(organized_chunks["description"][0]["content"])
        
        return guidance
    
    def _extract_best_practices(self, description: str) -> List[str]:
        """Extract best practices from description"""
        # This is a simple extraction - in a real system, you might use more sophisticated NLP
        practices = []
        
        lines = description.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('-') or line.startswith('•'):
                practices.append(line[1:].strip())
            elif 'recommend' in line.lower() or 'should' in line.lower():
                practices.append(line)
        
        return practices[:5]  # Limit to top 5 practices 