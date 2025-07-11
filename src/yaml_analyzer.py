import yaml
from typing import Dict, Any, List, Optional, Tuple
# Conditional imports for different execution contexts
try:
    # When running as module
    from .schema import PolicyLevel, PodSecurityAnalysis
    from .security_data import get_security_fields
except ImportError:
    # When running directly
    from schema import PolicyLevel, PodSecurityAnalysis
    from security_data import get_security_fields
import re


class KubernetesYAMLAnalyzer:
    """Analyzer for Kubernetes Pod YAML configurations"""
    
    def __init__(self):
        self.security_fields = {field.field_name: field for field in get_security_fields()}
        self.field_paths = {field.field_path: field for field in get_security_fields()}
    
    def parse_yaml(self, yaml_content: str) -> Dict[str, Any]:
        """Parse YAML content and return structured data"""
        try:
            return yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML format: {e}")
    
    def extract_security_fields(self, pod_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Extract security-related fields from pod spec"""
        security_fields = {}
        
        # Extract pod-level security context
        if "securityContext" in pod_spec:
            security_fields["pod_security_context"] = pod_spec["securityContext"]
        
        # Extract container-level security contexts
        if "containers" in pod_spec:
            for i, container in enumerate(pod_spec["containers"]):
                if "securityContext" in container:
                    security_fields[f"container_{i}_security_context"] = container["securityContext"]
        
        # Extract host-level fields
        host_fields = ["hostPID", "hostIPC", "hostNetwork"]
        for field in host_fields:
            if field in pod_spec:
                security_fields[field] = pod_spec[field]
        
        return security_fields
    
    def analyze_security_field(self, field_name: str, value: Any, 
                             kubernetes_version: str = "1.24") -> Dict[str, Any]:
        """Analyze a specific security field"""
        if field_name not in self.security_fields:
            return {
                "field_name": field_name,
                "value": value,
                "status": "unknown",
                "message": f"Unknown security field: {field_name}",
                "recommendation": "Review if this field is necessary for your use case"
            }
        
        field = self.security_fields[field_name]
        
        # Check if field is deprecated
        if field.deprecated_in and self._version_compare(kubernetes_version, field.deprecated_in) >= 0:
            return {
                "field_name": field_name,
                "value": value,
                "status": "deprecated",
                "message": f"Field is deprecated in Kubernetes {field.deprecated_in}",
                "recommendation": "Consider using alternative approaches",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
        
        # Analyze based on field type
        if field_name == "runAsNonRoot":
            return self._analyze_run_as_non_root(value, field)
        elif field_name == "allowPrivilegeEscalation":
            return self._analyze_allow_privilege_escalation(value, field)
        elif field_name == "privileged":
            return self._analyze_privileged(value, field)
        elif field_name == "readOnlyRootFilesystem":
            return self._analyze_read_only_root_filesystem(value, field)
        elif field_name == "runAsUser":
            return self._analyze_run_as_user(value, field)
        elif field_name == "capabilities":
            return self._analyze_capabilities(value, field)
        elif field_name in ["hostPID", "hostIPC", "hostNetwork"]:
            return self._analyze_host_fields(field_name, value, field)
        elif field_name in ["seccompProfile", "apparmorProfile"]:
            return self._analyze_security_profiles(field_name, value, field)
        else:
            return self._analyze_generic_field(field_name, value, field)
    
    def _analyze_run_as_non_root(self, value: Any, field) -> Dict[str, Any]:
        """Analyze runAsNonRoot field"""
        if value is True:
            return {
                "field_name": "runAsNonRoot",
                "value": value,
                "status": "secure",
                "message": "Container is configured to run as non-root",
                "recommendation": "Good security practice",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
        elif value is False:
            return {
                "field_name": "runAsNonRoot",
                "value": value,
                "status": "warning",
                "message": "Container can run as root user",
                "recommendation": "Set to true for better security",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
        else:
            return {
                "field_name": "runAsNonRoot",
                "value": value,
                "status": "error",
                "message": "runAsNonRoot should be explicitly set to true or false",
                "recommendation": "Set runAsNonRoot: true for security",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
    
    def _analyze_allow_privilege_escalation(self, value: Any, field) -> Dict[str, Any]:
        """Analyze allowPrivilegeEscalation field"""
        if value is False:
            return {
                "field_name": "allowPrivilegeEscalation",
                "value": value,
                "status": "secure",
                "message": "Privilege escalation is disabled",
                "recommendation": "Good security practice",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
        elif value is True:
            return {
                "field_name": "allowPrivilegeEscalation",
                "value": value,
                "status": "warning",
                "message": "Privilege escalation is allowed",
                "recommendation": "Set to false for better security",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
        else:
            return {
                "field_name": "allowPrivilegeEscalation",
                "value": value,
                "status": "error",
                "message": "allowPrivilegeEscalation should be explicitly set",
                "recommendation": "Set allowPrivilegeEscalation: false",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
    
    def _analyze_privileged(self, value: Any, field) -> Dict[str, Any]:
        """Analyze privileged field"""
        if value is True:
            return {
                "field_name": "privileged",
                "value": value,
                "status": "critical",
                "message": "Container runs in privileged mode - EXTREMELY DANGEROUS",
                "recommendation": "Remove privileged: true immediately",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
        elif value is False:
            return {
                "field_name": "privileged",
                "value": value,
                "status": "secure",
                "message": "Container is not privileged",
                "recommendation": "Good security practice",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
        else:
            return {
                "field_name": "privileged",
                "value": value,
                "status": "warning",
                "message": "Privileged mode not explicitly disabled",
                "recommendation": "Set privileged: false explicitly",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
    
    def _analyze_read_only_root_filesystem(self, value: Any, field) -> Dict[str, Any]:
        """Analyze readOnlyRootFilesystem field"""
        if value is True:
            return {
                "field_name": "readOnlyRootFilesystem",
                "value": value,
                "status": "secure",
                "message": "Root filesystem is read-only",
                "recommendation": "Good security practice",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
        elif value is False:
            return {
                "field_name": "readOnlyRootFilesystem",
                "value": value,
                "status": "warning",
                "message": "Root filesystem is writable",
                "recommendation": "Set to true for better security",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
        else:
            return {
                "field_name": "readOnlyRootFilesystem",
                "value": value,
                "status": "error",
                "message": "readOnlyRootFilesystem should be explicitly set",
                "recommendation": "Set readOnlyRootFilesystem: true",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
    
    def _analyze_run_as_user(self, value: Any, field) -> Dict[str, Any]:
        """Analyze runAsUser field"""
        if value == 0:
            return {
                "field_name": "runAsUser",
                "value": value,
                "status": "critical",
                "message": "Container runs as root user (UID 0)",
                "recommendation": "Use a non-zero UID",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
        elif value and value > 0:
            return {
                "field_name": "runAsUser",
                "value": value,
                "status": "secure",
                "message": f"Container runs as non-root user (UID {value})",
                "recommendation": "Good security practice",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
        else:
            return {
                "field_name": "runAsUser",
                "value": value,
                "status": "warning",
                "message": "runAsUser should be explicitly set to a non-zero value",
                "recommendation": "Set runAsUser to a non-zero value (e.g., 1000)",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
    
    def _analyze_capabilities(self, value: Any, field) -> Dict[str, Any]:
        """Analyze capabilities field"""
        if not value:
            return {
                "field_name": "capabilities",
                "value": value,
                "status": "warning",
                "message": "Capabilities not explicitly configured",
                "recommendation": "Drop ALL capabilities and add only required ones",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
        
        drop_all = False
        added_capabilities = []
        
        if "drop" in value:
            if "ALL" in value["drop"]:
                drop_all = True
        
        if "add" in value:
            added_capabilities = value["add"]
        
        if drop_all and not added_capabilities:
            return {
                "field_name": "capabilities",
                "value": value,
                "status": "secure",
                "message": "All capabilities dropped, no additional capabilities added",
                "recommendation": "Good security practice",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
        elif drop_all and added_capabilities:
            return {
                "field_name": "capabilities",
                "value": value,
                "status": "secure",
                "message": f"All capabilities dropped, only specific capabilities added: {added_capabilities}",
                "recommendation": "Good security practice - review if all added capabilities are necessary",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
        else:
            return {
                "field_name": "capabilities",
                "value": value,
                "status": "warning",
                "message": "Not all capabilities are dropped",
                "recommendation": "Drop ALL capabilities and add only required ones",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
    
    def _analyze_host_fields(self, field_name: str, value: Any, field) -> Dict[str, Any]:
        """Analyze host-level fields (hostPID, hostIPC, hostNetwork)"""
        if value is True:
            return {
                "field_name": field_name,
                "value": value,
                "status": "critical",
                "message": f"{field_name} is enabled - DANGEROUS",
                "recommendation": f"Remove {field_name}: true",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
        elif value is False:
            return {
                "field_name": field_name,
                "value": value,
                "status": "secure",
                "message": f"{field_name} is enabled",
                "recommendation": "Good security practice",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
        else:
            return {
                "field_name": field_name,
                "value": value,
                "status": "warning",
                "message": f"{field_name} should be explicitly set to false",
                "recommendation": f"Set {field_name}: false",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
    
    def _analyze_security_profiles(self, field_name: str, value: Any, field) -> Dict[str, Any]:
        """Analyze security profile fields (seccompProfile, apparmorProfile)"""
        if isinstance(value, dict) and "type" in value:
            profile_type = value["type"]
        else:
            profile_type = value
        
        if profile_type == "RuntimeDefault":
            return {
                "field_name": field_name,
                "value": value,
                "status": "secure",
                "message": f"{field_name} is set to RuntimeDefault",
                "recommendation": "Good security practice",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
        elif profile_type == "Unconfined":
            return {
                "field_name": field_name,
                "value": value,
                "status": "warning",
                "message": f"{field_name} is set to Unconfined",
                "recommendation": f"Set {field_name} to RuntimeDefault",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
        else:
            return {
                "field_name": field_name,
                "value": value,
                "status": "warning",
                "message": f"{field_name} should be set to RuntimeDefault",
                "recommendation": f"Set {field_name} to RuntimeDefault",
                "policy_level": field.policy_level.value,
                "security_impact": field.security_impact
            }
    
    def _analyze_generic_field(self, field_name: str, value: Any, field) -> Dict[str, Any]:
        """Analyze generic security fields"""
        return {
            "field_name": field_name,
            "value": value,
            "status": "info",
            "message": f"Field {field_name} is set to {value}",
            "recommendation": "Review if this configuration is appropriate",
            "policy_level": field.policy_level.value,
            "security_impact": field.security_impact
        }
    
    def _version_compare(self, version1: str, version2: str) -> int:
        """Compare two Kubernetes versions"""
        v1_parts = [int(x) for x in version1.split('.')]
        v2_parts = [int(x) for x in version2.split('.')]
        
        for i in range(max(len(v1_parts), len(v2_parts))):
            v1_part = v1_parts[i] if i < len(v1_parts) else 0
            v2_part = v2_parts[i] if i < len(v2_parts) else 0
            
            if v1_part < v2_part:
                return -1
            elif v1_part > v2_part:
                return 1
        
        return 0
    
    def analyze_pod_yaml(self, yaml_content: str, kubernetes_version: str = "1.24") -> PodSecurityAnalysis:
        """Analyze a complete Pod YAML configuration"""
        try:
            pod_data = self.parse_yaml(yaml_content)
        except ValueError as e:
            return PodSecurityAnalysis(
                pod_yaml=yaml_content,
                kubernetes_version=kubernetes_version,
                analysis_results=[{"error": str(e)}],
                overall_score=0.0,
                policy_compliance={PolicyLevel.BASELINE: False, PolicyLevel.RESTRICTED: False},
                recommendations=["Fix YAML syntax errors"],
                critical_issues=["Invalid YAML format"],
                warnings=[]
            )
        
        # Extract pod spec
        if "spec" not in pod_data:
            return PodSecurityAnalysis(
                pod_yaml=yaml_content,
                kubernetes_version=kubernetes_version,
                analysis_results=[{"error": "No spec found in Pod"}],
                overall_score=0.0,
                policy_compliance={PolicyLevel.BASELINE: False, PolicyLevel.RESTRICTED: False},
                recommendations=["Add spec section to Pod"],
                critical_issues=["Missing spec section"],
                warnings=[]
            )
        
        pod_spec = pod_data["spec"]
        security_fields = self.extract_security_fields(pod_spec)
        
        # Analyze each security field
        analysis_results = []
        critical_issues = []
        warnings = []
        recommendations = []
        
        for field_name, value in security_fields.items():
            if field_name.startswith("container_") and field_name.endswith("_security_context"):
                # Handle container security contexts
                container_idx = field_name.split("_")[1]
                for ctx_field, ctx_value in value.items():
                    result = self.analyze_security_field(ctx_field, ctx_value, kubernetes_version)
                    analysis_results.append(result)
                    
                    if result["status"] == "critical":
                        critical_issues.append(f"{ctx_field}: {result['message']}")
                    elif result["status"] == "warning":
                        warnings.append(f"{ctx_field}: {result['message']}")
                    
                    recommendations.append(result["recommendation"])
            else:
                # Handle pod-level fields
                result = self.analyze_security_field(field_name, value, kubernetes_version)
                analysis_results.append(result)
                
                if result["status"] == "critical":
                    critical_issues.append(f"{field_name}: {result['message']}")
                elif result["status"] == "warning":
                    warnings.append(f"{field_name}: {result['message']}")
                
                recommendations.append(result["recommendation"])
        
        # Calculate overall score
        total_fields = len(analysis_results)
        secure_fields = sum(1 for r in analysis_results if r["status"] == "secure")
        overall_score = (secure_fields / total_fields * 100) if total_fields > 0 else 0.0
        
        # Check policy compliance
        policy_compliance = {
            PolicyLevel.BASELINE: not any(r["status"] == "critical" for r in analysis_results),
            PolicyLevel.RESTRICTED: not any(r["status"] in ["critical", "warning"] for r in analysis_results)
        }
        
        return PodSecurityAnalysis(
            pod_yaml=yaml_content,
            kubernetes_version=kubernetes_version,
            analysis_results=analysis_results,
            overall_score=overall_score,
            policy_compliance=policy_compliance,
            recommendations=list(set(recommendations)),  # Remove duplicates
            critical_issues=critical_issues,
            warnings=warnings
        ) 