from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


class PolicyLevel(str, Enum):
    """Kubernetes Pod Security Standards levels"""
    BASELINE = "Baseline"
    RESTRICTED = "Restricted"
    PRIVILEGED = "Privileged"


class PolicyType(str, Enum):
    """Kubernetes security policy types by version"""
    POD_SECURITY_POLICY = "PodSecurityPolicy"           # 1.20-1.21
    POD_SECURITY_STANDARDS_ALPHA = "PodSecurityStandardsAlpha"  # 1.22-1.23
    POD_SECURITY_STANDARDS_STABLE = "PodSecurityStandardsStable"  # 1.24+


class SecurityField(BaseModel):
    """Schema for Kubernetes Pod security configuration fields"""
    field_name: str = Field(..., description="The YAML field name (e.g., 'runAsNonRoot')")
    field_path: str = Field(..., description="Full path to the field (e.g., 'spec.securityContext.runAsNonRoot')")
    description: str = Field(..., description="Detailed description of the security field")
    policy_level: PolicyLevel = Field(..., description="Minimum policy level that enforces this field")
    version_added: Optional[str] = Field(None, description="Kubernetes version when this field was added")
    deprecated_in: Optional[str] = Field(None, description="Kubernetes version when this field was deprecated")
    default_value: Optional[str] = Field(None, description="Default value if not specified")
    acceptable_values: List[str] = Field(default_factory=list, description="List of acceptable values")
    security_impact: str = Field(..., description="Explanation of security implications")
    yaml_example: Optional[str] = Field(None, description="YAML example showing proper usage")
    common_pitfalls: List[str] = Field(default_factory=list, description="Common mistakes and pitfalls")
    remediation_steps: List[str] = Field(default_factory=list, description="Steps to fix security issues")
    related_fields: List[str] = Field(default_factory=list, description="Related security fields")
    cve_references: List[str] = Field(default_factory=list, description="Related CVEs or security advisories")
    source_document: str = Field(..., description="Source document (e.g., 'Kubernetes Pod Security Standards')")
    last_updated: datetime = Field(default_factory=datetime.now, description="When this information was last updated")


class SecurityChunk(BaseModel):
    """Schema for vector database chunks"""
    id: str = Field(..., description="Unique identifier for the chunk")
    content: str = Field(..., description="The main content text for embedding")
    metadata: Dict[str, Any] = Field(..., description="Metadata for filtering and retrieval")
    field_name: str = Field(..., description="Associated security field name")
    policy_level: PolicyLevel = Field(..., description="Policy level this chunk relates to")
    version_added: Optional[str] = Field(None, description="Kubernetes version when this was added")
    deprecated_in: Optional[str] = Field(None, description="Kubernetes version when this was deprecated")
    has_example: bool = Field(False, description="Whether this chunk contains a YAML example")
    source_document: str = Field(..., description="Source document")
    tags: List[str] = Field(default_factory=list, description="Additional tags for categorization")


class PodSecurityAnalysis(BaseModel):
    """Schema for analysis results"""
    pod_yaml: str = Field(..., description="Input YAML configuration")
    kubernetes_version: str = Field(..., description="Target Kubernetes version")
    analysis_results: List[Dict[str, Any]] = Field(..., description="Security analysis results")
    overall_score: float = Field(..., description="Overall security score (0-100)")
    policy_compliance: Dict[PolicyLevel, bool] = Field(..., description="Compliance with each policy level")
    recommendations: List[str] = Field(..., description="List of security recommendations")
    critical_issues: List[str] = Field(..., description="Critical security issues found")
    warnings: List[str] = Field(..., description="Security warnings")
    fixed_yaml: Optional[str] = Field(None, description="Corrected YAML configuration") 