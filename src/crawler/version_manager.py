from typing import Dict, List, Optional
from dataclasses import dataclass
import re


@dataclass
class KubernetesVersion:
    """Kubernetes version information"""
    version: str
    major: int
    minor: int
    patch: int
    is_lts: bool
    docs_url: str
    security_docs_url: str
    policy_type: str


class VersionManager:
    """
    Manages Kubernetes version information and documentation URLs
    """
    
    def __init__(self):
        self.versions = self._initialize_versions()
    
    def _initialize_versions(self) -> Dict[str, KubernetesVersion]:
        """Initialize supported Kubernetes versions"""
        versions = {}
        
        # Major versions with their documentation URLs
        version_configs = [
            {
                "version": "1.20",
                "is_lts": False,
                "docs_url": "https://kubernetes.io/docs/",
                "security_docs_url": "https://kubernetes.io/docs/concepts/security/pod-security-policy/",
                "policy_type": "PodSecurityPolicy"
            },
            {
                "version": "1.21",
                "is_lts": True,
                "docs_url": "https://kubernetes.io/docs/",
                "security_docs_url": "https://kubernetes.io/docs/concepts/security/pod-security-policy/",
                "policy_type": "PodSecurityPolicy"
            },
            {
                "version": "1.22",
                "is_lts": False,
                "docs_url": "https://kubernetes.io/docs/",
                "security_docs_url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                "policy_type": "PodSecurityStandardsAlpha"
            },
            {
                "version": "1.23",
                "is_lts": False,
                "docs_url": "https://kubernetes.io/docs/",
                "security_docs_url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                "policy_type": "PodSecurityStandardsAlpha"
            },

            {
                "version": "1.24",
                "is_lts": True,
                "docs_url": "https://kubernetes.io/docs/",
                "security_docs_url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                "policy_type": "PodSecurityStandardsStable"
            },
            {
                "version": "1.25",
                "is_lts": False,
                "docs_url": "https://kubernetes.io/docs/",
                "security_docs_url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                "policy_type": "PodSecurityStandardsStable"
            },
            {
                "version": "1.26",
                "is_lts": False,
                "docs_url": "https://kubernetes.io/docs/",
                "security_docs_url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                "policy_type": "PodSecurityStandardsStable"
            },
            {
                "version": "1.27",
                "is_lts": True,
                "docs_url": "https://kubernetes.io/docs/",
                "security_docs_url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                "policy_type": "PodSecurityStandardsStable"
            },
            {
                "version": "1.28",
                "is_lts": False,
                "docs_url": "https://kubernetes.io/docs/",
                "security_docs_url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                "policy_type": "PodSecurityStandardsStable"
            },
            {
                "version": "1.29",
                "is_lts": False,
                "docs_url": "https://kubernetes.io/docs/",
                "security_docs_url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                "policy_type": "PodSecurityStandardsStable"
            }
        ]
        
        for config in version_configs:
            version_str = config["version"]
            major, minor = map(int, version_str.split("."))
            
            versions[version_str] = KubernetesVersion(
                version=version_str,
                major=major,
                minor=minor,
                patch=0,  # We focus on major.minor versions
                is_lts=config["is_lts"],
                docs_url=config["docs_url"],
                security_docs_url=config["security_docs_url"],
                policy_type=config.get("policy_type", "PodSecurityStandardsStable")
            )
        
        return versions
    
    def get_supported_versions(self) -> List[str]:
        """Get list of supported Kubernetes versions"""
        return list(self.versions.keys())
    
    def get_lts_versions(self) -> List[str]:
        """Get list of LTS (Long Term Support) versions"""
        return [v.version for v in self.versions.values() if v.is_lts]
    
    def get_version_info(self, version: str) -> Optional[KubernetesVersion]:
        """Get version information for a specific version"""
        return self.versions.get(version)
    
    def get_docs_url(self, version: str) -> Optional[str]:
        """Get documentation URL for a specific version"""
        version_info = self.get_version_info(version)
        return version_info.docs_url if version_info else None
    
    def get_security_docs_url(self, version: str) -> Optional[str]:
        """Get security documentation URL for a specific version"""
        version_info = self.get_version_info(version)
        return version_info.security_docs_url if version_info else None
    
    def is_version_supported(self, version: str) -> bool:
        """Check if a version is supported"""
        return version in self.versions
    
    def get_version_urls(self, version: str) -> Dict[str, str]:
        """Get all relevant URLs for a specific version"""
        version_info = self.get_version_info(version)
        if not version_info:
            return {}
        
        return {
            "docs": version_info.docs_url,
            "security": version_info.security_docs_url,
            "pod_security_standards": version_info.security_docs_url,
            "security_context": f"{version_info.docs_url}tasks/configure-pod-container/security-context/",
            "pod_security_policies": f"{version_info.docs_url}concepts/security/pod-security-policy/",
            "rbac": f"{version_info.docs_url}concepts/security/controlling-access/",
            "network_policies": f"{version_info.docs_url}concepts/services-networking/network-policies/",
            "secrets": f"{version_info.docs_url}concepts/configuration/secret/",
            "configmaps": f"{version_info.docs_url}concepts/configuration/configmap/",
            "service_accounts": f"{version_info.docs_url}concepts/security/service-accounts/"
        }
    
    def parse_version_string(self, version_str: str) -> Optional[Dict[str, int]]:
        """Parse version string and return components"""
        pattern = r'^(\d+)\.(\d+)(?:\.(\d+))?$'
        match = re.match(pattern, version_str)
        
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3)) if match.group(3) else 0
            
            return {
                "major": major,
                "minor": minor,
                "patch": patch
            }
        
        return None
    
    def get_closest_supported_version(self, version: str) -> Optional[str]:
        """Get the closest supported version to the given version"""
        parsed = self.parse_version_string(version)
        if not parsed:
            return None
        
        target_major = parsed["major"]
        target_minor = parsed["minor"]
        
        # Find the closest version
        closest_version = None
        min_distance = float('inf')
        
        for supported_version in self.get_supported_versions():
            supported_info = self.get_version_info(supported_version)
            if not supported_info:
                continue
            
            # Calculate distance (simple Manhattan distance)
            distance = abs(supported_info.major - target_major) + abs(supported_info.minor - target_minor)
            
            if distance < min_distance:
                min_distance = distance
                closest_version = supported_version
        
        return closest_version
    
    def get_policy_type_for_version(self, version: str) -> str:
        """Get policy type for a specific Kubernetes version"""
        version_info = self.get_version_info(version)
        return version_info.policy_type if version_info else "PodSecurityStandardsStable"
    
    def get_versions_by_policy_type(self, policy_type: str) -> List[str]:
        """Get all versions that use a specific policy type"""
        return [v.version for v in self.versions.values() if v.policy_type == policy_type]
    
    def is_psp_version(self, version: str) -> bool:
        """Check if version uses PodSecurityPolicy"""
        return self.get_policy_type_for_version(version) == "PodSecurityPolicy"
    
    def is_pss_alpha_version(self, version: str) -> bool:
        """Check if version uses Pod Security Standards Alpha"""
        return self.get_policy_type_for_version(version) == "PodSecurityStandardsAlpha"
    
    def is_pss_stable_version(self, version: str) -> bool:
        """Check if version uses Pod Security Standards Stable"""
        return self.get_policy_type_for_version(version) == "PodSecurityStandardsStable"


# Global instance
version_manager = VersionManager() 