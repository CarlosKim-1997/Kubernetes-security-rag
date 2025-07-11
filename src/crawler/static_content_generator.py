#!/usr/bin/env python3
"""
Static content generator for older Kubernetes versions
Since v1.20 and v1.21 docs are no longer accessible, we generate static content
based on known documentation and best practices.
"""

import json
from typing import List, Dict, Any
from dataclasses import dataclass, asdict
from pathlib import Path

from .content_parser import ParsedContent


@dataclass
class StaticContent:
    """Static content for older Kubernetes versions"""
    title: str
    content: str
    url: str
    version: str
    sections: List[str]
    metadata: Dict[str, Any]


class StaticContentGenerator:
    """
    Generates static content for older Kubernetes versions
    """
    
    def __init__(self):
        self.content_templates = self._load_content_templates()
    
    def _load_content_templates(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load content templates for different versions"""
        return {
            "1.20": self._get_v1_20_content(),
            "1.21": self._get_v1_21_content(),
            "1.22": self._get_v1_22_content(),
            "1.23": self._get_v1_23_content()
        }
    
    def _get_v1_20_content(self) -> List[Dict[str, Any]]:
        """Get static content for Kubernetes 1.20"""
        return [
            {
                "title": "Pod Security Policy (PSP) - Kubernetes 1.20",
                "content": """
# Pod Security Policy (PSP) - Kubernetes 1.20

Pod Security Policy is a cluster-level resource that controls security sensitive aspects of the pod specification. The PodSecurityPolicy objects define a set of conditions that a pod must run with in order to be accepted into the system, as well as defaults for the related fields.

## Key Features in 1.20

### Privilege Escalation Controls
- `allowPrivilegeEscalation`: Controls whether a process can gain more privileges than its parent process
- `defaultAllowPrivilegeEscalation`: Sets the default for allowPrivilegeEscalation

### Capabilities
- `allowedCapabilities`: List of capabilities that can be added
- `requiredDropCapabilities`: List of capabilities that must be dropped
- `defaultAddCapabilities`: List of capabilities that are added by default

### Host Namespace Controls
- `hostPID`: Controls the host PID namespace
- `hostIPC`: Controls the host IPC namespace
- `hostNetwork`: Controls the host network namespace

### Volume Controls
- `volumes`: List of allowed volume types
- `fsGroup`: Controls the supplemental group applied to volumes
- `runAsUser`: Controls the user ID for the container
- `runAsGroup`: Controls the primary group ID for the container
- `supplementalGroups`: Controls the supplemental groups for the container

## Security Best Practices

1. **Run as Non-Root**: Always run containers as non-root users
2. **Drop Unnecessary Capabilities**: Remove capabilities that are not needed
3. **Use Read-Only Root Filesystem**: Mount the root filesystem as read-only
4. **Limit Volume Types**: Only allow necessary volume types
5. **Network Policies**: Use network policies to restrict pod-to-pod communication

## Example PSP Configuration

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  readOnlyRootFilesystem: true
```
""",
                "url": "https://kubernetes.io/docs/concepts/security/pod-security-policy/",
                "sections": ["PSP Overview", "Security Controls", "Best Practices", "Configuration"],
                "metadata": {
                    "type": "security_policy",
                    "version": "1.20",
                    "policy_type": "PodSecurityPolicy",
                    "category": "security"
                }
            },
            {
                "title": "Security Context - Kubernetes 1.20",
                "content": """
# Security Context - Kubernetes 1.20

Security Context defines privilege and access control settings for a Pod or Container.

## Pod Security Context

The Pod Security Context applies to all containers in the pod and can be overridden by container-level security context.

### Key Fields

- `runAsUser`: The user ID to run the entrypoint of the container process
- `runAsGroup`: The primary group ID to run the entrypoint of the container process
- `fsGroup`: A special supplemental group that applies to all containers in the pod
- `supplementalGroups`: A list of groups applied to the first process run in each container

## Container Security Context

Container Security Context applies to individual containers and can override pod-level settings.

### Security Settings

- `runAsUser`: User ID to run the container process
- `runAsGroup`: Group ID to run the container process
- `readOnlyRootFilesystem`: Mount the container's root filesystem as read-only
- `capabilities`: Add or drop Linux capabilities
- `allowPrivilegeEscalation`: Allow the process to gain more privileges than its parent process
- `privileged`: Run the container in privileged mode

## Example Configuration

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
  containers:
  - name: sec-ctx-demo
    image: busybox
    command: ["sh", "-c", "sleep 1h"]
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
```

## Best Practices

1. **Non-Root Execution**: Always run containers as non-root users
2. **Read-Only Root**: Use read-only root filesystem when possible
3. **Drop Capabilities**: Remove unnecessary Linux capabilities
4. **No Privilege Escalation**: Prevent privilege escalation
5. **Proper File Permissions**: Set appropriate file system group
""",
                "url": "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
                "sections": ["Pod Security Context", "Container Security Context", "Configuration", "Best Practices"],
                "metadata": {
                    "type": "security_context",
                    "version": "1.20",
                    "category": "security"
                }
            },
            {
                "title": "RBAC Authorization - Kubernetes 1.20",
                "content": """
# RBAC Authorization - Kubernetes 1.20

Role-Based Access Control (RBAC) is a method of regulating access to computer or network resources based on the roles of individual users within an enterprise.

## Core Concepts

### Roles and ClusterRoles
- **Role**: Namespace-scoped permissions
- **ClusterRole**: Cluster-scoped permissions

### RoleBindings and ClusterRoleBindings
- **RoleBinding**: Grants permissions within a namespace
- **ClusterRoleBinding**: Grants permissions across the entire cluster

## Default Roles

### User-Facing Roles
- `cluster-admin`: Super-user access
- `admin`: Admin access within a namespace
- `edit`: Read/write access within a namespace
- `view`: Read-only access within a namespace

## Example RBAC Configuration

```yaml
# Create a Role
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "watch", "list"]

# Create a RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: User
  name: jane
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

## Security Best Practices

1. **Principle of Least Privilege**: Grant minimum necessary permissions
2. **Regular Audits**: Regularly review and audit RBAC configurations
3. **Namespace Isolation**: Use namespaces to isolate resources
4. **Service Accounts**: Use dedicated service accounts for applications
5. **Avoid Cluster-Admin**: Minimize use of cluster-admin role
""",
                "url": "https://kubernetes.io/docs/concepts/security/controlling-access/",
                "sections": ["Core Concepts", "Default Roles", "Configuration", "Best Practices"],
                "metadata": {
                    "type": "rbac",
                    "version": "1.20",
                    "category": "security"
                }
            }
        ]
    
    def _get_v1_21_content(self) -> List[Dict[str, Any]]:
        """Get static content for Kubernetes 1.21"""
        return [
            {
                "title": "Pod Security Policy (PSP) - Kubernetes 1.21",
                "content": """
# Pod Security Policy (PSP) - Kubernetes 1.21

Pod Security Policy continues to be the primary mechanism for enforcing pod security in Kubernetes 1.21, with some enhancements and improvements over 1.20.

## Enhanced Features in 1.21

### Improved SELinux Support
- Better integration with SELinux policies
- Enhanced security context handling
- Improved audit logging

### Network Policy Integration
- Better integration with Network Policies
- Enhanced pod-to-pod communication controls
- Improved ingress/egress filtering

### Volume Security Enhancements
- Enhanced volume type restrictions
- Improved filesystem security
- Better secret management integration

## Security Controls

### Privilege Controls
- `privileged`: Controls privileged container creation
- `allowPrivilegeEscalation`: Controls privilege escalation
- `defaultAllowPrivilegeEscalation`: Default privilege escalation setting

### User and Group Controls
- `runAsUser`: Controls user ID for containers
- `runAsGroup`: Controls primary group ID
- `supplementalGroups`: Controls supplemental groups
- `fsGroup`: Controls filesystem group

### Capability Controls
- `allowedCapabilities`: Allowed Linux capabilities
- `requiredDropCapabilities`: Required dropped capabilities
- `defaultAddCapabilities`: Default added capabilities

## Example PSP for 1.21

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted-v1-21
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: 'runtime/default'
    apparmor.security.beta.kubernetes.io/allowedProfileNames: 'runtime/default'
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  readOnlyRootFilesystem: true
```

## Migration Considerations

1. **Gradual Migration**: Plan migration from older versions carefully
2. **Testing**: Test PSP configurations in non-production environments
3. **Monitoring**: Monitor pod creation and security events
4. **Documentation**: Update security documentation and runbooks
""",
                "url": "https://kubernetes.io/docs/concepts/security/pod-security-policy/",
                "sections": ["Enhanced Features", "Security Controls", "Configuration", "Migration"],
                "metadata": {
                    "type": "security_policy",
                    "version": "1.21",
                    "policy_type": "PodSecurityPolicy",
                    "category": "security"
                }
            },
            {
                "title": "Network Policies - Kubernetes 1.21",
                "content": """
# Network Policies - Kubernetes 1.21

Network Policies provide a way to specify how groups of pods are allowed to communicate with each other and other network endpoints.

## Key Features

### Pod Selectors
- Label-based pod selection
- Namespace-based filtering
- IP block-based rules

### Policy Types
- `Ingress`: Controls incoming traffic
- `Egress`: Controls outgoing traffic

### Rule Components
- `from`: Source of traffic (for ingress)
- `to`: Destination of traffic (for egress)
- `ports`: Port and protocol specifications
- `protocol`: Network protocol (TCP, UDP, SCTP)

## Example Network Policy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test-network-policy
  namespace: default
spec:
  podSelector:
    matchLabels:
      role: db
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: frontend
    - podSelector:
        matchLabels:
          role: frontend
    ports:
    - protocol: TCP
      port: 6379
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
```

## Security Best Practices

1. **Default Deny**: Start with deny-all policies
2. **Namespace Isolation**: Use namespaces to group related pods
3. **Label Strategy**: Use consistent labeling strategy
4. **Monitoring**: Monitor network policy violations
5. **Testing**: Test policies in development environments

## Common Patterns

### Database Access
- Restrict database access to specific application pods
- Use namespace selectors for multi-tier applications

### API Access
- Control API server access
- Restrict external API calls

### Monitoring Access
- Allow monitoring tools to access pods
- Control metrics collection
""",
                "url": "https://kubernetes.io/docs/concepts/services-networking/network-policies/",
                "sections": ["Key Features", "Configuration", "Best Practices", "Common Patterns"],
                "metadata": {
                    "type": "network_policy",
                    "version": "1.21",
                    "category": "networking"
                }
            }
        ]
    
    def _get_v1_22_content(self) -> List[Dict[str, Any]]:
        """Get static content for Kubernetes 1.22 from extracted docs"""
        try:
            import json
            import os
            
            # Load extracted content for 1.22
            content_file = "extracted_docs/1.22_static_content.json"
            if os.path.exists(content_file):
                with open(content_file, 'r', encoding='utf-8') as f:
                    extracted_content = json.load(f)
                
                # Convert to our format
                static_content = []
                for doc in extracted_content:
                    static_content.append({
                        "title": doc["title"],
                        "content": doc["content"],
                        "url": doc["url"],
                        "version": doc["version"],
                        "sections": doc["sections"],
                        "metadata": doc["metadata"]
                    })
                
                return static_content
            else:
                print(f"Warning: {content_file} not found, using fallback content")
                return self._get_v1_22_fallback_content()
                
        except Exception as e:
            print(f"Error loading 1.22 content: {e}")
            return self._get_v1_22_fallback_content()
    
    def _get_v1_23_content(self) -> List[Dict[str, Any]]:
        """Get static content for Kubernetes 1.23 from extracted docs"""
        try:
            import json
            import os
            
            # Load extracted content for 1.23
            content_file = "extracted_docs/1.23_static_content.json"
            if os.path.exists(content_file):
                with open(content_file, 'r', encoding='utf-8') as f:
                    extracted_content = json.load(f)
                
                # Convert to our format
                static_content = []
                for doc in extracted_content:
                    static_content.append({
                        "title": doc["title"],
                        "content": doc["content"],
                        "url": doc["url"],
                        "version": doc["version"],
                        "sections": doc["sections"],
                        "metadata": doc["metadata"]
                    })
                
                return static_content
            else:
                print(f"Warning: {content_file} not found, using fallback content")
                return self._get_v1_23_fallback_content()
                
        except Exception as e:
            print(f"Error loading 1.23 content: {e}")
            return self._get_v1_23_fallback_content()
    
    def _get_v1_22_fallback_content(self) -> List[Dict[str, Any]]:
        """Fallback content for Kubernetes 1.22"""
        return [
            {
                "title": "Pod Security Standards (PSS) Alpha - Kubernetes 1.22",
                "content": """
# Pod Security Standards (PSS) Alpha - Kubernetes 1.22

Kubernetes 1.22 introduces Pod Security Standards (PSS) in Alpha, marking the transition from PodSecurityPolicy to a more standardized approach.

## Key Changes in 1.22

### Pod Security Standards Introduction
- New standardized security levels: privileged, baseline, restricted
- Alpha implementation of Pod Security Admission controller
- Gradual migration path from PodSecurityPolicy

### Security Levels

#### Privileged Level
- Unrestricted policy, provides the widest range of permissions
- Allows known privilege escalations
- Suitable for system and infrastructure workloads

#### Baseline Level
- Minimally restrictive policy
- Prevents known privilege escalations
- Allows the default (minimally specified) Pod configuration

#### Restricted Level
- Heavily restricted policy
- Follows current Pod hardening best practices
- Requires explicit configuration for most security-sensitive fields

## Migration from PSP

1. **Assessment**: Evaluate current PSP usage
2. **Mapping**: Map PSP rules to PSS levels
3. **Testing**: Test workloads with PSS enforcement
4. **Gradual Rollout**: Implement PSS in audit/warn mode first

## Example PSS Configuration

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: my-app
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/enforce-version: v1.22
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.22
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.22
```

## Best Practices

1. **Start with Baseline**: Begin with baseline level for most workloads
2. **Audit First**: Use audit mode to identify violations
3. **Gradual Enforcement**: Move to enforce mode after testing
4. **Monitor**: Watch for policy violations and adjust as needed
""",
                "url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                "sections": ["PSS Introduction", "Security Levels", "Migration", "Best Practices"],
                "metadata": {
                    "type": "security_policy",
                    "version": "1.22",
                    "policy_type": "PodSecurityStandardsAlpha",
                    "category": "security"
                }
            }
        ]
    
    def _get_v1_23_fallback_content(self) -> List[Dict[str, Any]]:
        """Fallback content for Kubernetes 1.23"""
        return [
            {
                "title": "Pod Security Standards (PSS) Alpha - Kubernetes 1.23",
                "content": """
# Pod Security Standards (PSS) Alpha - Kubernetes 1.23

Kubernetes 1.23 continues the Alpha implementation of Pod Security Standards with improvements and refinements.

## Enhancements in 1.23

### Improved PSS Implementation
- Enhanced validation and error reporting
- Better integration with admission controllers
- Improved namespace label handling

### Security Level Refinements
- Updated baseline and restricted level requirements
- Better handling of edge cases
- Improved compatibility with common workloads

### Migration Tools
- Enhanced migration utilities
- Better documentation and examples
- Improved error messages for violations

## PSS Levels in 1.23

### Privileged Level
- Unrestricted policy
- Allows all known privilege escalations
- Suitable for trusted system workloads

### Baseline Level
- Minimally restrictive
- Prevents known privilege escalations
- Allows default Pod configurations

### Restricted Level
- Heavily restricted
- Follows Pod hardening best practices
- Requires explicit security configurations

## Example Configuration

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production-apps
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.23
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.23
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.23
```

## Migration Strategy

1. **Inventory**: Document all current PSP usage
2. **Test**: Validate workloads with PSS in audit mode
3. **Plan**: Create migration timeline
4. **Execute**: Implement PSS enforcement gradually
5. **Monitor**: Track violations and adjust policies

## Best Practices

1. **Use Audit Mode**: Start with audit to identify issues
2. **Gradual Rollout**: Implement enforcement incrementally
3. **Monitor Violations**: Track and address policy violations
4. **Document Exemptions**: Clearly document any necessary exemptions
""",
                "url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                "sections": ["PSS Enhancements", "Security Levels", "Migration", "Best Practices"],
                "metadata": {
                    "type": "security_policy",
                    "version": "1.23",
                    "policy_type": "PodSecurityStandardsAlpha",
                    "category": "security"
                }
            }
        ]
    
    def generate_content_for_version(self, version: str) -> List[ParsedContent]:
        """Generate static content for a specific version"""
        if version not in self.content_templates:
            return []
        
        content_list = []
        templates = self.content_templates[version]
        
        for template in templates:
            content = ParsedContent(
                title=template["title"],
                content=template["content"],
                url=template["url"],
                version=version,
                sections=template["sections"],
                metadata=template["metadata"]
            )
            content_list.append(content)
        
        return content_list
    
    def get_supported_versions(self) -> List[str]:
        """Get list of versions with static content"""
        return list(self.content_templates.keys())
    
    def save_static_content(self, version: str, output_file: str) -> None:
        """Save static content to a file"""
        content_list = self.generate_content_for_version(version)
        
        # Convert to serializable format
        serializable_content = []
        for content in content_list:
            serializable_content.append(asdict(content))
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(serializable_content, f, indent=2, ensure_ascii=False)
        
        print(f"Saved {len(content_list)} static content items for version {version} to {output_file}")


# Global instance
static_content_generator = StaticContentGenerator() 