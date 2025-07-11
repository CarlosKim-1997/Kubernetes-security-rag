# Conditional imports for different execution contexts
try:
    # When running as module
    from .schema import SecurityField, PolicyLevel
except ImportError:
    # When running directly
    from schema import SecurityField, PolicyLevel
from typing import List


def get_security_fields() -> List[SecurityField]:
    """Get initial security fields from Kubernetes Pod Security Standards"""
    
    return [
        SecurityField(
            field_name="runAsNonRoot",
            field_path="spec.securityContext.runAsNonRoot",
            description="Controls whether the container must run as a non-root user. When set to true, the container must run as a non-root user. This is a critical security control that prevents privilege escalation attacks.",
            policy_level=PolicyLevel.BASELINE,
            version_added="1.0",
            default_value="false",
            acceptable_values=["true", "false"],
            security_impact="Running containers as non-root users significantly reduces the attack surface. If a container running as root is compromised, the attacker gains full access to the host system. Non-root containers limit the potential damage from container escapes.",
            yaml_example="""
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
  containers:
  - name: app
    image: nginx:alpine
""",
            common_pitfalls=[
                "Setting runAsNonRoot: true without specifying runAsUser",
                "Using UID 0 (root) even when runAsNonRoot is true",
                "Not ensuring the container image supports non-root execution",
                "Forgetting to set appropriate file permissions for non-root user"
            ],
            remediation_steps=[
                "Set runAsNonRoot: true in pod securityContext",
                "Specify a non-zero runAsUser (e.g., 1000)",
                "Ensure container image supports non-root execution",
                "Set appropriate file permissions for the non-root user",
                "Test the application works correctly as non-root"
            ],
            related_fields=["runAsUser", "runAsGroup", "fsGroup", "supplementalGroups"],
            cve_references=["CVE-2019-5736", "CVE-2021-30465"],
            source_document="Kubernetes Pod Security Standards"
        ),
        
        SecurityField(
            field_name="allowPrivilegeEscalation",
            field_path="spec.securityContext.allowPrivilegeEscalation",
            description="Controls whether a process can gain more privileges than its parent process. This includes setting the no_new_privs flag on Linux and is a critical security control.",
            policy_level=PolicyLevel.BASELINE,
            version_added="1.8",
            default_value="true",
            acceptable_values=["false", "true"],
            security_impact="When set to false, prevents privilege escalation attacks where a process can gain additional privileges through mechanisms like setuid binaries. This is essential for defense in depth.",
            yaml_example="""
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    allowPrivilegeEscalation: false
  containers:
  - name: app
    image: nginx:alpine
""",
            common_pitfalls=[
                "Not setting allowPrivilegeEscalation to false",
                "Confusing with privileged containers",
                "Not understanding the difference from runAsNonRoot"
            ],
            remediation_steps=[
                "Set allowPrivilegeEscalation: false in pod securityContext",
                "Test that the application doesn't require privilege escalation",
                "Ensure no setuid binaries are needed"
            ],
            related_fields=["privileged", "runAsNonRoot", "capabilities"],
            cve_references=["CVE-2019-5736"],
            source_document="Kubernetes Pod Security Standards"
        ),
        
        SecurityField(
            field_name="privileged",
            field_path="spec.containers[].securityContext.privileged",
            description="Controls whether the container runs in privileged mode. Privileged containers have access to all capabilities and host devices, which is extremely dangerous.",
            policy_level=PolicyLevel.PRIVILEGED,
            version_added="1.0",
            default_value="false",
            acceptable_values=["false", "true"],
            security_impact="Privileged containers have access to all Linux capabilities and host devices. This essentially gives the container root access to the host system, making it a major security risk.",
            yaml_example="""
# ❌ DANGEROUS - Don't do this in production
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: app
    image: nginx:alpine
    securityContext:
      privileged: true  # This is dangerous!
""",
            common_pitfalls=[
                "Using privileged: true for debugging and forgetting to remove it",
                "Thinking privileged containers are needed for system access",
                "Using privileged mode instead of specific capabilities"
            ],
            remediation_steps=[
                "Remove privileged: true from all containers",
                "Use specific capabilities instead of privileged mode",
                "Implement proper security monitoring",
                "Use security contexts and RBAC for access control"
            ],
            related_fields=["capabilities", "allowPrivilegeEscalation", "hostPID", "hostIPC"],
            cve_references=["CVE-2019-5736", "CVE-2021-30465"],
            source_document="Kubernetes Pod Security Standards"
        ),
        
        SecurityField(
            field_name="readOnlyRootFilesystem",
            field_path="spec.containers[].securityContext.readOnlyRootFilesystem",
            description="Controls whether the container's root filesystem is read-only. This prevents attackers from writing to the filesystem and installing persistence mechanisms.",
            policy_level=PolicyLevel.RESTRICTED,
            version_added="1.0",
            default_value="false",
            acceptable_values=["true", "false"],
            security_impact="A read-only root filesystem prevents attackers from writing malicious files, installing backdoors, or modifying system files. This is a key defense against container escape and persistence attacks.",
            yaml_example="""
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
  - name: app
    image: nginx:alpine
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: tmp-volume
      mountPath: /tmp
    - name: logs-volume
      mountPath: /var/log
  volumes:
  - name: tmp-volume
    emptyDir: {}
  - name: logs-volume
    emptyDir: {}
""",
            common_pitfalls=[
                "Setting readOnlyRootFilesystem: true without providing writable volumes",
                "Not understanding which directories need write access",
                "Forgetting to mount /tmp, /var/log, or other writable directories"
            ],
            remediation_steps=[
                "Set readOnlyRootFilesystem: true in container securityContext",
                "Identify directories that need write access",
                "Mount writable volumes for necessary directories",
                "Test application functionality with read-only root"
            ],
            related_fields=["volumeMounts", "volumes", "emptyDir"],
            cve_references=["CVE-2019-5736"],
            source_document="Kubernetes Pod Security Standards"
        ),
        
        SecurityField(
            field_name="runAsUser",
            field_path="spec.securityContext.runAsUser",
            description="Specifies the user ID to run the container process. Should be a non-zero value for security. Works in conjunction with runAsNonRoot.",
            policy_level=PolicyLevel.BASELINE,
            version_added="1.0",
            default_value="0",
            acceptable_values=["Any non-zero integer"],
            security_impact="Running as a specific non-root user limits the potential damage from container compromise. It prevents the container from accessing sensitive host files and reduces privilege escalation opportunities.",
            yaml_example="""
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
  containers:
  - name: app
    image: nginx:alpine
""",
            common_pitfalls=[
                "Using UID 0 (root) even when runAsNonRoot is true",
                "Not coordinating runAsUser with file permissions",
                "Using the same UID across different applications"
            ],
            remediation_steps=[
                "Set runAsUser to a non-zero value (e.g., 1000)",
                "Ensure file permissions match the user ID",
                "Use unique UIDs for different applications",
                "Test application functionality with the new user"
            ],
            related_fields=["runAsNonRoot", "runAsGroup", "fsGroup"],
            cve_references=["CVE-2019-5736"],
            source_document="Kubernetes Pod Security Standards"
        ),
        
        SecurityField(
            field_name="capabilities",
            field_path="spec.containers[].securityContext.capabilities",
            description="Controls Linux capabilities for the container. Should drop all capabilities and add only those specifically required.",
            policy_level=PolicyLevel.RESTRICTED,
            version_added="1.0",
            default_value="All capabilities",
            acceptable_values=["Specific capability names"],
            security_impact="Linux capabilities provide fine-grained control over what privileged operations a container can perform. Dropping unnecessary capabilities reduces the attack surface and follows the principle of least privilege.",
            yaml_example="""
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
  - name: app
    image: nginx:alpine
    securityContext:
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE  # Only if needed for port < 1024
""",
            common_pitfalls=[
                "Not dropping ALL capabilities by default",
                "Adding capabilities without understanding their security implications",
                "Using privileged mode instead of specific capabilities"
            ],
            remediation_steps=[
                "Drop ALL capabilities by default",
                "Add only specifically required capabilities",
                "Document why each capability is needed",
                "Regularly review and remove unnecessary capabilities"
            ],
            related_fields=["privileged", "allowPrivilegeEscalation"],
            cve_references=["CVE-2019-5736"],
            source_document="Kubernetes Pod Security Standards"
        ),
        
        SecurityField(
            field_name="hostPID",
            field_path="spec.hostPID",
            description="Controls whether the pod can see all processes on the host. This is a significant security risk as it can lead to information disclosure and privilege escalation.",
            policy_level=PolicyLevel.PRIVILEGED,
            version_added="1.0",
            default_value="false",
            acceptable_values=["false", "true"],
            security_impact="When set to true, the container can see all processes on the host, including those from other containers and the host system. This can lead to information disclosure and potential privilege escalation attacks.",
            yaml_example="""
# ❌ DANGEROUS - Don't do this in production
apiVersion: v1
kind: Pod
metadata:
  name: dangerous-pod
spec:
  hostPID: true  # This is dangerous!
  containers:
  - name: app
    image: nginx:alpine
""",
            common_pitfalls=[
                "Using hostPID for debugging and forgetting to remove it",
                "Thinking hostPID is needed for process monitoring",
                "Not understanding the security implications"
            ],
            remediation_steps=[
                "Remove hostPID: true from all pods",
                "Use Kubernetes-native monitoring tools instead",
                "Implement proper logging and monitoring",
                "Use security contexts for access control"
            ],
            related_fields=["hostIPC", "hostNetwork", "privileged"],
            cve_references=["CVE-2019-5736"],
            source_document="Kubernetes Pod Security Standards"
        ),
        
        SecurityField(
            field_name="hostNetwork",
            field_path="spec.hostNetwork",
            description="Controls whether the pod uses the host's network namespace. This gives the pod access to all network interfaces on the host, which is a security risk.",
            policy_level=PolicyLevel.PRIVILEGED,
            version_added="1.0",
            default_value="false",
            acceptable_values=["false", "true"],
            security_impact="When set to true, the pod can access all network interfaces on the host, potentially including internal networks and services. This can lead to network-based attacks and information disclosure.",
            yaml_example="""
# ❌ DANGEROUS - Don't do this in production
apiVersion: v1
kind: Pod
metadata:
  name: dangerous-pod
spec:
  hostNetwork: true  # This is dangerous!
  containers:
  - name: app
    image: nginx:alpine
""",
            common_pitfalls=[
                "Using hostNetwork for performance optimization",
                "Thinking hostNetwork is needed for network access",
                "Not understanding the security implications"
            ],
            remediation_steps=[
                "Remove hostNetwork: true from all pods",
                "Use Kubernetes Services for network access",
                "Configure proper network policies",
                "Use ingress controllers for external access"
            ],
            related_fields=["hostPID", "hostIPC", "networkPolicy"],
            cve_references=["CVE-2019-5736"],
            source_document="Kubernetes Pod Security Standards"
        ),
        
        SecurityField(
            field_name="seccompProfile",
            field_path="spec.securityContext.seccompProfile",
            description="Controls the seccomp profile applied to the container. Seccomp is a Linux kernel security feature that acts as a sandbox for system calls.",
            policy_level=PolicyLevel.RESTRICTED,
            version_added="1.19",
            default_value="Unconfined",
            acceptable_values=["RuntimeDefault", "Unconfined", "Localhost"],
            security_impact="Seccomp profiles restrict which system calls a container can make, significantly reducing the attack surface. The RuntimeDefault profile blocks dangerous system calls that could be used for privilege escalation.",
            yaml_example="""
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: nginx:alpine
""",
            common_pitfalls=[
                "Not setting seccompProfile to RuntimeDefault",
                "Using Unconfined profile in production",
                "Not testing application compatibility with seccomp"
            ],
            remediation_steps=[
                "Set seccompProfile.type to RuntimeDefault",
                "Test application functionality with seccomp enabled",
                "Create custom profiles only if necessary",
                "Monitor for seccomp violations"
            ],
            related_fields=["apparmorProfile", "capabilities"],
            cve_references=["CVE-2019-5736"],
            source_document="Kubernetes Pod Security Standards"
        ),
        
        SecurityField(
            field_name="apparmorProfile",
            field_path="spec.securityContext.apparmorProfile",
            description="Controls the AppArmor profile applied to the container. AppArmor is a Linux kernel security module that provides mandatory access control.",
            policy_level=PolicyLevel.RESTRICTED,
            version_added="1.4",
            default_value="Unconfined",
            acceptable_values=["RuntimeDefault", "Unconfined", "Localhost"],
            security_impact="AppArmor profiles restrict file access, network access, and other system resources. This provides an additional layer of security beyond standard Linux permissions and capabilities.",
            yaml_example="""
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    apparmorProfile: RuntimeDefault
  containers:
  - name: app
    image: nginx:alpine
""",
            common_pitfalls=[
                "Not setting apparmorProfile to RuntimeDefault",
                "Using Unconfined profile in production",
                "Not testing application compatibility with AppArmor"
            ],
            remediation_steps=[
                "Set apparmorProfile to RuntimeDefault",
                "Test application functionality with AppArmor enabled",
                "Create custom profiles only if necessary",
                "Monitor for AppArmor violations"
            ],
            related_fields=["seccompProfile", "capabilities"],
            cve_references=["CVE-2019-5736"],
            source_document="Kubernetes Pod Security Standards"
        )
    ] 