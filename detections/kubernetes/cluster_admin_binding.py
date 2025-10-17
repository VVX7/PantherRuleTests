"""
Kubernetes Cluster-Admin RoleBinding Creation

Detects creation of ClusterRoleBindings granting cluster-admin privileges,
which provides unrestricted access to the entire Kubernetes cluster.

MITRE ATT&CK:
    - T1098 (Account Manipulation)
    - T1078 (Valid Accounts)
Severity:
    - CRITICAL (for external users)
    - MEDIUM (for system accounts)
"""

from panther_base_helpers import deep_get


def rule(event):
    """
    Detection logic for cluster-admin binding creation

    Triggers on:
    - ClusterRoleBinding creation events
    - RoleRef pointing to 'cluster-admin' ClusterRole

    Args:
        event: Kubernetes audit log event

    Returns:
        bool: True if detection should fire
    """
    # Check if this is a ClusterRoleBinding creation
    if event.get('verb') != 'create':
        return False

    # Safely get objectRef (handle None/missing values)
    object_ref = event.get('objectRef')
    if not isinstance(object_ref, dict):
        return False

    if object_ref.get('resource') != 'clusterrolebindings':
        return False

    if object_ref.get('apiGroup') != 'rbac.authorization.k8s.io':
        return False

    # Safely get requestObject (handle None/missing values)
    request_object = event.get('requestObject')
    if not isinstance(request_object, dict):
        return False

    role_ref = request_object.get('roleRef')
    if not isinstance(role_ref, dict):
        return False

    if role_ref.get('name') != 'cluster-admin':
        return False

    # Detection fires - this is a cluster-admin binding creation
    return True


def title(event):
    """
    Generate alert title with key context

    Args:
        event: Kubernetes audit log event

    Returns:
        str: Human-readable alert title
    """
    user = deep_get(event, 'user', 'username', default='unknown')
    binding_name = deep_get(event, 'objectRef', 'name', default='unknown')

    # Extract subject (who is being granted admin)
    subjects = deep_get(event, 'requestObject', 'subjects', default=[])
    subject_names = [s.get('name', 'unknown') for s in subjects[:3]]  # First 3
    subject_str = ', '.join(subject_names) if subject_names else 'unknown'

    return (
        f"Kubernetes Cluster-Admin Binding Created: '{binding_name}' "
        f"by {user} for {subject_str}"
    )


def severity(event):
    """
    Dynamic severity based on context

    System service accounts receive MEDIUM severity, while external
    or user-initiated bindings receive CRITICAL/HIGH severity.

    Args:
        event: Kubernetes audit log event

    Returns:
        str: Alert severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    """
    user = deep_get(event, 'user', 'username', default='')

    # System service accounts = expected behavior (lower severity)
    if user.startswith('system:serviceaccount:kube-system:'):
        return 'MEDIUM'

    # System components (controller-manager, scheduler, etc.)
    if user.startswith('system:'):
        return 'MEDIUM'

    # External/human users creating cluster-admin bindings = critical
    subjects = deep_get(event, 'requestObject', 'subjects', default=[])
    for subject in subjects:
        subject_name = subject.get('name', '')

        # External email domains (not internal)
        if '@' in subject_name and not subject_name.endswith('@cloudvault.com'):
            return 'CRITICAL'

        # ServiceAccount in suspicious namespaces
        if subject.get('kind') == 'ServiceAccount':
            namespace = subject.get('namespace', '')
            if namespace not in ['kube-system', 'kube-public', 'kube-node-lease']:
                return 'HIGH'

    # Default: high severity for cluster-admin grants
    return 'HIGH'


def alert_context(event):
    """
    Provide rich context for investigation and deduplication

    Args:
        event: Kubernetes audit log event

    Returns:
        dict: Structured context data for alert enrichment
    """
    user = deep_get(event, 'user', 'username', default='unknown')
    user_groups = deep_get(event, 'user', 'groups', default=[])
    source_ips = event.get('sourceIPs', [])
    user_agent = event.get('userAgent', 'unknown')

    request_object = event.get('requestObject', {})
    subjects = request_object.get('subjects', [])
    role_ref = request_object.get('roleRef', {})

    binding_name = deep_get(event, 'objectRef', 'name', default='unknown')

    return {
        # Who performed the action
        'actor_user': user,
        'actor_groups': user_groups,
        'actor_source_ips': source_ips,
        'actor_user_agent': user_agent,

        # What was created
        'binding_name': binding_name,
        'role_granted': role_ref.get('name'),
        'role_kind': role_ref.get('kind'),

        # Who received privileges
        'subjects': [
            {
                'kind': s.get('kind'),
                'name': s.get('name'),
                'namespace': s.get('namespace', 'cluster-scoped')
            }
            for s in subjects
        ],

        # Investigation links
        'kubectl_command': (
            f"kubectl get clusterrolebinding {binding_name} -o yaml"
        ),

        # Deduplication key
        'dedup_key': f"{user}:{binding_name}"
    }


def dedup_seconds(event):
    """
    Deduplication window (avoid duplicate alerts)

    Args:
        event: Kubernetes audit log event

    Returns:
        int: Seconds to deduplicate on alert_context dedup_key
    """
    return 3600  # 1 hour


def description(event):
    """
    Detailed description for runbooks/documentation

    Args:
        event: Kubernetes audit log event

    Returns:
        str: Investigation guidance and context
    """
    return """
A ClusterRoleBinding granting cluster-admin privileges was created.

The cluster-admin role provides unrestricted access to all Kubernetes
resources and is the highest privilege level. This can be legitimate
for automation or administrative purposes, but is also a common
persistence mechanism for attackers.

INVESTIGATION STEPS:
1. Verify the user creating the binding is authorized
2. Check if the subject (user/serviceaccount receiving admin) is legitimate
3. Review recent API activity from the source IP
4. Check for other RBAC modifications from this user
5. Validate the binding is still needed (not left over from troubleshooting)

RESPONSE ACTIONS:
- If unauthorized: Delete the binding immediately
  kubectl delete clusterrolebinding <binding-name>
- If subject is compromised: Delete subject and binding
- Review all cluster-admin bindings for other suspicious grants
  kubectl get clusterrolebindings -o wide

FALSE POSITIVES:
- System controller-manager creating system bindings (filtered to MEDIUM severity)
- IaC tools (Terraform, Helm) during deployments
- Legitimate admin onboarding

MITRE ATT&CK:
- T1098: Account Manipulation - Adding privileges to accounts
- T1078: Valid Accounts - Using legitimate credentials with elevated access
"""


def reference(event):
    """
    External references for context

    Args:
        event: Kubernetes audit log event

    Returns:
        str: URLs to relevant documentation
    """
    return (
        "https://kubernetes.io/docs/reference/access-authn-authz/rbac/\n"
        "https://attack.mitre.org/techniques/T1098/\n"
        "https://microsoft.github.io/Threat-Matrix-for-Kubernetes/"
    )
