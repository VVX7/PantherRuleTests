"""
Kubernetes Detection Rules

This package contains detection rules for Kubernetes security events.

Available Detections:
- cluster_admin_binding: Detects creation of ClusterRoleBindings granting cluster-admin privileges
"""

__all__ = ['cluster_admin_binding']
