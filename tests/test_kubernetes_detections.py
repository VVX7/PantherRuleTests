# tests/test_kubernetes_detections.py

import pytest
from tests.test_framework import DetectionTestFramework


class TestClusterAdminDetection:
    """
    Test suite for Kubernetes cluster-admin binding detection logic.

    Coverage:
    - Malicious cluster-admin creation (TP)
    - Legitimate system bindings (TP - match but context differs)
    - Non-admin bindings (TN)
    - Edge cases and malformed events (TN)
    """

    @pytest.fixture
    def detection(self):
        """Load detection module"""
        from detections.kubernetes import cluster_admin_binding
        return cluster_admin_binding

    @pytest.fixture
    def fixtures(self):
        """Load test fixtures"""
        return DetectionTestFramework.load_test_fixtures('kubernetes_cluster_admin_events')

    def test_malicious_cluster_admin_creation_matches(self, detection, fixtures):
        """
        Test: Malicious cluster-admin binding should match

        Scenario: External user creates cluster-admin binding
        Expected: rule() returns True
        """
        DetectionTestFramework.assert_detection_matches(
            detection,
            fixtures['malicious_cluster_admin_creation']
        )

    def test_system_service_account_binding_matches(self, detection, fixtures):
        """
        Test: System service account cluster-admin binding should match

        Scenario: system:serviceaccount creates binding (legitimate but monitored)
        Expected: rule() returns True
        Note: Severity may differ but logic should still match
        """
        DetectionTestFramework.assert_detection_matches(
            detection,
            fixtures['legitimate_system_binding']
        )

    def test_non_cluster_admin_binding_does_not_match(self, detection, fixtures):
        """
        Test: Non-cluster-admin role binding should NOT match

        Scenario: Creating binding with 'view' role (not cluster-admin)
        Expected: rule() returns False
        """
        DetectionTestFramework.assert_detection_does_not_match(
            detection,
            fixtures['benign_view_binding'],
            reason="View role is not cluster-admin privilege escalation"
        )

    def test_update_verb_does_not_match(self, detection, fixtures):
        """
        Test: Update operations should NOT match

        Scenario: Updating existing cluster-admin binding (not creation)
        Expected: rule() returns False
        """
        event = fixtures['malicious_cluster_admin_creation'].copy()
        event['verb'] = 'update'

        DetectionTestFramework.assert_detection_does_not_match(
            detection,
            event,
            reason="Only creation events should trigger, not updates"
        )

    def test_delete_verb_does_not_match(self, detection, fixtures):
        """
        Test: Delete operations should NOT match

        Scenario: Deleting cluster-admin binding
        Expected: rule() returns False
        """
        event = fixtures['malicious_cluster_admin_creation'].copy()
        event['verb'] = 'delete'

        DetectionTestFramework.assert_detection_does_not_match(
            detection,
            event,
            reason="Deleting bindings is not a threat"
        )

    def test_rolebinding_does_not_match(self, detection, fixtures):
        """
        Test: RoleBinding (namespace-scoped) should NOT match

        Scenario: Creating RoleBinding instead of ClusterRoleBinding
        Expected: rule() returns False
        Note: RoleBindings are namespace-scoped, less critical
        """
        event = fixtures['malicious_cluster_admin_creation'].copy()
        event['objectRef']['resource'] = 'rolebindings'

        DetectionTestFramework.assert_detection_does_not_match(
            detection,
            event,
            reason="RoleBindings are namespace-scoped, not cluster-wide"
        )

    def test_different_api_group_does_not_match(self, detection, fixtures):
        """
        Test: Non-RBAC resources should NOT match

        Scenario: Creating resource in different API group
        Expected: rule() returns False
        """
        event = fixtures['malicious_cluster_admin_creation'].copy()
        event['objectRef']['apiGroup'] = 'apps/v1'

        DetectionTestFramework.assert_detection_does_not_match(
            detection,
            event,
            reason="Only RBAC API group events are relevant"
        )

    def test_missing_role_ref_does_not_match(self, detection, fixtures):
        """
        Test: Event without roleRef should NOT match

        Scenario: Malformed event missing roleRef
        Expected: rule() returns False (graceful handling)
        """
        event = fixtures['malicious_cluster_admin_creation'].copy()
        del event['requestObject']['roleRef']

        DetectionTestFramework.assert_detection_does_not_match(
            detection,
            event,
            reason="Malformed event should not crash or match"
        )

    def test_edit_role_does_not_match(self, detection, fixtures):
        """
        Test: 'edit' role binding should NOT match

        Scenario: Binding grants 'edit' role (not cluster-admin)
        Expected: rule() returns False
        """
        event = fixtures['malicious_cluster_admin_creation'].copy()
        event['requestObject']['roleRef']['name'] = 'edit'

        DetectionTestFramework.assert_detection_does_not_match(
            detection,
            event,
            reason="Edit role is not cluster-admin"
        )

    def test_admin_role_does_not_match(self, detection, fixtures):
        """
        Test: 'admin' role binding should NOT match

        Scenario: Binding grants 'admin' role (namespace-admin, not cluster-admin)
        Expected: rule() returns False
        """
        event = fixtures['malicious_cluster_admin_creation'].copy()
        event['requestObject']['roleRef']['name'] = 'admin'

        DetectionTestFramework.assert_detection_does_not_match(
            detection,
            event,
            reason="'admin' role is different from 'cluster-admin'"
        )

    def test_batch_validation(self, detection, fixtures):
        """
        Test: Run comprehensive test suite with all scenarios

        Validates overall detection coverage and logic correctness
        """
        test_cases = {
            'malicious_creation': {
                'event': fixtures['malicious_cluster_admin_creation'],
                'should_match': True
            },
            'system_binding': {
                'event': fixtures['legitimate_system_binding'],
                'should_match': True
            },
            'benign_view_binding': {
                'event': fixtures['benign_view_binding'],
                'should_match': False
            }
        }

        results = DetectionTestFramework.run_test_suite(
            detection,
            test_cases,
            verbose=True
        )

        # Assert all tests passed
        assert results['failed'] == 0, (
            f"Test failures detected:\n" +
            "\n".join(f"  - {err['test']}: {err['error']}" for err in results['errors'])
        )

        # Assert we have good coverage
        assert results['coverage']['true_positive_tests'] >= 2, \
            "Not enough true positive test cases"
        assert results['coverage']['true_negative_tests'] >= 1, \
            "Not enough true negative test cases"

    def test_detection_structure_validation(self, detection):
        """
        Test: Validate detection has proper Panther structure

        Checks for required and recommended functions
        """
        validation = DetectionTestFramework.validate_detection_structure(detection)

        if validation['has_critical_issues']:
            pytest.fail(
                "Detection has critical structural issues:\n" +
                "\n".join(f"  - {issue}" for issue in validation['issues']
                         if issue.startswith('CRITICAL'))
            )

        # Print warnings but don't fail
        warnings = [i for i in validation['issues'] if i.startswith('WARNING')]
        if warnings:
            print("\nDetection structure warnings:")
            for warning in warnings:
                print(f"  - {warning}")

    def test_event_variations(self, detection, fixtures):
        """
        Test: Various subject types should all match

        Tests that detection works regardless of subject kind
        (User, ServiceAccount, Group)
        """
        base_event = fixtures['malicious_cluster_admin_creation']

        variations = [
            # ServiceAccount subject
            {
                'requestObject': {
                    'roleRef': {'name': 'cluster-admin', 'kind': 'ClusterRole'},
                    'subjects': [
                        {'kind': 'ServiceAccount', 'name': 'malicious-sa', 'namespace': 'default'}
                    ]
                }
            },
            # Group subject
            {
                'requestObject': {
                    'roleRef': {'name': 'cluster-admin', 'kind': 'ClusterRole'},
                    'subjects': [
                        {'kind': 'Group', 'name': 'system:unauthenticated'}
                    ]
                }
            },
            # Multiple subjects
            {
                'requestObject': {
                    'roleRef': {'name': 'cluster-admin', 'kind': 'ClusterRole'},
                    'subjects': [
                        {'kind': 'User', 'name': 'user1@example.com'},
                        {'kind': 'User', 'name': 'user2@example.com'}
                    ]
                }
            }
        ]

        results = DetectionTestFramework.test_with_variations(
            detection,
            base_event,
            variations,
            should_match=True
        )

        assert results['failed'] == 0, (
            f"Some subject variations failed:\n" +
            "\n".join(
                f"  - Variation {d['variation_index']}: {d['error'] or 'unexpected match result'}"
                for d in results['details'] if not d['success']
            )
        )


class TestClusterAdminDetectionEdgeCases:
    """
    Additional edge case testing for robustness

    Tests unusual inputs, missing fields, and malformed events
    """

    @pytest.fixture
    def detection(self):
        from detections.kubernetes import cluster_admin_binding
        return cluster_admin_binding

    def test_empty_event(self, detection):
        """
        Test: Empty event should not crash

        Expected: rule() returns False gracefully
        """
        DetectionTestFramework.assert_detection_does_not_match(
            detection,
            {},
            reason="Empty event should not crash or match"
        )

    def test_missing_object_ref(self, detection):
        """
        Test: Event without objectRef should not crash

        Expected: rule() returns False gracefully
        """
        event = {'verb': 'create'}

        DetectionTestFramework.assert_detection_does_not_match(
            detection,
            event,
            reason="Missing objectRef should be handled gracefully"
        )

    def test_missing_request_object(self, detection):
        """
        Test: Event without requestObject should not crash

        Expected: rule() returns False gracefully
        """
        event = {
            'verb': 'create',
            'objectRef': {
                'apiGroup': 'rbac.authorization.k8s.io',
                'resource': 'clusterrolebindings'
            }
        }

        DetectionTestFramework.assert_detection_does_not_match(
            detection,
            event,
            reason="Missing requestObject should be handled gracefully"
        )

    def test_null_values(self, detection):
        """
        Test: Event with null values should not crash

        Expected: rule() returns False gracefully
        """
        event = {
            'verb': 'create',
            'objectRef': None,
            'requestObject': None
        }

        DetectionTestFramework.assert_detection_does_not_match(
            detection,
            event,
            reason="Null values should be handled gracefully"
        )

    def test_cluster_admin_substring_does_not_match(self, detection):
        """
        Test: Role name containing 'cluster-admin' as substring should NOT match

        Expected: rule() returns False (exact match required)
        """
        event = {
            'verb': 'create',
            'objectRef': {
                'apiGroup': 'rbac.authorization.k8s.io',
                'resource': 'clusterrolebindings',
                'name': 'test-binding'
            },
            'requestObject': {
                'roleRef': {
                    'name': 'not-cluster-admin',  # Contains 'cluster-admin' as substring
                    'kind': 'ClusterRole'
                }
            }
        }

        DetectionTestFramework.assert_detection_does_not_match(
            detection,
            event,
            reason="Should require exact match, not substring"
        )
