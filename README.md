# Panther Detection Testing Framework

A simple testing framework for Panther detection rules.

## Directory Structure

```
.
├── detections/ 
│   └── kubernetes/
│       ├── __init__.py
│       └── cluster_admin_binding.py
├── tests/                          # Test framework and test cases
│   ├── fixtures/                   
│   │   └── kubernetes_cluster_admin_events.json
│   ├── test_framework.py
│   └── test_kubernetes_detections.py
├── panther_base_helpers.py         # Mock Panther helpers for local testing
└── README.md
```

## Features

- **Logic-focused testing**: Tests only rule matching logic, not dynamic attributes like severity
- **Comprehensive fixtures**: Realistic test events for multiple scenarios
- **Edge case coverage**: Tests malformed events, missing fields, and error handling
- **Batch testing**: Run multiple test cases with coverage metrics
- **CI/CD ready**: Easy integration with pytest and GitHub Actions

## Installation

```bash
# Install dependencies
pip install pytest

# Optional: Install coverage tool
pip install pytest-cov
```

## Running Tests

### Run all tests
```bash
pytest tests/ -v
```

### Run specific test file
```bash
pytest tests/test_kubernetes_detections.py -v
```

### Run specific test
```bash
pytest tests/test_kubernetes_detections.py::TestClusterAdminDetection::test_malicious_cluster_admin_creation_matches -v
```

### Run with coverage report
```bash
pytest tests/ --cov=detections --cov-report=html
```

### Run verbose with output
```bash
pytest tests/ -vv -s
```

## Writing New Detection Rules

### 1. Create detection file

```python
# detections/kubernetes/my_detection.py

def rule(event):
    """
    Detection logic

    Returns:
        bool: True if detection should fire
    """
    # Your logic here
    return True

def title(event):
    """Alert title"""
    return "My Detection Alert"

def severity(event):
    """Dynamic severity"""
    return "HIGH"

def alert_context(event):
    """Investigation context"""
    return {
        'key': 'value'
    }
```

### 2. Create test fixtures

```json
# tests/fixtures/my_detection_events.json
{
  "malicious_event": {
    "field": "value"
  },
  "benign_event": {
    "field": "other_value"
  }
}
```

### 3. Write tests

```python
# tests/test_my_detection.py
import pytest
from tests.test_framework import DetectionTestFramework

class TestMyDetection:
    @pytest.fixture
    def detection(self):
        from detections.kubernetes import my_detection
        return my_detection

    @pytest.fixture
    def fixtures(self):
        return DetectionTestFramework.load_test_fixtures('my_detection_events')

    def test_malicious_event_matches(self, detection, fixtures):
        DetectionTestFramework.assert_detection_matches(
            detection,
            fixtures['malicious_event']
        )

    def test_benign_event_does_not_match(self, detection, fixtures):
        DetectionTestFramework.assert_detection_does_not_match(
            detection,
            fixtures['benign_event'],
            reason="This event is benign"
        )
```

## Example: Kubernetes Cluster-Admin Detection

This detection monitors for creation of ClusterRoleBindings that grant cluster-admin privileges.

### Detection Logic
- Matches on `verb: create`
- Checks resource is `clusterrolebindings`
- Validates roleRef name is `cluster-admin`

### Test Coverage
- Malicious cluster-admin creation (external user)
- System service account bindings (lower severity)
- Non-admin role bindings (should not match)
- Edge cases (wrong verb, missing fields, malformed events)

### Running Tests
```bash
# Run all cluster-admin tests
pytest tests/test_kubernetes_detections.py::TestClusterAdminDetection -v

# Expected output:
# test_malicious_cluster_admin_creation_matches PASSED
# test_system_service_account_binding_matches PASSED
# test_non_cluster_admin_binding_does_not_match PASSED
# test_update_verb_does_not_match PASSED
# ...
```

## CI/CD Integration

### GitHub Actions Example

```yaml
# .github/workflows/test-detections.yml
name: Test Detections

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install pytest pytest-cov

      - name: Run tests
        run: pytest tests/ -v --cov=detections

      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## Troubleshooting

### Test fails with "Detection did not match event"
- Check that all required fields are present in test fixture
- Verify detection logic is correct
- Use `debug=True` to see detailed output

### Import errors
- Ensure `panther_base_helpers.py` is in project root
- Check that detection files have correct import statements

### Fixture not found
- Verify fixture file exists in `tests/fixtures/`
- Check fixture filename matches (without .json extension)

## Contributing

When adding new detections:
1. Create detection in `detections/` with proper Panther format
2. Add test fixtures in `tests/fixtures/`
3. Write comprehensive tests covering TP, TN, and edge cases
4. Run tests locally before submitting PR
5. Ensure all tests pass in CI/CD

## Resources

- [Panther Documentation](https://docs.panther.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Kubernetes Audit Logs](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
