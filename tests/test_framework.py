# tests/test_framework.py

import json
import pytest
from pathlib import Path
from typing import Any, Dict, Optional, List
from dataclasses import dataclass


@dataclass
class DetectionResult:
    """Structured detection result for logic verification"""
    matched: bool
    error: Optional[str] = None


class DetectionTestFramework:
    """
    Framework for testing Panther detection logic with realistic test events.
    """

    @staticmethod
    def load_test_fixtures(fixture_name: str) -> Dict[str, Any]:
        """
        Load test events from fixtures directory

        Args:
            fixture_name: Name of fixture file (without .json extension)

        Returns:
            Dict of test event scenarios

        Raises:
            FileNotFoundError: If fixture file doesn't exist
            ValueError: If fixture JSON is invalid
        """
        fixture_path = Path(f"tests/fixtures/{fixture_name}.json")

        if not fixture_path.exists():
            available = list(Path('fixtures').glob('*.json'))
            raise FileNotFoundError(
                f"Test fixture not found: {fixture_path}\n"
                f"Available fixtures: {[f.name for f in available]}"
            )

        try:
            with open(fixture_path) as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in fixture {fixture_name}: {e}")

    @staticmethod
    def run_detection(detection, event: Dict[str, Any]) -> DetectionResult:
        """
        Execute detection rule logic and capture result

        Args:
            detection: Detection module with rule() function
            event: Event dictionary to test

        Returns:
            DetectionResult with match status and any errors
        """
        try:
            matched = detection.rule(event)
            return DetectionResult(matched=bool(matched))

        except Exception as e:
            return DetectionResult(
                matched=False,
                error=f"Detection execution failed: {type(e).__name__}: {str(e)}"
            )

    @staticmethod
    def assert_detection_matches(
        detection,
        event: Dict[str, Any],
        debug: bool = True
    ):
        """
        Assert detection rule() returns True for given event

        Args:
            detection: Detection module to test
            event: Event to test against
            debug: Print detailed debug info on failure

        Raises:
            AssertionError: If detection doesn't match or execution fails
        """
        result = DetectionTestFramework.run_detection(detection, event)

        if result.error:
            pytest.fail(f"Detection execution error: {result.error}")

        if not result.matched:
            if debug:
                print("\n=== Detection Did Not Match ===")
                print(f"Event preview: {json.dumps(event, indent=2)[:500]}...")
                print(f"\nDetection rule function: {detection.rule.__name__}")

                # Try to show rule source code for debugging
                try:
                    import inspect
                    source = inspect.getsource(detection.rule)
                    print(f"\nRule logic:\n{source}")
                except Exception:
                    pass

            pytest.fail(
                f"Detection did not match event.\n"
                f"Event keys: {list(event.keys())}\n"
                f"Expected: rule() to return True"
            )

    @staticmethod
    def assert_detection_does_not_match(
        detection,
        event: Dict[str, Any],
        reason: Optional[str] = None
    ):
        """
        Assert detection rule() returns False for given event

        Args:
            detection: Detection module to test
            event: Event to test against
            reason: Optional explanation of why it shouldn't match (for documentation)

        Raises:
            AssertionError: If detection matches or execution fails
        """
        result = DetectionTestFramework.run_detection(detection, event)

        if result.error:
            pytest.fail(f"Detection execution error: {result.error}")

        if result.matched:
            fail_msg = (
                f"Detection matched when it shouldn't have.\n"
                f"Event: {json.dumps(event, indent=2)[:300]}..."
            )
            if reason:
                fail_msg += f"\n\nExpected to not match because: {reason}"

            pytest.fail(fail_msg)

    @staticmethod
    def run_test_suite(
        detection,
        test_cases: Dict[str, Dict[str, Any]],
        verbose: bool = False
    ) -> Dict[str, Any]:
        """
        Run multiple test cases and return results summary

        Args:
            detection: Detection to test
            test_cases: Dict of {test_name: {event, should_match}}
            verbose: Print results for each test

        Returns:
            Summary dict with pass/fail counts and coverage metrics
        """
        results = {
            'total': len(test_cases),
            'passed': 0,
            'failed': 0,
            'errors': [],
            'coverage': {
                'true_positive_tests': 0,  # Should match and did
                'true_negative_tests': 0,  # Should not match and didn't
            }
        }

        for test_name, test_spec in test_cases.items():
            event = test_spec['event']
            should_match = test_spec['should_match']

            try:
                result = DetectionTestFramework.run_detection(detection, event)

                if result.error:
                    raise Exception(result.error)

                # Validate expected behavior
                if should_match:
                    assert result.matched, "Expected to match but didn't"
                    results['coverage']['true_positive_tests'] += 1
                else:
                    assert not result.matched, "Expected to not match but did"
                    results['coverage']['true_negative_tests'] += 1

                results['passed'] += 1

                if verbose:
                    status = "matched" if result.matched else "did not match"
                    print(f"✓ {test_name}: {status} (as expected)")

            except (AssertionError, Exception) as e:
                results['failed'] += 1
                results['errors'].append({
                    'test': test_name,
                    'error': str(e),
                    'expected_match': should_match
                })

                if verbose:
                    print(f"✗ {test_name}: {e}")

        return results

    @staticmethod
    def validate_detection_structure(detection) -> Dict[str, Any]:
        """
        Validate detection has required structure for Panther

        Args:
            detection: Detection module to validate

        Returns:
            Dict with validation results and any issues found
        """
        issues = []

        # Required: rule() function
        if not hasattr(detection, 'rule'):
            issues.append("CRITICAL: Missing required function: rule()")
        elif not callable(detection.rule):
            issues.append("CRITICAL: 'rule' attribute is not callable")

        # Recommended functions
        recommended = {
            'title': 'Alert title generation',
            'severity': 'Dynamic severity assignment',
            'description': 'Investigation guidance',
            'alert_context': 'Enrichment data for alerts'
        }

        for attr, purpose in recommended.items():
            if not hasattr(detection, attr):
                issues.append(f"WARNING: Missing recommended function: {attr}() - {purpose}")

        # Check for docstring
        if hasattr(detection, 'rule') and not detection.rule.__doc__:
            issues.append("WARNING: rule() function missing docstring")

        critical_issues = [i for i in issues if i.startswith('CRITICAL')]

        return {
            'valid': len(critical_issues) == 0,
            'issues': issues,
            'has_critical_issues': len(critical_issues) > 0
        }

    @staticmethod
    def test_with_variations(
        detection,
        base_event: Dict[str, Any],
        variations: List[Dict[str, Any]],
        should_match: bool = True
    ) -> Dict[str, Any]:
        """
        Test detection against multiple variations of a base event

        Useful for testing edge cases and input variations

        Args:
            detection: Detection to test
            base_event: Base event template
            variations: List of dicts to merge with base event
            should_match: Whether variations should match (default True)

        Returns:
            Results summary
        """
        results = {
            'total': len(variations),
            'passed': 0,
            'failed': 0,
            'details': []
        }

        for i, variation in enumerate(variations):
            # Deep merge variation into base event
            test_event = {**base_event, **variation}

            result = DetectionTestFramework.run_detection(detection, test_event)

            matched_as_expected = (result.matched == should_match)

            if matched_as_expected and not result.error:
                results['passed'] += 1
            else:
                results['failed'] += 1

            results['details'].append({
                'variation_index': i,
                'variation': variation,
                'matched': result.matched,
                'expected_match': should_match,
                'success': matched_as_expected,
                'error': result.error
            })

        return results
