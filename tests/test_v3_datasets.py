import json
from pathlib import Path

import pytest

from src.correlation import run_correlation_engine
from src.detector import run_detection_engine
from src.normalizer import (
    normalize_linux_auth_event,
    normalize_linux_timestamp,
)
from src.reporter import build_investigation_report


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_dataset(relative_path):
    dataset_path = PROJECT_ROOT / relative_path

    with dataset_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def test_norm_001_normal_activity_produces_no_findings():
    dataset = load_dataset(
        "data/v3/normal/NORM-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]

    alerts = run_detection_engine(events)
    correlations = run_correlation_engine(events)

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]


def test_corr_auth_exec_001_produces_expected_correlation():
    dataset = load_dataset(
        "data/v3/correlations/CORR-AUTH-EXEC-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]

    alerts = run_detection_engine(events)
    correlations = run_correlation_engine(events)

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]


def test_fp_auth_exec_001_does_not_correlate():
    dataset = load_dataset(
        "data/v3/false_positives/FP-AUTH-EXEC-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]

    alerts = run_detection_engine(events)
    correlations = run_correlation_engine(events)

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]


def test_bound_correlation_001_exact_window_boundary_correlates():
    dataset = load_dataset(
        "data/v3/boundaries/BOUND-CORRELATION-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]

    alerts = run_detection_engine(events)
    correlations = run_correlation_engine(events)

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]


def test_det_bf_001_produces_brute_force_detection():
    dataset = load_dataset(
        "data/v3/detections/DET-BF-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]

    alerts = run_detection_engine(events)
    correlations = run_correlation_engine(events)

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]


def test_det_ps_001_produces_expected_detections():
    dataset = load_dataset(
        "data/v3/detections/DET-PS-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]

    alerts = run_detection_engine(events)
    correlations = run_correlation_engine(events)

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]


def test_det_sf_001_produces_success_after_failures_detection():
    dataset = load_dataset(
        "data/v3/detections/DET-SF-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]

    alerts = run_detection_engine(events)
    correlations = run_correlation_engine(events)

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]
def test_det_da_001_produces_disabled_account_detection():
    dataset = load_dataset(
        "data/v3/detections/DET-DA-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]
    disabled_accounts = dataset["disabled_accounts"]

    alerts = run_detection_engine(
        events,
        disabled_accounts=disabled_accounts,
    )

    correlations = run_correlation_engine(events)

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]


def test_det_ma_001_produces_one_ip_many_accounts_detection():
    dataset = load_dataset(
        "data/v3/detections/DET-MA-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]

    alerts = run_detection_engine(events)
    correlations = run_correlation_engine(events)

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]


def test_det_mi_001_produces_many_ips_one_account_detection():
    dataset = load_dataset(
        "data/v3/detections/DET-MI-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]

    alerts = run_detection_engine(events)
    correlations = run_correlation_engine(events)

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]


def test_corr_priv_exec_001_produces_expected_correlation():
    dataset = load_dataset(
        "data/v3/correlations/CORR-PRIV-EXEC-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]

    alerts = run_detection_engine(events)
    correlations = run_correlation_engine(events)

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]


def test_corr_proc_net_001_produces_expected_correlation():
    dataset = load_dataset(
        "data/v3/correlations/CORR-PROC-NET-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]

    alerts = run_detection_engine(events)
    correlations = run_correlation_engine(events)

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]


def test_corr_proc_dns_001_produces_expected_correlation():
    dataset = load_dataset(
        "data/v3/correlations/CORR-PROC-DNS-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]

    alerts = run_detection_engine(events)
    correlations = run_correlation_engine(events)

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]


def test_corr_ssh_sudo_001_produces_expected_correlation():
    dataset = load_dataset(
        "data/v3/correlations/CORR-SSH-SUDO-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]

    alerts = run_detection_engine(events)
    correlations = run_correlation_engine(events)

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]


def test_fp_proc_net_001_does_not_correlate():
    dataset = load_dataset(
        "data/v3/false_positives/FP-PROC-NET-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]

    alerts = run_detection_engine(events)
    correlations = run_correlation_engine(events)

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]


def test_fp_ssh_sudo_001_does_not_correlate():
    dataset = load_dataset(
        "data/v3/false_positives/FP-SSH-SUDO-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]

    alerts = run_detection_engine(events)
    correlations = run_correlation_engine(events)

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]


def test_fp_time_001_outside_window_does_not_correlate():
    dataset = load_dataset(
        "data/v3/false_positives/FP-TIME-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]

    alerts = run_detection_engine(events)
    correlations = run_correlation_engine(events)

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]


def test_bound_detection_001_exact_window_boundary_detects():
    dataset = load_dataset(
        "data/v3/boundaries/BOUND-DETECTION-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]

    alerts = run_detection_engine(events)
    correlations = run_correlation_engine(events)

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]


def test_invalid_time_001_rejects_invalid_timestamp():
    dataset = load_dataset(
        "data/v3/invalid/INVALID-TIME-001.json"
    )

    events = dataset["events"]
    expected_error = dataset["expected_error"]

    with pytest.raises(ValueError) as error:
        run_correlation_engine(events)

    assert str(error.value) == expected_error



def test_invalid_linux_001_rejects_invalid_utc_offset():
    dataset = load_dataset(
        "data/v3/invalid/INVALID-LINUX-001.json"
    )

    test_input = dataset["input"]
    expected_error = dataset["expected_error"]

    with pytest.raises(ValueError) as error:
        normalize_linux_timestamp(
            test_input["timestamp"],
            year=test_input["year"],
            utc_offset=test_input["utc_offset"],
        )

    assert str(error.value) == expected_error


def test_invalid_event_001_rejects_unsupported_linux_event():
    dataset = load_dataset(
        "data/v3/invalid/INVALID-EVENT-001.json"
    )

    test_input = dataset["input"]
    expected_error = dataset["expected_error"]

    with pytest.raises(ValueError) as error:
        normalize_linux_auth_event(
            test_input["event"],
            year=test_input["year"],
            utc_offset=test_input["utc_offset"],
        )

    assert str(error.value) == expected_error


def test_zero_001_builds_valid_zero_finding_investigation():
    dataset = load_dataset(
        "data/v3/zero_results/ZERO-001.json"
    )

    events = dataset["events"]
    expected = dataset["expected"]

    alerts = run_detection_engine(events)
    correlations = run_correlation_engine(events)

    report = build_investigation_report(
        alerts,
        correlations,
    )

    actual_detection_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    actual_correlation_ids = [
        correlation["correlation_id"]
        for correlation in correlations
    ]

    assert actual_detection_ids == expected["detection_rule_ids"]
    assert actual_correlation_ids == expected["correlation_ids"]

    assert report["detection_summary"]["total"] == \
        expected["detection_count"]

    assert report["correlation_summary"]["total"] == \
        expected["correlation_count"]

    assert report["related_ids"]["detection_rule_ids"] == []
    assert report["related_ids"]["correlation_ids"] == []
    assert report["timeline"] == []
    assert report["detections"] == []
    assert report["correlations"] == []
