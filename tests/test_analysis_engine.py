from src.analysis_engine import (
    AnalysisRequest,
    AnalysisResult,
    run_analysis,
)


def test_analysis_request_defaults():
    request = AnalysisRequest()

    assert request.log_file is None
    assert request.windows_security is None
    assert request.sysmon is None
    assert request.linux_auth is None
    assert request.linux_year is None
    assert request.linux_utc_offset is None
    assert request.disabled_accounts is None
    assert request.detection_config is None
    assert request.correlation_config is None


def test_analysis_result_defaults():
    result = AnalysisResult()

    assert result.events == []
    assert result.detections == []
    assert result.correlations == []
    assert result.v3_mode is False


def test_run_analysis_detects_v2_brute_force():
    request = AnalysisRequest(
        log_file="data/brute_force_auth_log.csv"
    )

    result = run_analysis(request)

    assert result.v3_mode is False
    assert any(
        detection["rule_id"] == "AUTH-BF-001"
        for detection in result.detections
    )
    assert result.correlations == []
