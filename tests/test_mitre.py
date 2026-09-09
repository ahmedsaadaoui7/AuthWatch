from src.mitre import (
    attach_mitre_mapping,
    attach_mitre_mappings,
    get_mitre_mapping,
)


def test_get_mitre_mapping_for_brute_force():
    result = {
        "rule_id": "AUTH-BF-001",
    }

    mapping = get_mitre_mapping(result)

    assert mapping == {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "evidence": (
            "Repeated authentication failures against the same "
            "account within the configured detection window."
        ),
    }


def test_get_mitre_mapping_for_password_spraying():
    result = {
        "rule_id": "AUTH-PS-001",
    }

    mapping = get_mitre_mapping(result)

    assert mapping["technique_id"] == "T1110.003"
    assert mapping["technique_name"] == "Password Spraying"


def test_get_mitre_mapping_returns_none_for_unsupported_result():
    result = {
        "correlation_id": "CORR-PROC-NET-001",
    }

    mapping = get_mitre_mapping(result)

    assert mapping is None


def test_attach_mitre_mapping_to_supported_detection():
    result = {
        "rule_id": "AUTH-BF-001",
        "title": "Potential Brute-Force Activity",
        "severity": "high",
    }

    enriched_result = attach_mitre_mapping(result)

    assert enriched_result["mitre"]["technique_id"] == "T1110"
    assert enriched_result["mitre"]["technique_name"] == "Brute Force"

    assert "mitre" not in result


def test_attach_mitre_mapping_leaves_unsupported_result_unmapped():
    result = {
        "correlation_id": "CORR-PROC-NET-001",
        "title": "Process to Network Activity",
    }

    enriched_result = attach_mitre_mapping(result)

    assert "mitre" not in enriched_result



def test_attach_mitre_mappings_to_multiple_results():
    results = [
        {
            "rule_id": "AUTH-BF-001",
        },
        {
            "rule_id": "AUTH-PS-001",
        },
        {
            "correlation_id": "CORR-PROC-NET-001",
        },
    ]

    enriched_results = attach_mitre_mappings(results)

    assert enriched_results[0]["mitre"]["technique_id"] == "T1110"

    assert (
        enriched_results[1]["mitre"]["technique_id"]
        == "T1110.003"
    )

    assert "mitre" not in enriched_results[2]
