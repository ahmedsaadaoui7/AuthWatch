MITRE_MAPPINGS = {
    "AUTH-BF-001": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "evidence": (
            "Repeated authentication failures against the same "
            "account within the configured detection window."
        ),
    },
    "AUTH-PS-001": {
        "technique_id": "T1110.003",
        "technique_name": "Password Spraying",
        "evidence": (
            "Authentication failures were observed across multiple "
            "accounts from the same source within the configured "
            "detection window."
        ),
    },
}


def get_mitre_mapping(result):
    result_id = (
        result.get("rule_id")
        or result.get("correlation_id")
    )

    mapping = MITRE_MAPPINGS.get(result_id)

    if mapping is None:
        return None

    return mapping.copy()


def attach_mitre_mapping(result):
    enriched_result = result.copy()

    mapping = get_mitre_mapping(result)

    if mapping is not None:
        enriched_result["mitre"] = mapping

    return enriched_result


def attach_mitre_mappings(results):
    return [
        attach_mitre_mapping(result)
        for result in results
    ]
