from packageguard.behavior_rules import CHAIN_RULES


def apply_behavior_chains(findings):
    existing_rule_ids = {finding.get("rule_id") for finding in findings}

    all_tags = set()
    first_finding_by_tag = {}
    for finding in findings:
        tags = finding.get("tags") or []
        flat_tags = []
        for tag in tags:
            if isinstance(tag, list):
                flat_tags.extend(tag)
            else:
                flat_tags.append(tag)
        for tag in flat_tags:
            all_tags.add(tag)
            if tag not in first_finding_by_tag:
                first_finding_by_tag[tag] = finding

    chain_findings = []
    added_rule_ids = set()

    for rule in CHAIN_RULES:
        rule_id = rule["id"]
        if rule_id in existing_rule_ids or rule_id in added_rule_ids:
            continue

        suppressed = False
        for suppressor in rule.get("suppressed_by", []):
            if suppressor in added_rule_ids:
                suppressed = True
                break
        if suppressed:
            continue

        matched_tags = []
        rule_matches = True
        for group in rule.get("requires", []):
            found_tag = None
            for tag in group:
                if tag in all_tags:
                    found_tag = tag
                    break
            if not found_tag:
                rule_matches = False
                break
            matched_tags.append(found_tag)

        if not rule_matches:
            continue

        evidence_parts = []
        for tag in matched_tags:
            finding = first_finding_by_tag.get(tag)
            if not finding:
                continue
            source_rule = finding.get("rule_id", "unknown")
            file = finding.get("file", "unknown")
            line = finding.get("line")
            location = f"{file}:{line}" if line else str(file)
            evidence_parts.append(f"{tag} -> {source_rule} ({location})")

        chain_findings.append(
            {
                "rule_id": rule_id,
                "title": rule["title"],
                "severity": rule["severity"],
                "confidence": rule.get("confidence", ""),
                "file": "behavior-chain",
                "line": None,
                "evidence": "; ".join(evidence_parts),
                "explanation_recommendation": rule.get("description", ""),
                "tags": rule.get("tags", []),
                "source": "behavior-chain",
            }
        )
        added_rule_ids.add(rule_id)

    return findings + chain_findings