from app.scanner import FindingDraft, score_findings


def test_score_findings_bounds():
    score, sev = score_findings([])
    assert score == 100
    assert sev == "low"

    score, sev = score_findings([FindingDraft(severity="high", category="x", title="t", description="d") for _ in range(10)])
    assert 0 <= score <= 100
    assert sev in {"low", "medium", "high"}
