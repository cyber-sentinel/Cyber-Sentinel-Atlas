import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EVENT_ID = "atlas:event:microsoft.windows.security:4872"


def _event() -> dict:
    document = json.loads(
        (ROOT / "content/encyclopedia/approved-exemplars.json").read_text(
            encoding="utf-8"
        )
    )
    return next(event for event in document["events"] if event["id"] == EVENT_ID)


def _example() -> dict:
    document = json.loads(
        (ROOT / "content/encyclopedia/mvp2-analyst-examples.json").read_text(
            encoding="utf-8"
        )
    )
    return next(example for example in document["examples"] if example["subject_id"] == EVENT_ID)


def test_4872_analyst_title_is_semantic_while_provider_template_is_preserved() -> None:
    event = _event()
    assert re.search(r"%\d+", event["title"]) is None
    assert all(re.search(r"%\d+", alias) is None for alias in event["aliases"])
    assert re.search(r"%\d+", event["overview"]["summary"]) is None
    assert all(token in event["overview"]["provider_message_template"] for token in ("%1", "%2", "%3", "%4", "%5"))
    assert all(token in event["source_locator"] for token in ("%1", "%2", "%3", "%4", "%5"))


def test_4872_has_complete_product_facts_and_investigation_context() -> None:
    event = _event()
    assert event["overview"]["category"] == "Object Access"
    assert event["overview"]["subcategory"] == "Certification Services"
    assert event["overview"]["event_type"] == "Success"
    assert {field["native_name"] for field in event["fields"]} == {
        "IsBaseCRL",
        "CRLNumber",
        "KeyContainer",
        "NextPublish",
        "PublishURLs",
    }
    base_crl = next(field for field in event["fields"] if field["native_name"] == "IsBaseCRL")
    assert {item["value"] for item in base_crl["values"]} == {"Yes", "No"}
    assert len(event["collection"]["requirements"]) >= 3
    assert len(event["correlations"]) >= 2
    assert len(event["analysis"]) >= 3
    assert event["external_reference"]["redistribution"] == "source-link-and-coverage-benchmark-only"


def test_4872_example_is_independently_authored_and_sanitized() -> None:
    example = _example()
    normalized = f'{example["label"]} {example["text"]}'.lower()
    assert "synthetic" in normalized
    assert "documentation-only" in normalized
    assert "acme-fr" not in normalized
    assert "win-857zzx6rqhl" not in normalized
    assert "example.test" not in normalized  # rendered DN uses explicit DC components
    assert "dc=example,dc=test" in normalized
