"""Automated tests for the 10 required scenarios. Run:  python -m pytest -q"""
import io
import json
import os
import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from modules import data_manager as dm, risk_engine as eng, workflow as wf
from modules.report_generator import generate_pdf


@pytest.fixture(autouse=True)
def tmp_state(tmp_path, monkeypatch):
    monkeypatch.setenv("PIA_STATE_PATH", str(tmp_path / "state.json"))


def test_02_sample_data_loads():
    state = dm.sample_state()
    df = dm.findings_dataframe(state["findings"])
    assert len(df) >= 20 and list(df.columns) == dm.CSV_COLUMNS
    assert set(df.risk_level) == {"Low", "Medium", "High", "Critical"}
    assert df.lifecycle_stage.nunique() >= 6


def test_03_high_risk_workflow_triggers_findings():
    f = eng.analyze(wf.sample_workflow(), dm.default_pia())
    ids = {x["risk_id"].split("-")[0] for x in f}
    assert {"PR02", "PR03", "PR05", "PR06", "PR07", "PR08", "PR09", "PR10"} <= ids
    assert any(x["risk_level"] == "Critical" for x in f)


def test_03b_safe_workflow_has_no_findings():
    w = wf.blank_workflow()
    w["app_name"] = "Safe"
    assert eng.analyze(w, {"processing_purpose": "x"}) == []


def test_04_scores_and_levels():
    for l, i, s, lvl in [(1, 4, 4, "Low"), (1, 5, 5, "Medium"), (3, 3, 9, "Medium"),
                         (2, 5, 10, "High"), (4, 4, 16, "High"), (4, 5, 20, "Critical"), (5, 5, 25, "Critical")]:
        assert eng.risk_score(l, i) == s and eng.risk_level(s) == lvl
    assert eng.clamp(9) == 5 and eng.clamp("bad") == 1


def test_overall_score_range_and_status_effect():
    f = [eng.finalize({"likelihood": 5, "impact": 5, "status": "Pending"}) for _ in range(3)]
    assert eng.overall_score(f) == 100.0 and eng.overall_score([]) == 0.0
    f[0]["status"] = "Completed"
    assert eng.overall_score(f, residual=True) < 100.0 and eng.overall_score(f) == 100.0


def test_05_editing_workflow_changes_findings():
    w = wf.sample_workflow()
    before = {x["risk_id"] for x in eng.analyze(w, dm.default_pia())}
    w["controls"]["deletion_procedure"] = True
    w["stages"]["prompt_submission"]["anonymized"] = True
    after = {x["risk_id"] for x in eng.analyze(w, dm.default_pia())}
    assert "PR08-DEL" in before - after and "PR02-PRM" in before - after


def test_05b_adjusted_scores_and_status_survive_reanalysis():
    w, pia = wf.sample_workflow(), dm.default_pia()
    f = eng.analyze(w, pia)
    f[0].update(likelihood=1, impact=1, adjusted=True, status="Completed")
    rid = f[0]["risk_id"]
    again = {x["risk_id"]: x for x in eng.analyze(w, pia, f)}
    assert again[rid]["risk_score"] == 1 and again[rid]["status"] == "Completed"


def test_06_and_10_persistence_and_reset():
    state = dm.sample_state()
    state["findings"][0]["status"] = "Completed"
    dm.save_state(state)
    assert dm.load_state()["findings"][0]["status"] == "Completed"
    restored = dm.reset_state()
    assert restored["findings"][0]["status"] == dm.sample_state()["findings"][0]["status"]
    assert dm.load_state()["last_analyzed"] == "Sample data loaded"


def test_09_corrupt_state_falls_back_to_sample():
    dm.state_path().write_text("{not json", encoding="utf-8")
    assert len(dm.load_state()["findings"]) >= 20


def test_07_pdf_contains_current_results():
    from pypdf import PdfReader
    state = dm.sample_state()
    state["workflow"]["app_name"] = "Unique Test App 42"
    state["findings"][0]["risk_title"] = "Custom Marker Risk"
    text = "".join(p.extract_text() for p in PdfReader(io.BytesIO(generate_pdf(state))).pages)
    assert "Unique Test App 42" in text and "Custom Marker Risk" in text
    assert "Assessment Limitations" in text and "Executive Summary" in text


def test_pdf_with_no_findings_and_special_characters():
    state = dm.sample_state()
    state["findings"] = []
    state["pia"]["owner"] = "A & B <team>"
    assert generate_pdf(state)[:4] == b"%PDF"


def test_08_exports_match_records():
    findings = dm.sample_state()["findings"]
    df = pd.read_csv(io.BytesIO(dm.export_csv(findings)))
    js = json.loads(dm.export_json(findings, "App"))
    assert len(df) == len(js["risks"]) == len(findings)
    assert list(df.risk_id) == [r["risk_id"] for r in js["risks"]]
    assert dm.export_csv([]).decode().startswith("risk_id")


# ---- Scenario 1 + UI: run the real Streamlit app headlessly -----------------
def test_01_app_starts_and_all_pages_render():
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()
    assert not at.exception
    for page in ["Workflow Assessment", "Prompt & Output Scanner", "Risk Register", "PIA Questionnaire", "Reports & Exports", "Dashboard"]:
        at.sidebar.radio[0].set_value(page).run()
        assert not at.exception, f"{page}: {at.exception}"


def _click(at, label):
    next(b for b in at.button if b.label == label).click().run()


def test_ui_validation_and_analysis():
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()
    at.sidebar.radio[0].set_value("Workflow Assessment").run()
    at.text_input[0].set_value("   ")                          # blank application name
    _click(at, "Save & run analysis")
    assert any("required" in e.value for e in at.error)
    at.text_input[0].set_value("Demo App")
    _click(at, "Save & run analysis")
    assert not at.exception and any("potential risks" in s.value for s in at.success)
    assert dm.load_state()["workflow"]["app_name"] == "Demo App"


# ---- New feature: prompt & output scanner ------------------------------------
from modules import pii_scanner as pii

PROMPT = ("my name is Priya Sharma, email priya.sharma@example.com, phone +91 98765 43210, "
          "card 4111 1111 1111 1111, Aadhaar 2345 6789 0123, OTP is 482913")


def test_scanner_detects_expected_types():
    types = {e["type"] for e in pii.detect(PROMPT)}
    assert {"Email address", "Phone number", "Payment card number", "Aadhaar-format ID",
            "Credential / OTP / CVV", "Person name"} <= types


def test_scanner_luhn_avoids_false_positive_and_clean_text():
    assert not pii.luhn_ok("1234 5678 9012 3456")
    assert pii.luhn_ok("4111 1111 1111 1111")
    r = pii.scan("Where is my order? It was due on Monday, thanks for the help.")
    assert r["entities"] == [] and r["exposure_score"] == 0 and r["level"] == "None detected"


def test_redaction_removes_all_pii_and_score_drops():
    r = pii.scan(PROMPT)
    assert r["exposure_score"] == 100 and r["after_redaction_score"] == 0
    for secret in ["priya.sharma@example.com", "4111", "98765", "482913", "Priya"]:
        assert secret not in r["redacted"]
    assert "[EMAIL]" in r["redacted"] and "[CARD]" in r["redacted"]


def test_no_double_counting_card_as_aadhaar():
    ents = pii.detect("card 4111 1111 1111 1111")
    assert [e["type"] for e in ents] == ["Payment card number"]


def test_scan_evidence_raises_matching_risks_only():
    f = eng.analyze(wf.sample_workflow(), dm.default_pia())
    before = {x["risk_id"]: x["risk_score"] for x in f}
    changed = eng.apply_scan_evidence(f, pii.scan(PROMPT), pii.scan("Your email is a@b.com"), "now")
    assert set(changed) == {"PR02-PRM", "PR03-OUT"}
    after = {x["risk_id"]: x for x in f}
    assert after["PR02-PRM"]["likelihood"] == 5 and after["PR02-PRM"]["evidence"]
    assert after["PR03-OUT"]["risk_score"] >= before["PR03-OUT"]
    assert after["PR06-STO"]["risk_score"] == before["PR06-STO"]
    # evidence and adjusted scores survive a re-analysis
    again = {x["risk_id"]: x for x in eng.analyze(wf.sample_workflow(), dm.default_pia(), f)}
    assert again["PR02-PRM"]["evidence"] and again["PR02-PRM"]["likelihood"] == 5


def test_old_state_file_without_scans_still_loads():
    s = dm.sample_state(); s.pop("scans"); dm.save_state(s)
    assert dm.load_state()["scans"] == []


def test_pdf_contains_scan_evidence():
    from pypdf import PdfReader
    state = dm.sample_state()
    state["findings"] = eng.analyze(wf.sample_workflow(), dm.default_pia())
    eng.apply_scan_evidence(state["findings"], pii.scan(PROMPT), None, "t1")
    state["scans"] = [pii.summary("Prompt", pii.scan(PROMPT), "t1")]
    text = "".join(p.extract_text() for p in PdfReader(io.BytesIO(generate_pdf(state))).pages)
    assert "prompt and output scans" in text and "Likelihood set to 5" in text


def test_ui_scanner_flow_end_to_end():
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()
    at.sidebar.radio[0].set_value("Workflow Assessment").run()
    _click(at, "Save & run analysis")                       # create rule-based findings (PR02, PR03 ...)
    at.sidebar.radio[0].set_value("Prompt & Output Scanner").run()
    _click(at, "Scan text")                                 # empty input -> graceful warning
    assert any("Enter a prompt" in w.value for w in at.warning)
    _click(at, "Load synthetic example")
    _click(at, "Scan text")
    assert not at.exception
    _click(at, "Apply scan evidence to Risk Register")
    assert any("PR02-PRM" in x.value for x in at.success)
    saved = dm.load_state()
    assert len(saved["scans"]) == 2
    assert "Priya" not in json.dumps(saved["scans"])        # raw text is never persisted
    assert next(f for f in saved["findings"] if f["risk_id"] == "PR02-PRM")["likelihood"] == 5
