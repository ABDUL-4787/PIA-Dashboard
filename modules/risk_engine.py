"""risk_engine.py - Rule-based privacy risk detection and transparent scoring.

No machine learning and no external AI is used. Every finding comes from a
simple IF-condition on the workflow answers, so it can be explained in a viva.
Findings are POTENTIAL risks, not proof of a breach.
"""
from modules.workflow import STAGE_LABELS, STAGE_CODES

STATUSES = ["Pending", "In Progress", "Completed"]
LEVEL_ORDER = ["Low", "Medium", "High", "Critical"]

# How much of a risk still counts once its mitigation has progressed.
# Used only for the "current (residual-aware)" overall score.
RESIDUAL_FACTOR = {"Pending": 1.0, "In Progress": 0.6, "Completed": 0.2}

SENSITIVE_KEYWORDS = ["health", "medical", "biometric", "financial", "payment", "card",
                      "passport", "government id", "aadhaar", "religion", "political",
                      "children", "genetic", "sexual", "password", "bank"]


# ----------------------------------------------------------------- scoring --
def clamp(value):
    """Force a likelihood/impact value into the valid 1-5 range."""
    try:
        return int(max(1, min(5, round(float(value)))))
    except (TypeError, ValueError):
        return 1


def risk_score(likelihood, impact):
    """Risk Score = Likelihood x Impact (1-25)."""
    return clamp(likelihood) * clamp(impact)


def risk_level(score):
    """1-4 Low, 5-9 Medium, 10-16 High, 17-25 Critical."""
    if score <= 4:
        return "Low"
    if score <= 9:
        return "Medium"
    if score <= 16:
        return "High"
    return "Critical"


def finalize(f):
    """Recompute score and level from likelihood x impact (keeps data consistent)."""
    f["likelihood"], f["impact"] = clamp(f["likelihood"]), clamp(f["impact"])
    f["risk_score"] = risk_score(f["likelihood"], f["impact"])
    f["risk_level"] = risk_level(f["risk_score"])
    if f.get("status") not in STATUSES:
        f["status"] = "Pending"
    return f


def overall_score(findings, residual=False):
    """Overall workflow score on a 0-100 scale.

    score = sum(risk_score x weight) / (25 x number_of_risks) x 100
    weight = 1 for the inherent score; for the residual-aware score the weight is
    1.0 / 0.6 / 0.2 for Pending / In Progress / Completed mitigation.
    0 means no risks; 100 means every risk is 5 x 5 and nothing is mitigated.
    """
    if not findings:
        return 0.0
    total = 0.0
    for f in findings:
        w = RESIDUAL_FACTOR.get(f.get("status"), 1.0) if residual else 1.0
        total += clamp(f["likelihood"]) * clamp(f["impact"]) * w
    return round(total / (25 * len(findings)) * 100, 1)


def overall_label(score):
    """Same bands as the 1-25 scale, expressed as a percentage of 25."""
    if score <= 16:
        return "Low"
    if score <= 36:
        return "Medium"
    if score <= 64:
        return "High"
    return "Critical"


def count_by_level(findings):
    counts = {lvl: 0 for lvl in LEVEL_ORDER}
    for f in findings:
        counts[f["risk_level"]] += 1
    return counts


# ------------------------------------------------------------------- rules --
def _cap(v):
    return min(5, v)


def analyze(workflow, pia=None, existing=None):
    """Apply all rules to a workflow and return a list of finding dicts.

    existing: previous findings. For risks that are still detected we keep the
    user's status and any manually adjusted likelihood/impact.
    """
    pia = pia or {}
    app = workflow.get("app_name") or "Unnamed application"
    ctl = workflow.get("controls", {})
    stages = workflow.get("stages", {})
    out = []

    def add(rule, stage, title, desc, data, L, I, mitigation):
        out.append({
            "risk_id": f"{rule}-{STAGE_CODES[stage]}", "application_name": app,
            "lifecycle_stage": STAGE_LABELS[stage],
            "data_category": data or "Not specified", "risk_title": title,
            "risk_description": desc, "data_involved": data or "Not specified",
            "likelihood": _cap(L), "impact": _cap(I), "mitigation": mitigation,
            "status": "Pending", "source": "rule", "adjusted": False,
        })

    def s(key):
        return stages.get(key, {})

    any_personal = any(s(k).get("personal") for k in stages)
    any_sensitive = any(s(k).get("sensitive") for k in stages)

    # PR01 - unnecessary personal data collection
    c = s("data_collection")
    if c.get("personal") and not ctl.get("data_minimization"):
        sens = int(bool(c.get("sensitive")))
        add("PR01", "data_collection", "Collection of unnecessary personal information",
            "Personal data is collected but no data-minimization practice is in place, "
            "so more data than needed may be gathered.", c.get("data_types"),
            3 + sens, 3 + sens,
            "Apply data minimization: list each field and its purpose; remove fields that are not needed; "
            "avoid collecting sensitive information unless necessary.")

    # PR02 - sensitive data in prompts / PR04 - inadequate anonymization
    p = s("prompt_submission")
    pr02 = p.get("sensitive") and not p.get("anonymized")
    if pr02:
        add("PR02", "prompt_submission", "Exposure of sensitive information in prompts",
            "Sensitive data may be typed or pasted into prompts and sent to the model without redaction.",
            p.get("data_types"), 4, 5,
            "Redact personal identifiers and sensitive values before sending prompts to the AI model; "
            "add an input warning telling users not to enter card or ID numbers.")
    for key in ("data_preprocessing", "prompt_submission", "model_inference"):
        st_ = s(key)
        if key == "prompt_submission" and pr02:
            continue  # already reported more specifically as PR02
        if st_.get("personal") and not st_.get("anonymized"):
            sens = int(bool(st_.get("sensitive")))
            add("PR04", key, "Inadequate anonymization or pseudonymization",
                "Personal data is processed in identifiable form at this stage.",
                st_.get("data_types"), 4, 3 + sens + int(key == "data_preprocessing"),
                "Anonymize or pseudonymize data at preprocessing (mask names, emails, IDs); "
                "re-test that individuals cannot be re-identified.")

    # PR03 - leakage through generated output
    o = s("output_generation")
    if o.get("personal") and not ctl.get("output_filtering"):
        sens = int(bool(o.get("sensitive") or any_sensitive))
        add("PR03", "output_generation", "Personal data leakage through generated outputs",
            "The model may repeat or reveal personal data from prompts, history or training context "
            "in its replies, and outputs are not checked.", o.get("data_types"),
            3 + sens, 4 + sens,
            "Test generated outputs for accidental disclosure; add an output filter that masks personal data; "
            "limit the context passed to the model.")

    # PR05 - excessive retention, PR06 - weak access control, PR07 - third party
    for key in stages:
        st_ = s(key)
        if not st_.get("personal"):
            continue
        sens = int(bool(st_.get("sensitive")))
        days = st_.get("retention_days", 0) or 0
        if key != "data_deletion" and (days == 0 or days > 180):
            undefined = days == 0
            add("PR05", key, "Excessive or undefined data retention",
                ("No retention period is defined." if undefined else f"Data is kept for {days} days.")
                + " Keeping personal data longer than needed increases exposure if it is breached.",
                st_.get("data_types"), 4 if (undefined or days > 365) else 3, 3 + sens,
                "Define and enforce data retention periods (for example 30-90 days for chat logs) "
                "with automatic expiry.")
        if not st_.get("access_controls"):
            add("PR06", key, "Unauthorized access risk",
                "Access controls are not implemented, so staff or attackers may read personal data.",
                st_.get("data_types"), 3 + sens, 4 + sens,
                "Restrict access using role-based access control, encryption and audit logging; "
                "restrict access to prompt logs.")
        if st_.get("third_party"):
            dpa = ctl.get("dpa_in_place")
            add("PR07", key, "Third-party data-sharing risk",
                "Personal data leaves the organization for third-party processing"
                + ("." if dpa else " and no data-processing agreement is confirmed."),
                st_.get("data_types"), 2 if dpa else 4, 3 + sens,
                "Review third-party data-processing arrangements; sign a data-processing agreement; "
                "share only de-identified data and check where it is processed.")

    # PR08 - no deletion procedure
    if any_personal and not ctl.get("deletion_procedure"):
        d = s("data_deletion")
        add("PR08", "data_deletion", "Lack of a data deletion procedure",
            "Personal data is processed but no documented deletion procedure exists, "
            "so data may never be erased.", d.get("data_types") or "All stored personal data",
            4, 5 if any_sensitive else 4,
            "Establish secure deletion procedures covering databases, logs and backups; "
            "handle deletion requests within a defined time.")

    # PR09 - prompt logging
    if ctl.get("prompt_logs_stored") and p.get("personal"):
        add("PR09", "prompt_submission", "Potential prompt logging and information exposure",
            "Prompts and responses are logged; logs may contain personal or sensitive text.",
            p.get("data_types"), 4 if not p.get("access_controls") else 3,
            5 if p.get("sensitive") else 4,
            "Restrict access to prompt logs; mask personal data before logging; "
            "set a short retention period for logs.")

    # PR10 - unclear data usage and consent
    purpose_missing = not str(pia.get("processing_purpose", "")).strip()
    if c.get("personal") and (not ctl.get("consent_notice") or purpose_missing):
        no_consent = not ctl.get("consent_notice")
        add("PR10", "data_collection", "Unclear data usage and consent practices",
            ("No consent / privacy notice about AI processing. " if no_consent else "")
            + ("The purpose of processing is not documented in the PIA form." if purpose_missing else ""),
            c.get("data_types"), 4 if no_consent else 3, 3,
            "Show a clear privacy notice and obtain consent before chat starts; document the purpose "
            "of processing; establish incident response and privacy review procedures.")

    # PR11 - PIA says sensitive categories, workflow says none
    cats = " ".join(pia.get("data_categories", [])).lower()
    if any(k in cats for k in SENSITIVE_KEYWORDS) and not any_sensitive:
        add("PR11", "data_collection", "Sensitive data not reflected in the workflow",
            "The PIA form lists sensitive data categories but no lifecycle stage is marked as sensitive, "
            "so risks may be under-estimated.", ", ".join(pia.get("data_categories", [])),
            3, 4, "Review the workflow stages and mark sensitive data correctly; re-run the analysis.")

    # Merge with previous findings (keep status and manual score adjustments).
    old = {f["risk_id"]: f for f in (existing or [])}
    for f in out:
        prev = old.get(f["risk_id"])
        if prev:
            f["status"] = prev.get("status", "Pending")
            if prev.get("evidence"):
                f["evidence"] = prev["evidence"]
            if prev.get("adjusted"):
                f["likelihood"], f["impact"], f["adjusted"] = prev["likelihood"], prev["impact"], True
        finalize(f)
    out.sort(key=lambda f: (-f["risk_score"], f["risk_id"]))
    return out


def apply_scan_evidence(findings, prompt_scan=None, output_scan=None, when=""):
    """Use prompt/output scan results as evidence for the matching risks.

    * Sensitive items found in a test prompt  -> PR02-PRM likelihood raised to 5
    * Any personal data found in a model output -> PR03-OUT likelihood raised to 5
    Returns the list of risk IDs that were updated.
    """
    by_id = {f["risk_id"]: f for f in findings}
    changed = []

    def mark(rid, scan_result, what):
        f = by_id.get(rid)
        if not f:
            return
        types = ", ".join(scan_result["counts"]) or "none"
        f["likelihood"] = max(f["likelihood"], 5)
        f["adjusted"] = True
        f["evidence"] = f"Scan on {when}: {what} ({types}). Likelihood set to 5 from test evidence."
        finalize(f)
        changed.append(rid)

    if prompt_scan and prompt_scan["sensitive"] > 0:
        mark("PR02-PRM", prompt_scan, f"{prompt_scan['sensitive']} sensitive item(s) found in a test prompt")
    if output_scan and output_scan["sensitive"] + output_scan["personal"] > 0:
        mark("PR03-OUT", output_scan,
             f"{output_scan['sensitive'] + output_scan['personal']} personal item(s) repeated in a model output")
    return changed
