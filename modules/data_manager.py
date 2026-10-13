"""data_manager.py - Synthetic dataset, local persistence (JSON) and exports (CSV/JSON)."""
import json
import os
from datetime import datetime
from pathlib import Path

import pandas as pd

from modules import risk_engine as engine
from modules.workflow import sample_workflow

BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLE_CSV = BASE_DIR / "data" / "sample_risks.csv"
APP_NAME = "ShopAssist Support Chatbot"

CSV_COLUMNS = ["risk_id", "application_name", "lifecycle_stage", "data_category", "risk_title",
               "risk_description", "data_involved", "likelihood", "impact", "risk_score",
               "risk_level", "mitigation", "status"]


def state_path():
    """Where the assessment is saved. Can be overridden (used by the tests)."""
    return Path(os.environ.get("PIA_STATE_PATH", BASE_DIR / "data" / "assessment_state.json"))


# ------------------------------------------------- synthetic sample dataset --
# (id, stage, data category, title, description, likelihood, impact, mitigation, status)
_SAMPLE_ROWS = [
    ("SR-001", "Data collection", "Contact details", "Collection of unnecessary personal information",
     "Chat form asks for phone number and address although neither is needed to answer queries.", 4, 3,
     "Apply data minimization; remove optional fields; document purpose of each field.", "In Progress"),
    ("SR-002", "Data collection", "Customer identifiers", "Unclear data usage and consent practices",
     "Privacy notice does not mention that chats are processed by a language model.", 4, 3,
     "Show a clear AI-processing notice and consent prompt before the chat starts.", "Pending"),
    ("SR-003", "Data collection", "Minors' data", "Collection of data from children",
     "No age check; users under 18 could submit personal details.", 2, 5,
     "Add an age gate; avoid collecting sensitive information unless necessary.", "Pending"),
    ("SR-004", "Data preprocessing", "Chat text, email", "Inadequate anonymization",
     "Names and emails remain in the text after cleaning and tokenisation.", 4, 4,
     "Redact personal identifiers during preprocessing; re-test for re-identification.", "In Progress"),
    ("SR-005", "Data preprocessing", "Order history", "Unauthorized access to preprocessing store",
     "Intermediate files are saved in a shared folder without access control.", 3, 3,
     "Apply role-based access control and encrypt intermediate files.", "Completed"),
    ("SR-006", "Data preprocessing", "Free-text queries", "Residual identifiers in training samples",
     "Free-text samples kept for tuning may include addresses typed by customers.", 3, 4,
     "Use automated PII detection and remove records that fail the check.", "Pending"),
    ("SR-007", "Prompt submission", "Payment details", "Exposure of sensitive information in prompts",
     "Customers paste card numbers and ID numbers into the chat prompt.", 5, 5,
     "Redact personal identifiers before sending prompts; show an input warning.", "In Progress"),
    ("SR-008", "Prompt submission", "Prompt logs", "Potential prompt logging and information exposure",
     "All prompts are logged in plain text and readable by support staff.", 4, 4,
     "Restrict access to prompt logs and mask sensitive values before logging.", "Pending"),
    ("SR-009", "Prompt submission", "Health remarks", "Sensitive health data volunteered in queries",
     "Customers sometimes mention medical conditions when asking about returns.", 3, 5,
     "Detect and block sensitive categories; train staff on handling such logs.", "Pending"),
    ("SR-010", "Model inference", "Prompt, chat history", "Third-party model hosting",
     "Prompts are processed by an external model host with unclear data handling.", 4, 4,
     "Review third-party data-processing arrangements; sign a data-processing agreement.", "Pending"),
    ("SR-011", "Model inference", "Chat history", "Excess context passed to the model",
     "The full chat history, including old personal details, is sent with each request.", 3, 3,
     "Limit context to the last few turns and strip identifiers.", "Completed"),
    ("SR-012", "Model inference", "Prompt content", "Prompt injection exposing other users' data",
     "Crafted prompts might trick the bot into revealing earlier conversation content.", 2, 4,
     "Isolate sessions and test outputs for accidental disclosure.", "In Progress"),
    ("SR-013", "Output generation", "Order details", "Personal data leakage through generated outputs",
     "The bot repeats full addresses and order numbers in replies.", 4, 4,
     "Test generated outputs for accidental disclosure; mask personal data in replies.", "Pending"),
    ("SR-014", "Output generation", "Customer names", "Wrong-person disclosure",
     "The bot may answer with another customer's details after a session mix-up.", 2, 5,
     "Bind sessions to authenticated users and add automated disclosure tests.", "In Progress"),
    ("SR-015", "Output generation", "Generated text", "Outputs stored without review",
     "Replies containing personal data are cached and reused for similar questions.", 3, 2,
     "Do not cache replies containing personal data.", "Completed"),
    ("SR-016", "Data storage and retention", "Transcripts", "Excessive data retention",
     "Transcripts are kept for 730 days with no business reason.", 5, 3,
     "Define and enforce retention periods (e.g. 90 days) with automatic expiry.", "Pending"),
    ("SR-017", "Data storage and retention", "Transcripts, email", "Unauthorized access risk",
     "The transcript database is readable by all engineers.", 4, 5,
     "Restrict access with RBAC, encryption at rest and audit logs.", "In Progress"),
    ("SR-018", "Data storage and retention", "Backups", "Unencrypted backups",
     "Database backups are stored without encryption.", 2, 4,
     "Encrypt backups and apply the same retention limits.", "Pending"),
    ("SR-019", "Data sharing and third-party processing", "Transcripts", "Third-party data-sharing risk",
     "Transcripts are shared with an analytics vendor without a signed agreement.", 4, 4,
     "Review third-party arrangements; share de-identified data only.", "Pending"),
    ("SR-020", "Data sharing and third-party processing", "Device ID", "Cross-border transfer unclear",
     "The vendor may process data in other countries; locations are not documented.", 3, 3,
     "Document processing locations and add transfer clauses to the contract.", "Pending"),
    ("SR-021", "Data deletion", "Customer profile", "Lack of a data deletion procedure",
     "Deletion is manual and ad hoc; backups and logs are never cleaned.", 5, 4,
     "Establish secure deletion procedures covering databases, logs and backups.", "In Progress"),
    ("SR-022", "Data deletion", "Analytics copies", "Vendor copies not deleted",
     "Deletion requests are not forwarded to the analytics vendor.", 4, 3,
     "Add vendor deletion to the procedure and confirm in writing.", "Pending"),
    ("SR-023", "Data deletion", "Transcripts", "No incident response plan",
     "No documented steps exist if a privacy incident or leak occurs.", 3, 4,
     "Establish incident response and privacy review procedures.", "Pending"),
    ("SR-024", "Data storage and retention", "Audit logs", "Low-risk metadata retention",
     "Access logs keep IP addresses for 30 days.", 1, 3,
     "Keep as is but document the purpose and retention period.", "Completed"),
]


def build_sample_dataframe():
    """Create the 24-record synthetic dataset programmatically."""
    rows = []
    for rid, stage, cat, title, desc, lik, imp, mit, status in _SAMPLE_ROWS:
        rows.append({"risk_id": rid, "application_name": APP_NAME, "lifecycle_stage": stage,
                     "data_category": cat, "risk_title": title, "risk_description": desc,
                     "data_involved": cat, "likelihood": lik, "impact": imp,
                     "risk_score": engine.risk_score(lik, imp),
                     "risk_level": engine.risk_level(engine.risk_score(lik, imp)),
                     "mitigation": mit, "status": status})
    return pd.DataFrame(rows, columns=CSV_COLUMNS)


def ensure_sample_csv():
    """Write data/sample_risks.csv if it does not exist yet."""
    if not SAMPLE_CSV.exists():
        SAMPLE_CSV.parent.mkdir(parents=True, exist_ok=True)
        build_sample_dataframe().to_csv(SAMPLE_CSV, index=False)


def load_sample_findings():
    """Read the sample CSV and convert it to finding dictionaries."""
    ensure_sample_csv()
    try:
        df = pd.read_csv(SAMPLE_CSV)
    except Exception:  # damaged file -> rebuild from code
        df = build_sample_dataframe()
    findings = []
    for rec in df.to_dict("records"):
        rec["source"], rec["adjusted"] = "sample", False
        findings.append(engine.finalize(rec))  # recompute score/level from L x I
    return findings


# ------------------------------------------------------------- persistence --
def sample_state():
    return {"workflow": sample_workflow(), "pia": default_pia(),
            "findings": load_sample_findings(), "scans": [],
            "last_analyzed": "Sample data loaded"}


def default_pia():
    return {"business_purpose": "Answer customer questions about orders, returns and delivery.",
            "owner": "Customer Experience Team (synthetic)", "intended_users": "Online shop customers",
            "data_categories": ["Contact details", "Order history"],
            "processing_purpose": "Provide automated customer support.",
            "collection_methods": "Chat widget on the shop website",
            "storage_retention": "Transcripts stored for 730 days in a central database",
            "third_party_integrations": "Hosted language model; analytics vendor",
            "impacts": ["Loss of confidentiality", "Unwanted profiling"],
            "identified_risks": "Payment details in prompts; long retention; no deletion procedure.",
            "mitigation_measures": "Redaction of prompts, retention limit, deletion workflow.",
            "residual_risks": "Third-party processing will remain after mitigation.",
            "conclusion": "Not acceptable until mitigated",
            "conclusion_notes": "Proceed to deployment only after critical risks are completed."}


def save_state(state):
    """Save atomically so a crash cannot corrupt the file."""
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(path)


def load_state():
    """Load the saved assessment; fall back to the sample if missing or damaged."""
    path = state_path()
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        assert {"workflow", "pia", "findings"} <= set(state)
        state["findings"] = [engine.finalize(f) for f in state["findings"]]
        state.setdefault("scans", [])   # older saved files have no scan history
        return state
    except Exception:
        state = sample_state()
        try:
            save_state(state)
        except OSError:
            pass
        return state


def reset_state():
    """Restore the sample assessment (workflow, PIA form and risk register)."""
    state = sample_state()
    save_state(state)
    return state


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


# ----------------------------------------------------------------- exports --
def findings_dataframe(findings):
    df = pd.DataFrame(findings)
    if df.empty:
        return pd.DataFrame(columns=CSV_COLUMNS)
    return df[CSV_COLUMNS]


def export_csv(findings):
    return findings_dataframe(findings).to_csv(index=False).encode("utf-8")


def export_json(findings, app_name=""):
    payload = {"application": app_name, "exported_at": now(),
               "note": "Potential risks identified by predefined rules; not proof of a breach.",
               "risks": findings_dataframe(findings).to_dict("records")}
    return json.dumps(payload, indent=2, default=str).encode("utf-8")
