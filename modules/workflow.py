"""workflow.py - Definition of the GenAI lifecycle stages and the sample workflow.

A *workflow* is a plain Python dictionary so it can be saved as JSON:

    {
      "app_name": "...",
      "controls": {...application-wide privacy practices (True/False)...},
      "stages":   {stage_key: {description, data_types, personal, ...}}
    }
"""
import copy

# (key, label, short code used in risk IDs)
STAGES = [
    ("data_collection", "Data collection", "COL"),
    ("data_preprocessing", "Data preprocessing", "PRE"),
    ("prompt_submission", "Prompt submission", "PRM"),
    ("model_inference", "Model inference", "INF"),
    ("output_generation", "Output generation", "OUT"),
    ("data_storage", "Data storage and retention", "STO"),
    ("data_sharing", "Data sharing and third-party processing", "SHR"),
    ("data_deletion", "Data deletion", "DEL"),
]
STAGE_KEYS = [s[0] for s in STAGES]
STAGE_LABELS = {k: label for k, label, _ in STAGES}
STAGE_CODES = {k: code for k, _, code in STAGES}
LABEL_ORDER = [label for _, label, _ in STAGES]

# Application-wide practices (checkbox = True means the practice EXISTS).
CONTROLS = {
    "data_minimization": "Only data that is strictly needed is collected (data minimization)",
    "consent_notice": "Users are shown a clear privacy notice / consent about AI processing",
    "output_filtering": "Generated outputs are tested/filtered for accidental disclosure of personal data",
    "deletion_procedure": "A documented procedure exists to delete user data on request / expiry",
    "prompt_logs_stored": "Prompts and responses are logged/stored (this is a risk factor)",
    "dpa_in_place": "A data-processing agreement is in place with every third party",
}

EMPTY_STAGE = {
    "description": "",
    "data_types": "",
    "personal": False,
    "sensitive": False,
    "anonymized": False,
    "retention_days": 0,  # 0 = not defined / indefinite
    "access_controls": False,
    "third_party": False,
}


def blank_workflow():
    """An empty workflow the user can fill in from scratch."""
    return {
        "app_name": "",
        "controls": {k: False for k in CONTROLS},
        "stages": {k: copy.deepcopy(EMPTY_STAGE) for k in STAGE_KEYS},
    }


def sample_workflow():
    """Synthetic customer-support chatbot workflow (no real data)."""
    def st(desc, types, personal, sensitive, anon, days, access, third):
        return {"description": desc, "data_types": types, "personal": personal,
                "sensitive": sensitive, "anonymized": anon, "retention_days": days,
                "access_controls": access, "third_party": third}

    return {
        "app_name": "ShopAssist Support Chatbot",
        "controls": {
            "data_minimization": False, "consent_notice": False,
            "output_filtering": False, "deletion_procedure": False,
            "prompt_logs_stored": True, "dpa_in_place": False,
        },
        "stages": {
            "data_collection": st("Chat widget collects customer name, email and order ID before the chat starts.",
                                  "name, email, order ID, phone number", True, False, False, 365, True, False),
            "data_preprocessing": st("Chat text is cleaned and tokenised; no personal identifiers are removed.",
                                     "chat text, email, order ID", True, False, False, 90, True, False),
            "prompt_submission": st("Customer questions are sent as prompts; customers sometimes paste card or ID numbers.",
                                    "query text, payment details, delivery address", True, True, False, 365, False, False),
            "model_inference": st("A hosted language model generates the reply from the prompt and chat history.",
                                  "prompt, chat history, order details", True, False, False, 30, True, True),
            "output_generation": st("The bot shows the answer to the customer and may repeat order details.",
                                    "generated reply, order details, name", True, False, False, 365, True, False),
            "data_storage": st("Full transcripts are stored in a database for quality review and analytics.",
                               "transcripts, email, order history", True, True, False, 730, False, False),
            "data_sharing": st("Transcripts are shared with an analytics vendor to improve responses.",
                               "transcripts, email, device ID", True, False, False, 0, False, True),
            "data_deletion": st("Records are deleted manually when a customer complains; no schedule exists.",
                                "transcripts, customer profile", True, False, False, 0, False, False),
        },
    }
