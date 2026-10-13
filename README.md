# Privacy Impact Assessment of a Generative AI Application

A local Streamlit dashboard that identifies, scores, tracks and documents privacy risks across the data
lifecycle of a Generative AI application. It is **rule-based** (no external AI, no API keys, no internet)
and uses **synthetic data only**.

> Findings are *potential risks identified by predefined rules*, not proof of a breach. Scores are a
> planning aid, **not** a certified privacy or compliance rating. The PIA template follows general privacy
> principles and does not guarantee compliance with GDPR, India's DPDP Act or any other law.

## Problem statement
GenAI applications handle personal data at many points (collection, prompts, model inference, logs, sharing,
deletion). Organizations need a simple, repeatable way to check these risks *before* deployment.

## Objectives
1. Model the 8 lifecycle stages of a GenAI application.
2. Detect common privacy risks with transparent rules.
3. Score risks (Likelihood × Impact) and an overall 0-100 score.
4. Track mitigation (Pending / In Progress / Completed).
5. Export a PDF PIA report plus CSV and JSON.

## Features
Dashboard · Workflow assessment (8 stages) · **Prompt & Output Scanner** (runtime PII detection and redaction) · · Rule-based risk detection (10 rules + 1 consistency check) ·
Editable scoring · PIA questionnaire · Mitigation tracker · PDF/CSV/JSON export · 24-record synthetic dataset ·
Persistence between runs · Reset to sample.

## Research gap addressed
The reference paper (*Navigating Privacy Risks in Generative AI*, Yang, 2026) recommends, in its deployment
section, that runtime systems **sanitize user inputs** and use **output filtering** to block sensitive data, plus
**regular privacy audits**. The paper treats this only as advice and focuses on model-level defenses
(differential privacy, federated learning) that need training infrastructure.
This project closes the practical gap with a **Prompt & Output Scanner**:
1. Paste a (synthetic) prompt and model output; rules detect emails, phones, Luhn-valid card numbers,
   Aadhaar/PAN-format IDs, OTP/CVV/passwords, dates of birth, IPs and self-introduced names.
2. Each text gets an **exposure score** = min(100, 25 × sensitive items + 10 × personal items).
3. A redacted version is produced and re-scanned (score after redaction should be 0).
4. **Apply scan evidence** raises risk PR02 (sensitive data in prompts) and PR03 (leakage via outputs) to
   likelihood 5 in the register, with the evidence shown in the risk details and the PDF report.
Only counts and scores are saved, never the raw text. Limitation: pattern matching cannot catch every
name, address or free-text disclosure.

## Technology stack
Python · Streamlit · Pandas · Plotly · ReportLab · JSON/CSV storage.

## Project structure and architecture
```
app.py                    Streamlit UI (5 pages, sidebar navigation, session state)
modules/workflow.py       Lifecycle stages, practice checklist, sample/blank workflow
modules/risk_engine.py    Rules, scoring, levels, overall score, merge, scan-evidence update
modules/pii_scanner.py    Regex + Luhn detection and redaction of PII in prompts/outputs
modules/data_manager.py   Synthetic dataset, JSON persistence, CSV/JSON export
modules/report_generator.py  PDF report (ReportLab) built from the current state
data/sample_risks.csv     Synthetic dataset (24 records)
data/assessment_state.json  Saved assessment (created automatically on first run)
tests/test_app.py         Automated tests (pytest)
.streamlit/config.toml    Light theme with blue accent
```
Flow: *UI form → workflow dict → risk_engine.analyze() → findings list → saved JSON → dashboard / register / PDF / exports.*

## Risk scoring methodology
* **Risk Score = Likelihood (1-5) × Impact (1-5)**
* Levels: 1-4 Low · 5-9 Medium · 10-16 High · 17-25 Critical
* Likelihood and impact start from rule defaults (higher if sensitive data, no anonymization, no controls)
  and can be edited by the user in the Risk Register.
* **Overall score (0-100)** = Σ(risk score × weight) ÷ (25 × number of risks) × 100.
  * *Inherent* score: weight = 1 for all risks.
  * *Current* score: weight = 1.0 Pending, 0.6 In Progress, 0.2 Completed, so mitigation lowers it.
  * Bands: ≤16 Low, 17-36 Medium, 37-64 High, >64 Critical.

### Rules
| Rule | Detects | Trigger (simplified) |
|---|---|---|
| PR01 | Unnecessary data collection | personal data collected, no data-minimization |
| PR02 | Sensitive data in prompts | sensitive prompt data, not anonymized |
| PR03 | Leakage via outputs | personal data in output stage, no output filtering |
| PR04 | Inadequate anonymization | personal data not anonymized (preprocessing / prompt / inference) |
| PR05 | Excessive retention | personal data, retention undefined or > 180 days |
| PR06 | Unauthorized access | personal data, no access controls |
| PR07 | Third-party sharing | personal data shared externally (higher risk without agreement) |
| PR08 | No deletion procedure | personal data, no documented deletion procedure |
| PR09 | Prompt logging exposure | prompt logs stored with personal data |
| PR10 | Unclear consent/usage | no privacy notice, or purpose missing in PIA form |
| PR11 | Classification mismatch | PIA lists sensitive categories but no stage marked sensitive |

Risk IDs look like `PR06-STO` (rule + stage), so a risk keeps its ID, status and manual scores when you re-run the analysis.

## Dataset
`data/sample_risks.csv` has 24 synthetic records for a fictional chatbot ("ShopAssist") covering all 8 stages
and all four risk levels. Columns: risk_id, application_name, lifecycle_stage, data_category, risk_title,
risk_description, data_involved, likelihood, impact, risk_score, risk_level, mitigation, status.
It is generated by `data_manager.build_sample_dataframe()` if the file is missing. No real personal data is used.
The sample is the *starting* register; running the analysis replaces it with rule-based findings for the current workflow.

## Installation and running
```
pip install -r requirements.txt
streamlit run app.py
```
Run tests: `python -m pytest -q`

## Example workflow for testing
1. Open **Dashboard** - the sample register (24 risks) is shown.
2. **Workflow Assessment** → *Save & run analysis* - 19 rule-based findings appear.
3. Tick "documented deletion procedure" and "Data is anonymized" for Prompt submission → analyze again; PR08 and PR02 disappear.
3b. **Prompt & Output Scanner** → *Load synthetic example* → *Scan text* → *Apply scan evidence to Risk Register*.
4. **Risk Register** → change a likelihood/impact; score and level update. Open **Mitigation tracker** and set a status.
5. **Dashboard** - the current score falls as mitigations progress.
6. **PIA Questionnaire** → fill and analyze. **Reports & Exports** → generate the PDF, download CSV and JSON.
7. Sidebar → *Restore sample assessment* resets everything.

## Limitations and future enhancements
* Rules are simplified; likelihood/impact are estimates, not measurements.
* One assessment at a time, stored in a local JSON file; single user, no authentication.
* Future: multiple assessments, custom rules, PII-detection on sample text, version history, charts in the PDF, mapping to specific legal clauses.

## Suggested viva questions
1. **What is a PIA?** A structured process to identify and reduce privacy risks of a system before deployment.
2. **Why is a GenAI app special?** Prompts and logs can contain personal data, models may echo it in outputs, and third-party hosting is common.
3. **Is AI used to find the risks?** No. Transparent if-then rules are used so every finding can be explained.
4. **How is risk calculated?** Likelihood × Impact (1-25), mapped to Low/Medium/High/Critical.
5. **How is the 0-100 score derived?** Sum of weighted risk scores divided by the maximum possible (25 per risk) × 100; mitigation status lowers the weights.
6. **Does a low score mean legal compliance?** No. It is a planning aid, not a certification.
7. **What is data minimization?** Collecting only the data needed for the stated purpose.
8. **Anonymization vs pseudonymization?** Anonymized data cannot be linked back to a person; pseudonymized data can, using separate extra information.
9. **How do you reduce leakage through outputs?** Limit the context sent to the model, filter/mask outputs, test for disclosure.
10. **How is data kept between runs?** In `data/assessment_state.json`, written after every change.
11. **Which paper gap did you address?** The paper recommends input sanitization and output filtering but gives no implementation; the scanner implements and measures both and feeds the evidence into the risk register.
12. **What are the limitations?** Rule coverage, subjective scores, no real system scan, not legal advice.
