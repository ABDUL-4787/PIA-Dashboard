"""app.py - Streamlit interface for the GenAI Privacy Impact Assessment dashboard.

Run with:  streamlit run app.py
All state is kept in st.session_state and saved to data/assessment_state.json.
"""
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from modules import data_manager as dm
from modules import risk_engine as engine
from modules import pii_scanner as pii
from modules.report_generator import generate_pdf
from modules.workflow import (CONTROLS, LABEL_ORDER, STAGES, blank_workflow)

st.set_page_config(page_title="GenAI Privacy Impact Assessment", page_icon="🛡️", layout="wide")

LEVEL_COLORS = {"Low": "#43a047", "Medium": "#f9a825", "High": "#ef6c00", "Critical": "#c62828"}
PAGES = ["Dashboard", "Workflow Assessment", "Prompt & Output Scanner", "Risk Register", "PIA Questionnaire", "Reports & Exports"]
DATA_CATEGORIES = ["Contact details", "Customer identifiers", "Order history", "Payment information",
                   "Health information", "Chat transcripts", "Device/online identifiers", "Biometric data",
                   "Government ID numbers", "Children's data"]
IMPACTS = ["Loss of confidentiality", "Identity theft or fraud", "Unwanted profiling", "Loss of control over data",
           "Discrimination or unfair treatment", "Distress or reputational harm"]
CONCLUSIONS = ["Acceptable", "Acceptable with conditions", "Not acceptable until mitigated"]

# ------------------------------------------------------------------ styling --
st.markdown("""
<style>
.block-container {padding-top: 2rem; max-width: 1250px;}
.card {background:#fff; border:1px solid #dfe6f1; border-radius:10px; padding:14px 16px;
       box-shadow:0 1px 2px rgba(31,111,235,.06);}
.card .label {font-size:.78rem; color:#5b6b82; text-transform:uppercase; letter-spacing:.04em;}
.card .value {font-size:1.9rem; font-weight:700; color:#1f2937; line-height:1.2;}
.card .sub {font-size:.8rem; color:#6b7a90;}
.notice {background:#eef4ff; border-left:4px solid #1f6feb; padding:10px 14px; border-radius:6px;
         font-size:.9rem; color:#1f2937; margin-bottom:1rem;}
</style>""", unsafe_allow_html=True)

# ------------------------------------------------------------ session state --
S = st.session_state
if "state" not in S:
    S.state = dm.load_state()   # persisted from a previous run, or the sample
    S.form_v = 0                # bump to reset form widgets
    S.reg_v = 0                 # bump to reset the register editor
    S.pdf = None

state = S.state
state.setdefault("scans", [])

SAMPLE_PROMPT = ("Hi, my name is Priya Sharma. My email is priya.sharma@example.com and my phone is +91 98765 43210. "
                 "My card 4111 1111 1111 1111 was charged twice for order ORD-48213. Aadhaar 2345 6789 0123, OTP is 482913.")
SAMPLE_OUTPUT = ("Sure Priya Sharma, I found order ORD-48213 and will email priya.sharma@example.com. "
                 "I can see the phone number +91 98765 43210 on your profile.")


def persist():
    """Save the assessment to disk, showing a friendly error if it fails."""
    try:
        dm.save_state(S.state)
    except OSError as exc:
        st.error(f"Could not save the assessment to disk: {exc}")


def run_analysis():
    """Run the rule engine on the saved workflow + PIA form and store the findings."""
    S.state["findings"] = engine.analyze(S.state["workflow"], S.state["pia"], S.state["findings"])
    S.state["last_analyzed"] = dm.now()
    S.pdf = None
    S.reg_v += 1
    persist()


def restore_sample():
    S.state = dm.reset_state()
    S.form_v += 1
    S.reg_v += 1
    S.pdf = None


def card(label, value, sub="", color=None):
    style = f"style='color:{color}'" if color else ""
    st.markdown(f"<div class='card'><div class='label'>{label}</div>"
                f"<div class='value' {style}>{value}</div><div class='sub'>{sub}</div></div>",
                unsafe_allow_html=True)


def notice():
    st.markdown("<div class='notice'>Findings are <b>potential risks identified by predefined rules</b> "
                "using synthetic or user-entered information. They are not proof of a breach and not a "
                "certified privacy or compliance rating.</div>", unsafe_allow_html=True)


def score_explanation():
    with st.expander("How are the scores calculated?"):
        st.markdown("""
**Risk Score = Likelihood (1-5) × Impact (1-5)** → range 1-25.
Levels: **1-4 Low**, **5-9 Medium**, **10-16 High**, **17-25 Critical**.

**Overall workflow score (0-100)** = Σ (risk score × weight) ÷ (25 × number of risks) × 100

* *Inherent score*: every weight is 1.
* *Current score*: weight is 1.0 for **Pending**, 0.6 for **In Progress**, 0.2 for **Completed**, so the
  score falls as mitigation progresses.
* 0 = no risks. 100 = every risk is 5×5 and nothing is mitigated.
* Bands: ≤16 Low, 17-36 Medium, 37-64 High, above 64 Critical (the same cut-offs as the 1-25 scale).

This is a transparent planning aid, **not** a certified privacy or compliance rating.
""")


# ------------------------------------------------------------------ sidebar --
with st.sidebar:
    st.markdown("## 🛡️ GenAI PIA")
    st.caption("Privacy Impact Assessment of a Generative AI application")
    page = st.radio("Navigation", PAGES, label_visibility="collapsed")
    st.divider()
    st.caption(f"Application: **{state['workflow'].get('app_name') or '—'}**")
    st.caption(f"Last analysis: {state.get('last_analyzed', '—')}")
    with st.expander("Reset to sample data"):
        st.write("Restores the sample workflow, PIA form and 24-record risk register.")
        sure = st.checkbox("I understand my changes will be lost")
        if st.button("Restore sample assessment", disabled=not sure, width="stretch"):
            restore_sample()
            st.rerun()

findings = state["findings"]

# ---------------------------------------------------------------- dashboard --
if page == "Dashboard":
    st.title("Privacy Risk Dashboard")
    st.caption(f"{state['workflow'].get('app_name') or 'Unnamed application'} · rule-based assessment of the GenAI data lifecycle")
    notice()
    if not findings:
        st.info("No risks yet. Open **Workflow Assessment**, fill in the stages and click "
                "**Save & run analysis** (or restore the sample from the sidebar).")
    else:
        counts = engine.count_by_level(findings)
        inherent = engine.overall_score(findings)
        current = engine.overall_score(findings, residual=True)
        done = sum(f["status"] == "Completed" for f in findings)
        prog = sum(f["status"] == "In Progress" for f in findings)

        cols = st.columns(5)
        with cols[0]: card("Total risks", len(findings), "identified potential risks")
        for col, lvl in zip(cols[1:], engine.LEVEL_ORDER):
            with col: card(f"{lvl} risk", counts[lvl], "findings", LEVEL_COLORS[lvl])
        st.write("")
        cols = st.columns(4)
        with cols[0]: card("Overall risk score (current)", f"{current}/100", engine.overall_label(current), LEVEL_COLORS[engine.overall_label(current)])
        with cols[1]: card("Inherent score", f"{inherent}/100", "before any mitigation")
        with cols[2]: card("Mitigation completed", f"{done}/{len(findings)}", "risks with finished actions")
        with cols[3]: card("Mitigation in progress", prog, f"{len(findings) - done - prog} still pending")
        st.write("")
        score_explanation()

        df = dm.findings_dataframe(findings)
        c1, c2 = st.columns([1, 1])
        with c1:
            st.subheader("Risk distribution")
            dist = pd.DataFrame({"Level": engine.LEVEL_ORDER, "Count": [counts[l] for l in engine.LEVEL_ORDER]})
            fig = px.pie(dist, names="Level", values="Count", hole=0.55, color="Level", color_discrete_map=LEVEL_COLORS)
            fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=340, paper_bgcolor="white")
            st.plotly_chart(fig, width="stretch")
        with c2:
            st.subheader("Overall score gauge")
            fig = go.Figure(go.Indicator(mode="gauge+number", value=current,
                gauge={"axis": {"range": [0, 100]}, "bar": {"color": "#1f6feb"},
                       "steps": [{"range": [0, 16], "color": "#c8e6c9"}, {"range": [16, 36], "color": "#fff3c4"},
                                 {"range": [36, 64], "color": "#ffd9b3"}, {"range": [64, 100], "color": "#f4b6b6"}]}))
            fig.update_layout(margin=dict(t=30, b=10, l=30, r=30), height=340, paper_bgcolor="white")
            st.plotly_chart(fig, width="stretch")

        st.subheader("Privacy risks by GenAI lifecycle stage")
        by_stage = df.groupby(["lifecycle_stage", "risk_level"]).size().reset_index(name="Count")
        fig = px.bar(by_stage, x="lifecycle_stage", y="Count", color="risk_level", color_discrete_map=LEVEL_COLORS,
                     category_orders={"lifecycle_stage": LABEL_ORDER, "risk_level": engine.LEVEL_ORDER},
                     labels={"lifecycle_stage": "Lifecycle stage", "risk_level": "Level"})
        fig.update_layout(height=380, margin=dict(t=10, b=10), paper_bgcolor="white", plot_bgcolor="white")
        st.plotly_chart(fig, width="stretch")

        st.subheader("Top 5 risks")
        top = df.sort_values("risk_score", ascending=False).head(5)
        st.dataframe(top[["risk_id", "risk_title", "lifecycle_stage", "risk_score", "risk_level", "status"]],
                     hide_index=True, width="stretch")

# ------------------------------------------------------ workflow assessment --
elif page == "Workflow Assessment":
    st.title("GenAI Workflow Assessment")
    st.caption("Describe how data moves through the application. Editing these answers changes the findings.")
    notice()
    b1, b2, _ = st.columns([1, 1, 3])
    if b1.button("Load sample chatbot", width="stretch"):
        from modules.workflow import sample_workflow
        S.state["workflow"] = sample_workflow()
        S.form_v += 1
        persist()
        st.rerun()
    if b2.button("Start blank workflow", width="stretch"):
        S.state["workflow"] = blank_workflow()
        S.form_v += 1
        persist()
        st.rerun()

    wf, v = state["workflow"], S.form_v
    with st.form(f"wf_form_{v}"):
        app_name = st.text_input("Application name *", wf.get("app_name", ""), key=f"w{v}_app")
        st.markdown("**Application-wide privacy practices**")
        ctl = {}
        for k, label in CONTROLS.items():
            ctl[k] = st.checkbox(label, wf["controls"].get(k, False), key=f"w{v}_c_{k}")
        st.markdown("**Lifecycle stages**")
        tabs = st.tabs([label for _, label, _ in STAGES])
        stages = {}
        for tab, (key, label, _) in zip(tabs, STAGES):
            cur = wf["stages"][key]
            with tab:
                k = f"w{v}_{key}"
                desc = st.text_area("Description of the activity", cur["description"], key=f"{k}_d", height=80)
                types = st.text_input("Types of data processed (comma separated)", cur["data_types"], key=f"{k}_t")
                a, b, c = st.columns(3)
                personal = a.checkbox("Personal data involved", cur["personal"], key=f"{k}_p")
                sensitive = b.checkbox("Sensitive data involved", cur["sensitive"], key=f"{k}_s")
                anon = c.checkbox("Data is anonymized", cur["anonymized"], key=f"{k}_a")
                d, e, f = st.columns(3)
                days = d.number_input("Retention period (days, 0 = not defined)", 0, 36500,
                                      int(cur["retention_days"]), step=1, key=f"{k}_r")
                access = e.checkbox("Access controls implemented", cur["access_controls"], key=f"{k}_ac")
                third = f.checkbox("Shared with third parties", cur["third_party"], key=f"{k}_3")
                stages[key] = {"description": desc.strip(), "data_types": types.strip(), "personal": personal,
                               "sensitive": sensitive, "anonymized": anon, "retention_days": int(days),
                               "access_controls": access, "third_party": third}
        s1, s2 = st.columns(2)
        save_only = s1.form_submit_button("Save workflow", width="stretch")
        save_run = s2.form_submit_button("Save & run analysis", type="primary", width="stretch")

    if save_only or save_run:
        errors, notes = [], []
        if not app_name.strip():
            errors.append("Application name is required.")
        for key, label, _ in STAGES:
            s_ = stages[key]
            if s_["sensitive"] and not s_["personal"]:
                s_["personal"] = True      # sensitive data is always personal data
                notes.append(f"{label}: sensitive data implies personal data, so 'Personal data' was ticked.")
            if s_["personal"] and not s_["data_types"]:
                errors.append(f"{label}: list the types of data processed when personal data is involved.")
        if errors:
            for e_ in errors:
                st.error(e_)
        else:
            S.state["workflow"] = {"app_name": app_name.strip(), "controls": ctl, "stages": stages}
            persist()
            for n_ in notes:
                st.warning(n_)
            if save_run:
                run_analysis()
                st.success(f"Workflow saved. {len(S.state['findings'])} potential risks identified - see the Risk Register.")
            else:
                st.success("Workflow saved. Click **Save & run analysis** to refresh the risk findings.")

# ------------------------------------------------ prompt & output scanner --
elif page == "Prompt & Output Scanner":
    st.title("Prompt & Output Privacy Scanner")
    st.caption("Runtime safeguards for a deployed GenAI app: sanitize user prompts before they reach the model and "
               "filter model outputs before they reach the user. Rule-based (regex + Luhn checksum), no AI model.")
    st.markdown("<div class='notice'>Paste <b>synthetic text only</b>. Raw text is never saved; only counts and "
                "scores are stored as assessment evidence.</div>", unsafe_allow_html=True)
    S.setdefault("scan_prompt", "")
    S.setdefault("scan_output", "")

    def load_example():
        S.scan_prompt, S.scan_output = SAMPLE_PROMPT, SAMPLE_OUTPUT

    def clear_text():
        S.scan_prompt, S.scan_output, S.scan_result = "", "", None

    b1, b2, _ = st.columns([1.3, 1, 3])
    b1.button("Load synthetic example", on_click=load_example, width="stretch")
    b2.button("Clear", on_click=clear_text, width="stretch")
    c1, c2 = st.columns(2)
    prompt = c1.text_area("User prompt (input to the model)", key="scan_prompt", height=170)
    output = c2.text_area("Model output (reply to the user)", key="scan_output", height=170)

    if st.button("Scan text", type="primary"):
        if not prompt.strip() and not output.strip():
            st.warning("Enter a prompt, an output, or load the synthetic example first.")
        else:
            res = {"prompt": pii.scan(prompt) if prompt.strip() else None,
                   "output": pii.scan(output) if output.strip() else None, "time": dm.now()}
            for name, key in (("Prompt", "prompt"), ("Output", "output")):
                if res[key]:
                    S.state["scans"].append(pii.summary(name, res[key], res["time"]))
            S.state["scans"] = S.state["scans"][-20:]
            S.scan_result = res
            persist()

    res = S.get("scan_result")
    if res:
        for title, key in (("Prompt scan", "prompt"), ("Output scan", "output")):
            r = res[key]
            if not r:
                continue
            st.subheader(title)
            m = st.columns(4)
            m[0].metric("Items found", len(r["entities"]))
            m[1].metric("Sensitive", r["sensitive"])
            m[2].metric("Personal", r["personal"])
            m[3].metric("Exposure score", f"{r['exposure_score']}/100", r["level"], delta_color="off")
            if r["entities"]:
                st.dataframe(pd.DataFrame(r["entities"])[["type", "category", "text"]], hide_index=True, width="stretch")
                st.markdown("**Redacted text (safe to send / display):**")
                st.code(r["redacted"], language=None, wrap_lines=True)
                st.caption(f"Exposure score after redaction: {r['after_redaction_score']}/100")
            else:
                st.success("No personal data patterns detected by the rules.")
        st.divider()
        st.markdown("**Use this result as evidence in the assessment.** Sensitive data in the test prompt raises "
                    "risk PR02, and personal data repeated in the output raises risk PR03 (likelihood set to 5).")
        if st.button("Apply scan evidence to Risk Register"):
            changed = engine.apply_scan_evidence(S.state["findings"], res["prompt"], res["output"], res["time"])
            if changed:
                persist()
                S.pdf = None
                S.reg_v += 1
                st.success("Updated risks: " + ", ".join(changed) + ". See the Risk Register and Dashboard.")
            else:
                st.info("No matching risks (PR02-PRM / PR03-OUT) in the register, or no qualifying data was found. "
                        "Run the workflow analysis first.")
    else:
        st.info("No scan yet. Click **Load synthetic example**, then **Scan text**.")
    st.caption("Limitations: pattern-based detection finds structured identifiers (emails, phones, cards, ID formats) "
               "but not every name, address or free-text disclosure.")

# ------------------------------------------------------------ risk register --
elif page == "Risk Register":
    st.title("Risk Register")
    notice()
    if not findings:
        st.info("The register is empty. Run an analysis from the Workflow Assessment page "
                "or restore the sample assessment from the sidebar.")
    else:
        tab_reg, tab_mit = st.tabs(["Register & scoring", "Mitigation tracker"])
        df_all = dm.findings_dataframe(findings)

        with tab_reg:
            f1, f2, f3 = st.columns(3)
            lv = f1.multiselect("Risk level", engine.LEVEL_ORDER)
            sg = f2.multiselect("Lifecycle stage", LABEL_ORDER)
            stt = f3.multiselect("Status", engine.STATUSES)
            view = df_all
            if lv: view = view[view.risk_level.isin(lv)]
            if sg: view = view[view.lifecycle_stage.isin(sg)]
            if stt: view = view[view.status.isin(stt)]
            st.caption("Edit **likelihood**, **impact** or **status** directly in the table. "
                       "Score and level update automatically.")
            cols = ["risk_id", "risk_title", "lifecycle_stage", "data_involved", "likelihood", "impact",
                    "risk_score", "risk_level", "status"]
            if view.empty:
                st.warning("No risks match the selected filters.")
            else:
                edited = st.data_editor(
                    view[cols], hide_index=True, width="stretch", key=f"reg_{S.reg_v}",
                    disabled=[c for c in cols if c not in ("likelihood", "impact", "status")],
                    column_config={
                        "likelihood": st.column_config.NumberColumn("Likelihood", min_value=1, max_value=5, step=1),
                        "impact": st.column_config.NumberColumn("Impact", min_value=1, max_value=5, step=1),
                        "status": st.column_config.SelectboxColumn("Status", options=engine.STATUSES, required=True),
                        "risk_score": "Score", "risk_level": "Level", "risk_id": "Risk ID",
                        "risk_title": "Risk title", "lifecycle_stage": "Stage", "data_involved": "Data involved"})
                by_id = {f["risk_id"]: f for f in S.state["findings"]}
                changed = False
                for rec in edited.to_dict("records"):
                    f = by_id[rec["risk_id"]]
                    try:
                        new_l, new_i = engine.clamp(rec["likelihood"]), engine.clamp(rec["impact"])
                    except Exception:
                        continue
                    if (new_l, new_i) != (f["likelihood"], f["impact"]):
                        f["likelihood"], f["impact"], f["adjusted"] = new_l, new_i, True
                        engine.finalize(f)
                        changed = True
                    if rec["status"] in engine.STATUSES and rec["status"] != f["status"]:
                        f["status"] = rec["status"]
                        changed = True
                if changed:
                    persist()
                    S.pdf = None
                    S.reg_v += 1
                    st.rerun()

            st.subheader("Risk details")
            pick = st.selectbox("Select a risk", [f"{f['risk_id']} - {f['risk_title']}" for f in findings])
            f = next(x for x in findings if x["risk_id"] == pick.split(" - ")[0])
            with st.container(border=True):
                st.markdown(f"**{f['risk_id']} · {f['risk_title']}**  \n"
                            f"Stage: {f['lifecycle_stage']} · Data: {f['data_involved']}")
                st.markdown(f"**Description:** {f['risk_description']}")
                st.markdown(f"**Likelihood {f['likelihood']} × Impact {f['impact']} = {f['risk_score']} → "
                            f"{f['risk_level']}**" + (" _(manually adjusted)_" if f.get("adjusted") else ""))
                if f.get("evidence"):
                    st.markdown(f"**Evidence:** {f['evidence']}")
                st.markdown(f"**Recommended mitigation:** {f['mitigation']}")
                st.caption("Potential risk identified by predefined rules; not proof of a breach.")
            score_explanation()

        with tab_mit:
            done = sum(x["status"] == "Completed" for x in findings)
            st.progress(done / len(findings), text=f"{done} of {len(findings)} mitigation actions completed")

            def set_status(rid, key):
                for x in S.state["findings"]:
                    if x["risk_id"] == rid:
                        x["status"] = S[key]
                S.pdf = None
                S.reg_v += 1
                persist()

            for f in sorted(findings, key=lambda x: -x["risk_score"]):
                with st.container(border=True):
                    a, b = st.columns([4, 1.2])
                    a.markdown(f"**{f['risk_id']} · {f['risk_title']}**  \n"
                               f"{f['lifecycle_stage']} · score {f['risk_score']} ({f['risk_level']})")
                    for action in [x.strip() for x in f["mitigation"].split(";") if x.strip()]:
                        a.markdown(f"- {action}")
                    key = f"st_{f['risk_id']}_{S.reg_v}"
                    b.selectbox("Status", engine.STATUSES, index=engine.STATUSES.index(f["status"]),
                                key=key, on_change=set_status, args=(f["risk_id"], key))

# -------------------------------------------------------- PIA questionnaire --
elif page == "PIA Questionnaire":
    st.title("Privacy Impact Assessment Questionnaire")
    st.caption("A generic PIA template informed by common privacy principles (purpose, minimization, "
               "retention, security, transparency). It does not guarantee compliance with GDPR, India's DPDP Act or any other law.")
    pia, v = state["pia"], S.form_v
    with st.form(f"pia_form_{v}"):
        k = f"p{v}_"
        app_name = st.text_input("Application name *", state["workflow"].get("app_name", ""), key=k + "app")
        purpose = st.text_area("Business purpose *", pia["business_purpose"], key=k + "bp", height=70)
        a, b = st.columns(2)
        owner = a.text_input("Application owner *", pia["owner"], key=k + "own")
        users = b.text_input("Intended users", pia["intended_users"], key=k + "usr")
        cats = st.multiselect("Categories of data processed", sorted(set(DATA_CATEGORIES) | set(pia["data_categories"])),
                              pia["data_categories"], key=k + "cat")
        proc = st.text_area("Purpose of data processing", pia["processing_purpose"], key=k + "pp", height=70)
        c, d = st.columns(2)
        coll = c.text_area("Data collection methods", pia["collection_methods"], key=k + "cm", height=80)
        stor = d.text_area("Data storage and retention", pia["storage_retention"], key=k + "sr", height=80)
        third = st.text_area("Third-party integrations", pia["third_party_integrations"], key=k + "tp", height=70)
        imp = st.multiselect("Potential impacts on individuals", IMPACTS, [i for i in pia["impacts"] if i in IMPACTS], key=k + "imp")
        risks = st.text_area("Identified privacy risks (your summary)", pia["identified_risks"], key=k + "ir", height=70)
        mit = st.text_area("Proposed mitigation measures", pia["mitigation_measures"], key=k + "mm", height=70)
        res = st.text_area("Residual risks", pia["residual_risks"], key=k + "rr", height=70)
        conc = st.selectbox("Assessment conclusion", CONCLUSIONS,
                            index=CONCLUSIONS.index(pia["conclusion"]) if pia["conclusion"] in CONCLUSIONS else 1, key=k + "con")
        cnotes = st.text_area("Conclusion notes", pia["conclusion_notes"], key=k + "cn", height=70)
        s1, s2 = st.columns(2)
        save_only = s1.form_submit_button("Save questionnaire", width="stretch")
        analyze = s2.form_submit_button("Analyze assessment & generate findings", type="primary", width="stretch")

    if save_only or analyze:
        missing = [n for n, val in [("Application name", app_name), ("Business purpose", purpose),
                                    ("Application owner", owner)] if not val.strip()]
        if missing:
            st.error("Please complete required fields: " + ", ".join(missing) + ".")
        else:
            S.state["workflow"]["app_name"] = app_name.strip()
            S.state["pia"] = {"business_purpose": purpose.strip(), "owner": owner.strip(), "intended_users": users.strip(),
                              "data_categories": cats, "processing_purpose": proc.strip(), "collection_methods": coll.strip(),
                              "storage_retention": stor.strip(), "third_party_integrations": third.strip(), "impacts": imp,
                              "identified_risks": risks.strip(), "mitigation_measures": mit.strip(),
                              "residual_risks": res.strip(), "conclusion": conc, "conclusion_notes": cnotes.strip()}
            persist()
            if analyze:
                run_analysis()
                st.success(f"Analysis complete: {len(S.state['findings'])} potential risks. See the Risk Register or Dashboard.")
            else:
                st.success("Questionnaire saved.")

# ------------------------------------------------------- reports & exports --
else:
    st.title("Reports & Exports")
    notice()
    if not findings:
        st.info("Nothing to export yet. Run an analysis or restore the sample assessment first.")
    else:
        cur = engine.overall_score(findings, residual=True)
        st.write(f"The report will contain **{len(findings)} risks** for "
                 f"**{state['workflow'].get('app_name') or 'Unnamed application'}** "
                 f"with a current overall score of **{cur}/100 ({engine.overall_label(cur)})**.")
        st.subheader("PDF report")
        if st.button("Generate PDF report", type="primary"):
            try:
                S.state["report_time"] = dm.now()
                S.pdf = generate_pdf(S.state)
            except Exception as exc:
                S.pdf = None
                st.error(f"Could not create the PDF: {exc}")
        if S.pdf:
            st.download_button("⬇️ Download PIA report (PDF)", S.pdf, "pia_report.pdf", "application/pdf")
        st.subheader("Data exports")
        c1, c2 = st.columns(2)
        c1.download_button("⬇️ Risk register (CSV)", dm.export_csv(findings), "privacy_risks.csv", "text/csv", width="stretch")
        c2.download_button("⬇️ Risk register (JSON)", dm.export_json(findings, state["workflow"].get("app_name", "")),
                           "privacy_risks.json", "application/json", width="stretch")
        st.subheader("Preview")
        st.dataframe(dm.findings_dataframe(findings), hide_index=True, width="stretch")
