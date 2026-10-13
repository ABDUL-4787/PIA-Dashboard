"""report_generator.py - Builds the downloadable PDF PIA report with ReportLab.

The report is generated from the CURRENT assessment state, so it always
contains the actual results (not a static template).
"""
import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

from modules import risk_engine as engine
from modules.workflow import STAGES, CONTROLS

BLUE = colors.HexColor("#1f6feb")
LIGHT = colors.HexColor("#eef4ff")
LEVEL_COLORS = {"Low": "#2e7d32", "Medium": "#b7791f", "High": "#d9480f", "Critical": "#c62828"}


def _p(text, style):
    """Paragraph with safe (escaped) text."""
    return Paragraph(escape(str(text if text not in (None, "") else "Not provided")), style)


def _table(data, widths, header=True):
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d3e3")),
             ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), BLUE), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
    t.setStyle(TableStyle(style))
    return t


def generate_pdf(state):
    """Return the PIA report as PDF bytes."""
    wf, pia, findings = state["workflow"], state["pia"], state["findings"]
    app = wf.get("app_name") or "Unnamed application"
    inherent = engine.overall_score(findings)
    current = engine.overall_score(findings, residual=True)
    counts = engine.count_by_level(findings)
    open_risks = [f for f in findings if f["status"] != "Completed"]

    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["Normal"], fontSize=9.5, leading=13)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10)
    cell_w = ParagraphStyle("cellw", parent=small, textColor=colors.white, fontName="Helvetica-Bold")
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], textColor=BLUE, fontSize=14, spaceBefore=12, spaceAfter=6)
    title = ParagraphStyle("title", parent=ss["Title"], textColor=BLUE, fontSize=22)

    def hdr(*labels):
        return [Paragraph(escape(x), cell_w) for x in labels]

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=1.8 * cm, rightMargin=1.8 * cm,
                            topMargin=1.8 * cm, bottomMargin=1.8 * cm,
                            title=f"Privacy Impact Assessment - {app}")
    s = []

    # Cover / 1. project details
    s += [Spacer(1, 1.5 * cm), Paragraph("Privacy Impact Assessment Report", title),
          Paragraph(escape(f"Generative AI Application: {app}"), ss["Heading2"]),
          Spacer(1, 0.4 * cm)]
    details = [("Application name", app), ("Business purpose", pia.get("business_purpose")),
               ("Application owner", pia.get("owner")), ("Intended users", pia.get("intended_users")),
               ("Data categories", ", ".join(pia.get("data_categories", []))),
               ("Report generated", state.get("report_time", "")),
               ("Last analysis", state.get("last_analyzed", ""))]
    s.append(Paragraph("1. Project and Application Details", h1))
    s.append(_table([[_p(k, small), _p(v, small)] for k, v in details], [4.5 * cm, 12.9 * cm], header=False))
    s.append(Spacer(1, 0.3 * cm))
    s.append(_p("Notice: findings are POTENTIAL risks identified by predefined rules using synthetic or "
                "user-entered information. They are not proof of a breach, and this report is not a "
                "certified privacy or legal-compliance rating.", small))

    # 2. Executive summary
    s.append(Paragraph("2. Executive Summary", h1))
    summary = (f"The assessment identified {len(findings)} potential privacy risks: {counts['Critical']} critical, "
               f"{counts['High']} high, {counts['Medium']} medium and {counts['Low']} low. The inherent overall "
               f"risk score is {inherent}/100 ({engine.overall_label(inherent)}). After accounting for mitigation "
               f"progress the current score is {current}/100 ({engine.overall_label(current)}). "
               f"{len(findings) - len(open_risks)} of {len(findings)} mitigation actions are completed and "
               f"{len(open_risks)} remain open.")
    s.append(_p(summary if findings else "No risks have been identified yet. Run the analysis first.", body))

    # 3. Methodology
    s.append(Paragraph("3. Assessment Methodology", h1))
    for line in ["Workflow answers for eight lifecycle stages are checked against predefined if-then rules.",
                 "Risk Score = Likelihood (1-5) x Impact (1-5). Levels: 1-4 Low, 5-9 Medium, 10-16 High, 17-25 Critical.",
                 "Overall score (0-100) = sum of (risk score x weight) / (25 x number of risks) x 100. Weight is 1.0 "
                 "for the inherent score; for the current score it is 1.0 Pending, 0.6 In Progress, 0.2 Completed.",
                 "Likelihood and impact may be reviewed and adjusted manually by the assessor."]:
        s.append(_p("- " + line, body))

    # 4. Lifecycle overview
    s.append(Paragraph("4. GenAI Data Lifecycle Overview", h1))
    rows = [hdr("Stage", "Data types", "Personal", "Sensitive", "Anonym.", "Retention", "Access", "3rd party")]
    yn = lambda v: "Yes" if v else "No"
    for key, label, _ in STAGES:
        st = wf["stages"].get(key, {})
        days = st.get("retention_days") or 0
        rows.append([_p(label, small), _p(st.get("data_types"), small), yn(st.get("personal")),
                     yn(st.get("sensitive")), yn(st.get("anonymized")),
                     f"{days} d" if days else "Not defined", yn(st.get("access_controls")), yn(st.get("third_party"))])
    s.append(_table(rows, [3.4 * cm, 4.4 * cm, 1.5 * cm, 1.6 * cm, 1.5 * cm, 1.8 * cm, 1.4 * cm, 1.6 * cm]))
    present = [CONTROLS[k] for k, v in wf["controls"].items() if v]
    s.append(Spacer(1, 0.2 * cm))
    s.append(_p("Practices confirmed in place: " + ("; ".join(present) if present else "none"), small))

    # 5/6. Risks and scores
    s.append(PageBreak())
    s.append(Paragraph("5. Identified Privacy Risks and 6. Scores and Severity", h1))
    if findings:
        rows = [hdr("ID", "Risk", "Stage", "L", "I", "Score", "Level", "Status")]
        for f in findings:
            lvl = f"<font color='{LEVEL_COLORS[f['risk_level']]}'><b>{f['risk_level']}</b></font>"
            rows.append([_p(f["risk_id"], small), _p(f["risk_title"], small), _p(f["lifecycle_stage"], small),
                         f["likelihood"], f["impact"], f["risk_score"], Paragraph(lvl, small), _p(f["status"], small)])
        s.append(_table(rows, [2.1 * cm, 5.2 * cm, 3.3 * cm, 0.7 * cm, 0.7 * cm, 1.1 * cm, 1.7 * cm, 2.1 * cm]))
        s.append(Spacer(1, 0.3 * cm))
        for f in findings:
            s.append(_p(f"{f['risk_id']}: {f['risk_description']} (Data: {f['data_involved']})", small))
    else:
        s.append(_p("No risks identified.", body))

    # Supporting evidence from prompt/output scans (only if scans were run)
    scans = state.get("scans", [])
    ev = [f for f in findings if f.get("evidence")]
    if scans or ev:
        s.append(Paragraph("Supporting evidence: prompt and output scans", ss["Heading3"]))
        if scans:
            rows = [hdr("Time", "Target", "Sensitive", "Personal", "Exposure", "After redaction")]
            for sc in scans[-10:]:
                rows.append([_p(sc["time"], small), _p(sc["target"], small), sc["sensitive"], sc["personal"],
                             f"{sc['exposure_score']}/100", f"{sc['after_redaction_score']}/100"])
            s.append(_table(rows, [3.4 * cm, 2.2 * cm, 2.2 * cm, 2.2 * cm, 2.6 * cm, 3.0 * cm]))
        for f in ev:
            s.append(_p(f"{f['risk_id']}: {f['evidence']}", small))

    # 7. Mitigation
    s.append(Paragraph("7. Recommended Mitigation Measures", h1))
    if findings:
        rows = [hdr("ID", "Recommended mitigation", "Status")]
        rows += [[_p(f["risk_id"], small), _p(f["mitigation"], small), _p(f["status"], small)] for f in findings]
        s.append(_table(rows, [2.3 * cm, 12.0 * cm, 3.0 * cm]))

    # 8. Residual
    s.append(Paragraph("8. Residual Risks and Outstanding Actions", h1))
    s.append(_p("Assessor's residual risk notes: " + str(pia.get("residual_risks") or "Not provided"), body))
    s.append(Spacer(1, 0.2 * cm))
    if open_risks:
        rows = [hdr("ID", "Outstanding action", "Level", "Status")]
        rows += [[_p(f["risk_id"], small), _p(f["risk_title"], small), _p(f["risk_level"], small),
                  _p(f["status"], small)] for f in open_risks]
        s.append(_table(rows, [2.3 * cm, 9.5 * cm, 2.5 * cm, 3.0 * cm]))
    else:
        s.append(_p("All mitigation actions are marked completed.", body))

    # 9. Conclusion
    s.append(Paragraph("9. Overall Assessment Conclusion", h1))
    crit_open = sum(1 for f in open_risks if f["risk_level"] == "Critical")
    auto = (f"Current overall risk score: {current}/100 ({engine.overall_label(current)}). "
            f"{crit_open} critical risk(s) remain open.")
    s.append(_p(auto, body))
    s.append(_p("Assessor conclusion: " + str(pia.get("conclusion") or "Not provided") + ". "
                + str(pia.get("conclusion_notes") or ""), body))

    # 10. Limitations
    s.append(Paragraph("10. Assessment Limitations", h1))
    for line in ["Rule-based and simplified: it checks only the predefined rules and the answers entered.",
                 "Likelihood and impact values are estimates and should be reviewed by a privacy professional.",
                 "No real personal data, system scan or penetration test was used.",
                 "The template follows general privacy principles but does not guarantee compliance with GDPR, "
                 "India's DPDP Act or any other law.",
                 "The scores are not a certified privacy or compliance rating."]:
        s.append(_p("- " + line, body))

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawString(1.8 * cm, 1.0 * cm, f"PIA Report - {app}")
        canvas.drawRightString(A4[0] - 1.8 * cm, 1.0 * cm, f"Page {d.page}")
        canvas.restoreState()

    doc.build(s, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
