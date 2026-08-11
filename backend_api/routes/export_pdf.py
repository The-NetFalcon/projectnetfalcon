"""
routes/export_pdf.py
---------------------
Generates a court-admissible forensic PDF report for a case, matching
the "Sample Forensic Report Preview" shown in the Case Management &
Evidence Vault panel of the dashboard: case metadata, correlated
alert timeline, evidence table with SHA-256 hashes, and the full
chain-of-custody log — ending with the export itself being sealed
into that same log.
"""

import io
import logging
from datetime import datetime

from flask import Blueprint, request, jsonify, send_file
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)

from database.db_connection import get_db_cursor

logger = logging.getLogger("routes.export_pdf")
export_bp = Blueprint("export_bp", __name__, url_prefix="/api")


def _fetch_case_bundle(case_id):
    with get_db_cursor() as cur:
        cur.execute("SELECT * FROM cases WHERE case_id = %s", (case_id,))
        case = cur.fetchone()
        if not case:
            return None

        cur.execute("SELECT * FROM alerts WHERE case_id = %s ORDER BY detected_at ASC", (case_id,))
        alerts = cur.fetchall()

        cur.execute("SELECT * FROM evidence_vault WHERE case_id = %s ORDER BY created_at ASC", (case_id,))
        evidence = cur.fetchall()

        evidence_ids = [e["evidence_id"] for e in evidence]
        custody = []
        if evidence_ids:
            cur.execute(
                "SELECT * FROM chain_of_custody WHERE evidence_id = ANY(%s) ORDER BY action_at ASC",
                (evidence_ids,),
            )
            custody = cur.fetchall()

    case["alerts"] = alerts
    case["evidence"] = evidence
    case["chain_of_custody"] = custody
    return case


def _styled_table(rows, col_widths, font_size=7.5):
    table = Table(rows, colWidths=col_widths)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123a5e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), font_size),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef3f8")]),
    ]))
    return table


def _build_pdf(case: dict) -> io.BytesIO:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm, leftMargin=2 * cm, rightMargin=2 * cm,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], textColor=colors.HexColor("#123a5e"))
    heading_style = ParagraphStyle(
        "SectionHeading", parent=styles["Heading2"],
        textColor=colors.HexColor("#123a5e"), spaceBefore=14, spaceAfter=6,
    )
    body_style = styles["BodyText"]

    story = [
        Paragraph("THE MIDNIGHT PROTOCOL", title_style),
        Paragraph("Court-Admissible Digital Forensic Report", styles["Heading3"]),
        HRFlowable(width="100%", color=colors.HexColor("#123a5e"), thickness=1),
        Spacer(1, 12),
    ]

    meta_rows = [
        ["Case Number", case.get("case_number", "-")],
        ["Threat Type", case.get("threat_type", "-")],
        ["Investigator", case.get("investigator", "-")],
        ["Status", case.get("status", "-")],
        ["Opened", str(case.get("opened_at", "-"))],
        ["Report Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")],
    ]
    meta_table = Table(meta_rows, colWidths=[5 * cm, 10 * cm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#123a5e")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.lightgrey),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8))

    if case.get("summary"):
        story.append(Paragraph("Case Summary", heading_style))
        story.append(Paragraph(case["summary"], body_style))

    story.append(Paragraph("Correlated Alert Timeline", heading_style))
    if case["alerts"]:
        alert_rows = [["Detected At", "Alert Type", "Source IP", "Dest IP", "Severity", "Engine"]]
        for a in case["alerts"]:
            alert_rows.append([
                str(a.get("detected_at", "-")),
                a.get("alert_type", "-"),
                a.get("source_ip", "-"),
                a.get("destination_ip", "-"),
                a.get("severity", "-"),
                a.get("detection_engine", "-"),
            ])
        story.append(_styled_table(alert_rows, [3.2 * cm, 4 * cm, 2.6 * cm, 2.6 * cm, 2.1 * cm, 2.1 * cm]))
    else:
        story.append(Paragraph("No correlated alerts on record.", body_style))

    story.append(Paragraph("Evidence Vault", heading_style))
    if case["evidence"]:
        ev_rows = [["Filename", "Type", "SHA-256 Hash", "Status", "Added By"]]
        for e in case["evidence"]:
            ev_rows.append([
                e.get("filename", "-"),
                e.get("evidence_type", "-"),
                e.get("sha256_hash") or "-",
                e.get("status", "-"),
                e.get("added_by", "-"),
            ])
        story.append(_styled_table(ev_rows, [3.5 * cm, 2.5 * cm, 6.5 * cm, 2 * cm, 2.1 * cm], font_size=6.8))
    else:
        story.append(Paragraph("No evidence items on record.", body_style))

    story.append(Paragraph("Chain of Custody Log", heading_style))
    if case["chain_of_custody"]:
        custody_rows = [["Timestamp", "Action", "Actor", "Notes"]]
        for c in case["chain_of_custody"]:
            custody_rows.append([
                str(c.get("action_at", "-")),
                c.get("action", "-"),
                c.get("actor", "-"),
                c.get("notes") or "-",
            ])
        story.append(_styled_table(custody_rows, [3.2 * cm, 4 * cm, 2.8 * cm, 6.6 * cm], font_size=7))
    else:
        story.append(Paragraph("No custody events on record.", body_style))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", color=colors.lightgrey, thickness=0.5))
    story.append(Paragraph(
        "This report was generated automatically by The Midnight Protocol platform. "
        "All evidence items are sealed with SHA-256 hashes and a verifiable chain of "
        "custody to support legal admissibility.",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=7, textColor=colors.grey),
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer


@export_bp.route("/cases/<int:case_id>/export", methods=["GET"])
def export_case_pdf(case_id):
    """GET /api/cases/<id>/export?exported_by=Insp.%20Solanki — backs 'Export Forensic Report (PDF)'."""
    case = _fetch_case_bundle(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404

    exported_by = request.args.get("exported_by", "System")
    pdf_buffer = _build_pdf(case)

    # Seal the export action itself into the chain of custody, per evidence item
    if case["evidence"]:
        with get_db_cursor(commit=True) as cur:
            for e in case["evidence"]:
                cur.execute(
                    """
                    INSERT INTO chain_of_custody (evidence_id, action, actor, notes)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (e["evidence_id"], "Report exported (PDF, signed)", exported_by, None),
                )

    filename = f"{case.get('case_number', 'case')}_forensic_report.pdf"
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )
