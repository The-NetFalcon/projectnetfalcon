import io
import sqlite3
from flask import Blueprint, current_app, jsonify, request, send_file
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from reportlab.lib.units import inch
from database.db_connection import get_connection

export_pdf_bp = Blueprint('export_pdf', __name__, url_prefix='/export-pdf')


def fetch_cases(database_path: str, case_id: int | None = None):
    connection = get_connection(database_path)
    connection.row_factory = sqlite3.Row
    with connection:
        if case_id is not None:
            case = connection.execute('SELECT * FROM cases WHERE id = ?', (case_id,)).fetchone()
            return [case] if case is not None else []
        return connection.execute('SELECT * FROM cases ORDER BY created_at DESC').fetchall()


@export_pdf_bp.route('', methods=['GET'])
def export_pdf():
    case_id = request.args.get('case_id', type=int)
    cases = fetch_cases(current_app.config['DATABASE'], case_id)

    if case_id is not None and not cases:
        return jsonify({'error': 'Case not found'}), 404

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, leftMargin=inch, rightMargin=inch, topMargin=inch, bottomMargin=inch)
    styles = getSampleStyleSheet()
    story = [Paragraph('Case Export', styles['Title']), Spacer(1, 0.25 * inch)]

    if not cases:
        story.append(Paragraph('No cases available to export.', styles['Normal']))
    else:
        for case in cases:
            story.append(Paragraph(f"<b>Case {case['id']}:</b> {case['title']}", styles['Heading2']))
            story.append(Paragraph(f"<b>Status:</b> {case['status']}", styles['Normal']))
            story.append(Paragraph(f"<b>Created At:</b> {case['created_at']}", styles['Normal']))
            story.append(Spacer(1, 0.1 * inch))
            description = case['description'] or 'No description provided.'
            story.append(Paragraph(f"<b>Description:</b>", styles['Normal']))
            story.append(Paragraph(description.replace('\n', '<br/>'), styles['BodyText']))
            story.append(Spacer(1, 0.3 * inch))

    doc.build(story)
    buffer.seek(0)

    filename = 'case.pdf' if case_id is not None else 'cases.pdf'
    return send_file(
        buffer,
        mimetype='application/pdf',
        download_name=filename,
        as_attachment=True
    )
