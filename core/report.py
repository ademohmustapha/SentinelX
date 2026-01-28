from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
import os
from datetime import datetime

def generate_pdf(findings, logo_path="assets/sentinelX_logo.png", filename=None):
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/SentinelX_Report_{timestamp}.pdf"

    os.makedirs("reports", exist_ok=True)
    doc = SimpleDocTemplate(filename, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()
    title_style = styles['Title']
    normal_style = styles['Normal']
    header_style = ParagraphStyle('Header', fontSize=14, spaceAfter=12, textColor=colors.HexColor("#2E86C1"))

    # -------------------------
    # Cover Page
    # -------------------------
    if os.path.exists(logo_path):
        elements.append(Image(logo_path, width=150, height=150))
    elements.append(Spacer(1, 24))
    elements.append(Paragraph("SentinelX Security Assessment Report", title_style))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(PageBreak())

    # -------------------------
    # Executive Summary
    # -------------------------
    summary = findings.summary()
    elements.append(Paragraph("Executive Summary", header_style))
    for sev, count in summary.items():
        elements.append(Paragraph(f"{sev}: {count}", normal_style))
    elements.append(Spacer(1, 12))

    # -------------------------
    # Detailed Findings Table
    # -------------------------
    elements.append(Paragraph("Detailed Findings", header_style))
    data = [["Title", "Severity", "Description", "Fix / Recommendation"]]
    for f in findings.to_list():
        data.append([f.title, f.severity, f.desc, f.fix])

    table = Table(data, colWidths=[150, 60, 200, 150], repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2E86C1")),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('ALIGN',(0,0),(-1,-1),'LEFT'),
        ('FONTNAME', (0,0),(-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',(0,0),(-1,0),12),
        ('BOTTOMPADDING',(0,0),(-1,0),6),
        ('BACKGROUND',(0,1),(-1,-1),colors.whitesmoke),
        ('GRID',(0,0),(-1,-1),1,colors.grey),
    ]))

    # Color-code rows based on severity
    severity_colors = {
        "Info": colors.blue,
        "Low": colors.green,
        "Medium": colors.orange,
        "High": colors.red,
        "Critical": colors.darkred
    }
    for i, f in enumerate(findings.to_list(), start=1):
        table.setStyle(TableStyle([
            ('TEXTCOLOR', (1,i), (1,i), severity_colors.get(f.severity, colors.black))
        ]))

    elements.append(table)

    doc.build(elements)
    print(f"Polished PDF report saved to: {filename}")

