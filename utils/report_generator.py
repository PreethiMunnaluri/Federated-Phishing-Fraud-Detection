"""
Report generation utilities for CyberShield AI.
Exports threats as CSV and PDF.
"""

import io
import os
import csv
from datetime import datetime
from typing import Optional

# ─────────────────────────────────────────────────────────────
# CSV export
# ─────────────────────────────────────────────────────────────

def export_threats_csv() -> bytes:
    """
    Export all threats from threat logger as CSV bytes.
    Returns bytes object suitable for st.download_button.
    """
    from utils.threat_logger import get_threats

    threats = get_threats(limit=10000)

    output = io.StringIO()
    fieldnames = ["id", "timestamp", "threat_type", "severity", "username", "details"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for t in threats:
        row = {
            "id":          t.get("id", ""),
            "timestamp":   t.get("timestamp", ""),
            "threat_type": t.get("threat_type", ""),
            "severity":    t.get("severity", ""),
            "username":    t.get("username", ""),
            "details":     str(t.get("details", {})),
        }
        writer.writerow(row)

    return output.getvalue().encode("utf-8")


# ─────────────────────────────────────────────────────────────
# PDF export
# ─────────────────────────────────────────────────────────────

def export_threats_pdf(threats: Optional[list] = None) -> bytes:
    """
    Generate a PDF threat report using ReportLab.
    Returns bytes suitable for st.download_button.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm, inch
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable,
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT

        if threats is None:
            from utils.threat_logger import get_threats
            threats = get_threats(limit=100)

        # Page setup
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=landscape(A4),
            leftMargin=15 * mm,
            rightMargin=15 * mm,
            topMargin=15 * mm,
            bottomMargin=15 * mm,
        )

        styles = getSampleStyleSheet()
        COLOR_DARK = colors.HexColor("#0a0e1a")
        COLOR_GREEN = colors.HexColor("#00ff88")
        COLOR_CYAN = colors.HexColor("#00d4ff")
        COLOR_RED = colors.HexColor("#ff3366")
        COLOR_ORANGE = colors.HexColor("#ff9500")
        COLOR_YELLOW = colors.HexColor("#ffd700")
        COLOR_GRAY = colors.HexColor("#4a5568")
        COLOR_WHITE = colors.white

        title_style = ParagraphStyle(
            "CyberTitle",
            parent=styles["Title"],
            fontSize=22,
            textColor=COLOR_GREEN,
            alignment=TA_CENTER,
            spaceAfter=4,
        )
        subtitle_style = ParagraphStyle(
            "CyberSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            textColor=COLOR_CYAN,
            alignment=TA_CENTER,
            spaceAfter=2,
        )
        meta_style = ParagraphStyle(
            "Meta",
            parent=styles["Normal"],
            fontSize=8,
            textColor=COLOR_GRAY,
            alignment=TA_CENTER,
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#e2e8f0"),
        )
        stat_label_style = ParagraphStyle(
            "StatLabel",
            parent=styles["Normal"],
            fontSize=9,
            textColor=COLOR_CYAN,
        )

        elements = []

        # Title
        elements.append(Paragraph("🛡️ CyberShield AI — Threat Intelligence Report", title_style))
        elements.append(Paragraph("Federated AI-Based Framework for Secure Phishing and Fraud Detection", subtitle_style))
        elements.append(Paragraph(
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | "
            f"Total Records: {len(threats)}",
            meta_style,
        ))
        elements.append(HRFlowable(width="100%", color=COLOR_GREEN, thickness=1.5, spaceAfter=8))

        # Summary statistics
        from utils.threat_logger import get_threat_stats
        stats = get_threat_stats()

        summary_data = [
            ["Total Threats", "Last 24h", "Critical", "High", "Medium", "Low"],
            [
                str(stats.get("total", 0)),
                str(stats.get("recent_24h", 0)),
                str(stats.get("by_severity", {}).get("CRITICAL", 0)),
                str(stats.get("by_severity", {}).get("HIGH", 0)),
                str(stats.get("by_severity", {}).get("MEDIUM", 0)),
                str(stats.get("by_severity", {}).get("LOW", 0)),
            ],
        ]
        summary_table = Table(summary_data, colWidths=[45 * mm] * 6)
        summary_table.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR",    (0, 0), (-1, 0), COLOR_CYAN),
            ("BACKGROUND",   (0, 1), (-1, 1), colors.HexColor("#0d1526")),
            ("TEXTCOLOR",    (0, 1), (-1, 1), COLOR_GREEN),
            ("FONTSIZE",     (0, 0), (-1, -1), 10),
            ("FONTNAME",     (0, 0), (-1, -1), "Helvetica-Bold"),
            ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUND",(0, 0), (-1, 0), colors.HexColor("#111827")),
            ("GRID",         (0, 0), (-1, -1), 0.5, COLOR_GRAY),
            ("TOPPADDING",   (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 8 * mm))

        # Threats table
        elements.append(Paragraph("Threat Log (Latest 100)", ParagraphStyle(
            "SectionHead", parent=styles["Normal"],
            fontSize=12, textColor=COLOR_GREEN, spaceAfter=4,
        )))

        def _severity_color(sev):
            return {
                "CRITICAL": COLOR_RED,
                "HIGH": COLOR_ORANGE,
                "MEDIUM": COLOR_YELLOW,
                "LOW": COLOR_GREEN,
            }.get(sev, COLOR_GRAY)

        table_data = [["#", "Timestamp", "Type", "Severity", "User", "Details"]]
        for i, t in enumerate(threats[:100], 1):
            details = t.get("details", {})
            detail_str = ""
            if isinstance(details, dict):
                for k, v in list(details.items())[:3]:
                    detail_str += f"{k}: {str(v)[:30]}  "
            else:
                detail_str = str(details)[:80]

            table_data.append([
                str(i),
                t.get("timestamp", "")[:19].replace("T", " "),
                t.get("threat_type", "").replace("_", " ").title(),
                t.get("severity", ""),
                t.get("username", "system"),
                detail_str[:60] + ("..." if len(detail_str) > 60 else ""),
            ])

        col_widths = [10 * mm, 38 * mm, 40 * mm, 20 * mm, 25 * mm, 100 * mm]
        threats_table = Table(table_data, colWidths=col_widths, repeatRows=1)

        style_cmds = [
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_CYAN),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, 0), 8),
            ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE",      (0, 1), (-1, -1), 7),
            ("TEXTCOLOR",     (0, 1), (-1, -1), colors.HexColor("#e2e8f0")),
            ("ALIGN",         (0, 0), (-1, -1), "LEFT"),
            ("ALIGN",         (0, 0), (0, -1), "CENTER"),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("GRID",          (0, 0), (-1, -1), 0.3, COLOR_GRAY),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ]
        # Alternating row colors
        for row_idx in range(1, len(table_data)):
            if row_idx % 2 == 0:
                style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), colors.HexColor("#0d1526")))
            else:
                style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), colors.HexColor("#0a0e1a")))
            # Color severity cell
            sev = table_data[row_idx][3] if len(table_data[row_idx]) > 3 else ""
            style_cmds.append(("TEXTCOLOR", (3, row_idx), (3, row_idx), _severity_color(sev)))

        threats_table.setStyle(TableStyle(style_cmds))
        elements.append(threats_table)

        # Footer
        elements.append(Spacer(1, 8 * mm))
        elements.append(HRFlowable(width="100%", color=COLOR_GRAY, thickness=0.5))
        elements.append(Paragraph(
            "CyberShield AI | Federated AI-Based Framework for Secure Phishing and Fraud Detection | CONFIDENTIAL",
            meta_style,
        ))

        doc.build(elements)
        return buf.getvalue()

    except ImportError:
        # ReportLab not installed — return plain text bytes
        lines = ["CyberShield AI Threat Report", "=" * 60, ""]
        for t in threats[:100]:
            lines.append(
                f"[{t.get('severity','?')}] {t.get('timestamp','')} | "
                f"{t.get('threat_type','')} | {t.get('username','')}"
            )
        return "\n".join(lines).encode("utf-8")


# ─────────────────────────────────────────────────────────────
# Summary report
# ─────────────────────────────────────────────────────────────

def generate_summary_report() -> dict:
    """
    Generate a comprehensive summary stats dict for the dashboard.

    Returns:
        total_threats, recent_24h, by_type, by_severity,
        models_active, top_threat_type, critical_count
    """
    from utils.threat_logger import get_threat_stats

    stats = get_threat_stats()
    by_type = stats.get("by_type", {})
    by_severity = stats.get("by_severity", {})

    top_threat = max(by_type, key=by_type.get) if by_type else "N/A"

    return {
        "total_threats":  stats.get("total", 0),
        "recent_24h":     stats.get("recent_24h", 0),
        "by_type":        by_type,
        "by_severity":    by_severity,
        "models_active":  4,  # email, url, sms, fraud
        "top_threat_type":top_threat,
        "critical_count": by_severity.get("CRITICAL", 0),
        "high_count":     by_severity.get("HIGH", 0),
    }
