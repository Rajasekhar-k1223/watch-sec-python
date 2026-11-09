"""
[v4.4.0] Standards-Compliant Pure-Python PDF 1.4 Compliance Report Generator
Generates valid, multi-page `%PDF-1.4` documents containing executive summary,
evidence-based framework scores, control findings, remediation actions,
residual risk indicators, and mandatory legal disclaimers (zero external binary deps).
"""
from typing import List


def _escape_pdf_text(text: str) -> str:
    """Escapes ASCII text for PDF content stream literals."""
    safe = text.encode("ascii", errors="replace").decode("ascii")
    return safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def render_compliance_pdf_bytes(title: str, lines: List[str]) -> bytes:
    """
    Builds a standards-compliant PDF 1.4 byte stream with accurate xref offsets.
    """
    wrapped_lines: List[str] = [title, "=" * min(85, len(title)), ""]
    for raw in lines:
        clean = raw.replace("\t", "    ")
        if not clean:
            wrapped_lines.append("")
            continue
        while len(clean) > 92:
            wrapped_lines.append(clean[:92])
            clean = "  " + clean[92:]
        wrapped_lines.append(clean)

    lines_per_page = 46
    pages_lines: List[List[str]] = [
        wrapped_lines[i : i + lines_per_page]
        for i in range(0, max(1, len(wrapped_lines)), lines_per_page)
    ]

    objects: List[bytes] = []
    # Obj 1: Catalog
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    # Obj 2: Pages placeholder (filled after page objects are known)
    objects.append(b"")
    # Obj 3: Helvetica Font
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    # Obj 4: Helvetica-Bold Font
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

    page_obj_nums: List[int] = []
    total_pages = len(pages_lines)

    for page_idx, plines in enumerate(pages_lines, start=1):
        stream_cmds: List[str] = ["BT", "/F2 11 Tf", "45 755 Td"]
        for line_idx, text_line in enumerate(plines):
            escaped = _escape_pdf_text(text_line)
            if line_idx == 0 and page_idx == 1:
                stream_cmds.append(f"({escaped}) Tj")
                stream_cmds.append("/F1 9 Tf")
                stream_cmds.append("0 -16 Td")
            else:
                if text_line.startswith("## ") or text_line.startswith("=== "):
                    stream_cmds.append("/F2 10 Tf")
                    stream_cmds.append(f"({escaped}) Tj")
                    stream_cmds.append("/F1 9 Tf")
                else:
                    stream_cmds.append(f"({escaped}) Tj")
                stream_cmds.append("0 -15 Td")

        footer = _escape_pdf_text(
            f"MONITORIX TECHNICAL CONTROL ASSESSMENT | Page {page_idx} of {total_pages} | Not Legal Certification"
        )
        stream_cmds.append("ET")
        stream_cmds.append("BT /F1 8 Tf 45 30 Td")
        stream_cmds.append(f"({footer}) Tj ET")

        stream_bytes = "\n".join(stream_cmds).encode("ascii", errors="replace")
        content_obj_num = len(objects) + 1
        objects.append(
            f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii")
            + stream_bytes
            + b"\nendstream"
        )

        page_obj_num = len(objects) + 1
        page_obj_nums.append(page_obj_num)
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
                f"/Contents {content_obj_num} 0 R >>"
            ).encode("ascii")
        )

    kids_str = " ".join(f"{num} 0 R" for num in page_obj_nums)
    objects[1] = f"<< /Type /Pages /Kids [{kids_str}] /Count {len(page_obj_nums)} >>".encode("ascii")

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: List[int] = [0]
    for idx, obj_body in enumerate(objects, start=1):
        offsets.append(len(out))
        out.extend(f"{idx} 0 obj\n".encode("ascii"))
        out.extend(obj_body)
        out.extend(b"\nendobj\n")

    xref_pos = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode("ascii"))

    out.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(out)

