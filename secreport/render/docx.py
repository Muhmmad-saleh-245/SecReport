"""DOCX renderer built with the standard library only (zipfile + raw OOXML).

Produces a real Word document with styles, a header (classification), a footer
(page x of y), styled tables with repeating header rows and severity badges.
"""

from __future__ import annotations

import base64
import io
import re
import zipfile
from xml.sax.saxutils import escape

from .. import branding
from ..charts import SEV_COLORS

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
TEXT_W = 9638  # A4 width 11906 - margins 2*1134 (dxa)
_BAD_XML = re.compile("[^\x09\x0A\x0D\x20-퟿-�\U00010000-\U0010ffff]")
SEV_COLS = ("Severity", "Priority", "Highest")


def _x(text) -> str:
    return escape(_BAD_XML.sub("", str(text)))


def _hex(color: str) -> str:
    return color.lstrip("#").upper()


def run(text, bold=False, italic=False, color=None, size=None, mono=False, shade=None) -> str:
    props = ""
    if mono:
        props += '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>'
    if bold:
        props += "<w:b/>"
    if italic:
        props += "<w:i/>"
    if color:
        props += f'<w:color w:val="{_hex(color)}"/>'
    if size:
        props += f'<w:sz w:val="{int(size * 2)}"/><w:szCs w:val="{int(size * 2)}"/>'
    if shade:
        props += f'<w:shd w:val="clear" w:color="auto" w:fill="{_hex(shade)}"/>'
    parts = str(text).replace("\r", "").split("\n")
    body = '<w:br/>'.join(f'<w:t xml:space="preserve">{_x(p)}</w:t>' for p in parts)
    return f"<w:r>{('<w:rPr>' + props + '</w:rPr>') if props else ''}{body}</w:r>"


def para(runs: str, style=None, keep_next=False, after=None, before=None, left=None,
         hanging=None, jc=None, shade=None, border=None) -> str:
    p = ""
    if style:
        p += f'<w:pStyle w:val="{style}"/>'
    if keep_next:
        p += "<w:keepNext/>"
    if border:
        p += (f'<w:pBdr><w:left w:val="single" w:sz="24" w:space="6" w:color="{_hex(border)}"/></w:pBdr>')
    if shade:
        p += f'<w:shd w:val="clear" w:color="auto" w:fill="{_hex(shade)}"/>'
    if after is not None or before is not None:
        p += "<w:spacing" + (f' w:before="{before}"' if before is not None else "") + \
             (f' w:after="{after}"' if after is not None else "") + "/>"
    if left is not None:
        p += f'<w:ind w:left="{left}"' + (f' w:hanging="{hanging}"' if hanging else "") + "/>"
    if jc:
        p += f'<w:jc w:val="{jc}"/>'
    return f"<w:p>{('<w:pPr>' + p + '</w:pPr>') if p else ''}{runs}</w:p>"


def _cell(inner: str, width: int, fill=None, span=None) -> str:
    props = f'<w:tcW w:w="{width}" w:type="dxa"/>'
    if span:
        props += f'<w:gridSpan w:val="{span}"/>'
    if fill:
        props += f'<w:shd w:val="clear" w:color="auto" w:fill="{_hex(fill)}"/>'
    return f"<w:tc><w:tcPr>{props}</w:tcPr>{inner}</w:tc>"


def _borders(color="E2E8F0", size=4, inside=True) -> str:
    sides = ["top", "left", "bottom", "right"] + (["insideH", "insideV"] if inside else [])
    return "<w:tblBorders>" + "".join(
        f'<w:{s} w:val="single" w:sz="{size}" w:space="0" w:color="{color}"/>' for s in sides) + "</w:tblBorders>"


def table(headers, rows, widths, mono=(), sev_cols=SEV_COLS) -> str:
    total = sum(widths) or 1
    cols = [max(400, int(TEXT_W * w / total)) for w in widths]
    mono = set(mono)
    x = ('<w:tbl><w:tblPr><w:tblW w:w="%d" w:type="dxa"/>%s<w:tblLayout w:type="fixed"/>'
         '<w:tblCellMar><w:top w:w="40" w:type="dxa"/><w:left w:w="80" w:type="dxa"/>'
         '<w:bottom w:w="40" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar></w:tblPr>'
         % (sum(cols), _borders()))
    x += "<w:tblGrid>" + "".join(f'<w:gridCol w:w="{c}"/>' for c in cols) + "</w:tblGrid>"
    x += "<w:tr><w:trPr><w:cantSplit/><w:tblHeader/></w:trPr>" + "".join(
        _cell(para(run(h, bold=True, size=9), after=0), cols[i], fill="F1F5F9") for i, h in enumerate(headers)) + "</w:tr>"
    for row in rows:
        x += "<w:tr><w:trPr><w:cantSplit/></w:trPr>"
        for i, c in enumerate(row):
            c = str(c)
            if i in mono:
                r = run(c, mono=True, size=7.5)
            elif c in SEV_COLORS and headers[i] in sev_cols:
                r = run(f" {c} ", bold=True, color="FFFFFF", size=8.5, shade=SEV_COLORS[c])
            else:
                r = run(c, size=9)
            x += _cell(para(r, after=0), cols[i])
        x += "</w:tr>"
    return x + "</w:tbl>" + para("", after=60)


def kv_table(items) -> str:
    cols = [2300, TEXT_W - 2300]
    x = ('<w:tbl><w:tblPr><w:tblW w:w="%d" w:type="dxa"/><w:tblLayout w:type="fixed"/>'
         '<w:tblCellMar><w:left w:w="60" w:type="dxa"/><w:right w:w="60" w:type="dxa"/></w:tblCellMar></w:tblPr>'
         % TEXT_W)
    x += "<w:tblGrid>" + "".join(f'<w:gridCol w:w="{c}"/>' for c in cols) + "</w:tblGrid>"
    for k, v in items:
        x += "<w:tr><w:trPr><w:cantSplit/></w:trPr>"
        x += _cell(para(run(k, color="64748B", size=9.5), after=20), cols[0])
        x += _cell(para(run(v, size=9.5), after=20), cols[1]) + "</w:tr>"
    return x + "</w:tbl>" + para("", after=40)


def _chart(counts: dict) -> str:
    peak = max(list(counts.values()) + [1])
    out = ""
    for sev, n in counts.items():
        bar = "█" * (max(1, round(28 * n / peak)) if n else 0)
        out += (f'<w:p><w:pPr><w:tabs><w:tab w:val="left" w:pos="1300"/></w:tabs>'
                f'<w:spacing w:after="20"/></w:pPr>{run(sev, size=9.5)}<w:r><w:tab/></w:r>'
                f'{run(bar, color=SEV_COLORS[sev], size=10)}{run("  " + str(n), bold=True, size=9.5)}</w:p>')
    return out + para("", after=60)


def _body(blocks) -> str:
    x = ""
    for b in blocks:
        t = b["t"]
        if t == "cover":
            if b.get("logo_data_uri"):
                logo = re.fullmatch(r"data:image/(?:png|jpeg);base64,([A-Za-z0-9+/=]+)", b["logo_data_uri"])
                if not logo:
                    raise ValueError("Invalid embedded logo data")
                logo_data = base64.b64decode(logo.group(1), validate=True)
                extension, _, width, height = branding.inspect_logo(logo_data)
                cx, cy = width * 9525, height * 9525
                scale = min(1.0, 2 * 914400 / cx, 0.7 * 914400 / cy)
                cx, cy = int(cx * scale), int(cy * scale)
                x += (f'<w:p><w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0">'
                      f'<wp:extent cx="{cx}" cy="{cy}"/><wp:docPr id="1" name="Client logo"/>'
                      '<wp:cNvGraphicFramePr><a:graphicFrameLocks noChangeAspect="1"/></wp:cNvGraphicFramePr>'
                      '<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
                      '<pic:pic><pic:nvPicPr><pic:cNvPr id="0" name="logo.' + extension + '"/><pic:cNvPicPr/></pic:nvPicPr>'
                      '<pic:blipFill><a:blip r:embed="rId4"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
                      f'<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>'
                      '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
                      '</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>')
                b["_logo_data"] = logo_data
                b["_logo_extension"] = extension
            brand_color = _hex(b.get("brand_color", branding.DEFAULT_COLOR))
            band = (para(run(b.get("brand_name", b.get("client", "")), bold=True, color="FFFFFF", size=14), after=60, before=120)
                    + para(run(b["title"], bold=True, color="FFFFFF", size=24), after=60)
                    + para(run(b["subtitle"], color="CBD5E1", size=13), after=200)
                    + para(run(b["classification"], bold=True, color="FCD34D", size=9), after=200))
            x += ('<w:tbl><w:tblPr><w:tblW w:w="%d" w:type="dxa"/><w:tblLayout w:type="fixed"/>'
                  '<w:tblCellMar><w:left w:w="280" w:type="dxa"/><w:right w:w="280" w:type="dxa"/></w:tblCellMar>'
                  '</w:tblPr><w:tblGrid><w:gridCol w:w="%d"/></w:tblGrid><w:tr>%s</w:tr></w:tbl>'
                  % (TEXT_W, TEXT_W, _cell(band, TEXT_W, fill=brand_color)))
            x += para("", after=120) + kv_table(b["meta"])
        elif t == "toc":
            continue
        elif t == "h1":
            x += para(run(b["text"]), style="Heading1")
        elif t == "h2":
            x += para(run(b["text"]), style="Heading2")
        elif t == "h3":
            badge = ""
            if b.get("sev"):
                badge = run("  ") + run(f" {b['sev'].upper()} ", bold=True, color="FFFFFF", size=9,
                                       shade=SEV_COLORS.get(b["sev"], "475569"))
            x += para(run(b["text"]) + badge, style="Heading3")
        elif t == "label":
            x += para(run(b["text"].upper(), bold=True, color="64748B", size=8.5), keep_next=True, before=120, after=30)
        elif t == "p":
            if b.get("small"):
                x += para(run(b["text"], color="64748B", size=8.5), after=60)
            else:
                x += para(run(b["text"]), after=100)
        elif t == "kv":
            x += kv_table(b["items"])
        elif t in ("ul", "refs"):
            for item in b["items"]:
                x += para(run("•\t") + run(item), left=360, hanging=260, after=40)
        elif t == "table":
            x += table(b["headers"], b["rows"], b["widths"] if "widths" in b else [1] * len(b["headers"]),
                       b.get("mono", ()))
        elif t == "chart":
            x += _chart(b["counts"])
        elif t == "note":
            fill, bar = ("FEF3C7", "F59E0B") if b.get("kind") == "draft" else ("E0F2FE", "38BDF8")
            x += para(run(b["text"], size=10), shade=fill, border=bar, after=120, before=60, left=120)
        elif t == "pagebreak":
            x += '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'
    return x


STYLES = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="{W_NS}">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Calibri" w:cs="Calibri"/>
<w:color w:val="1E293B"/><w:sz w:val="21"/><w:szCs w:val="21"/><w:lang w:val="en-US"/></w:rPr></w:rPrDefault>
<w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>
<w:pPr><w:keepNext/><w:pBdr><w:bottom w:val="single" w:sz="8" w:space="2" w:color="E2E8F0"/></w:pBdr><w:spacing w:before="360" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr>
<w:rPr><w:b/><w:color w:val="0F172A"/><w:sz w:val="32"/><w:szCs w:val="32"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>
<w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="1"/></w:pPr>
<w:rPr><w:b/><w:color w:val="0F172A"/><w:sz w:val="26"/><w:szCs w:val="26"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>
<w:pPr><w:keepNext/><w:pBdr><w:top w:val="single" w:sz="6" w:space="6" w:color="E2E8F0"/></w:pBdr><w:spacing w:before="320" w:after="80"/><w:outlineLvl w:val="2"/></w:pPr>
<w:rPr><w:b/><w:color w:val="0F172A"/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Header"><w:name w:val="header"/><w:basedOn w:val="Normal"/><w:pPr><w:jc w:val="center"/><w:spacing w:after="0"/></w:pPr>
<w:rPr><w:b/><w:color w:val="64748B"/><w:sz w:val="16"/><w:szCs w:val="16"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Footer"><w:name w:val="footer"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="0"/></w:pPr>
<w:rPr><w:color w:val="64748B"/><w:sz w:val="16"/><w:szCs w:val="16"/></w:rPr></w:style>
</w:styles>"""


def _header(classification: str) -> str:
    return (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:hdr xmlns:w="{W_NS}">'
            + para(run(classification.upper()), style="Header") + "</w:hdr>")


def _footer(label: str) -> str:
    def fld(instr):
        return (f'<w:fldSimple w:instr="{instr}"><w:r><w:rPr><w:color w:val="64748B"/></w:rPr>'
                f'<w:t>1</w:t></w:r></w:fldSimple>')
    p = (f'<w:p><w:pPr><w:pStyle w:val="Footer"/><w:tabs><w:tab w:val="right" w:pos="{TEXT_W}"/></w:tabs></w:pPr>'
         f'{run(label)}<w:r><w:tab/></w:r>{run("Page ")}{fld(" PAGE ")}{run(" of ")}{fld(" NUMPAGES ")}</w:p>')
    return f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr xmlns:w="{W_NS}">{p}</w:ftr>'


def render(blocks: list) -> bytes:
    cover = next((b for b in blocks if b["t"] == "cover"), {"title": "Report", "client": "", "classification": ""})
    sect = ('<w:sectPr><w:headerReference w:type="default" r:id="rId2"/><w:footerReference w:type="default" r:id="rId3"/>'
            '<w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" '
            'w:header="567" w:footer="567" w:gutter="0"/></w:sectPr>')
    body = _body(blocks)
    logo_data = cover.get("_logo_data")
    extension = cover.get("_logo_extension")
    document = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                f'<w:document xmlns:w="{W_NS}" xmlns:r="{R_NS}" '
                'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
                'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
                'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">'
                f'<w:body>{body}{sect}</w:body></w:document>')
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
        '<Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>'
        '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
        '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
        '</Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '</Relationships>')
    image_rel = (f'<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
                 f'Target="media/logo.{extension}"/>') if logo_data else ""
    mime = "image/png" if extension == "png" else "image/jpeg"
    image_type = f'<Default Extension="{extension}" ContentType="{mime}"/>' if logo_data else ""
    content_types = content_types.replace("</Types>", image_type + "</Types>")
    doc_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
                '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/>'
                '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>'
                + image_rel + '</Relationships>')
    core = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>%s</dc:title><dc:creator>SecReport</dc:creator>'
            '</cp:coreProperties>' % _x(cover["title"]))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", rels)
        z.writestr("word/document.xml", document)
        z.writestr("word/styles.xml", STYLES)
        z.writestr("word/header1.xml", _header(cover.get("classification", "")))
        z.writestr("word/footer1.xml", _footer(f"{cover.get('client', '')} - {cover['title']}"))
        z.writestr("word/_rels/document.xml.rels", doc_rels)
        if logo_data:
            z.writestr(f"word/media/logo.{extension}", logo_data)
        z.writestr("docProps/core.xml", core)
    return buf.getvalue()
