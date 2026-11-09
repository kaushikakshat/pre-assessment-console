"""A4 PDF from the report model. Imported by the worker only: the api streams stored files without WeasyPrint."""
import os
from pathlib import Path

from markupsafe import Markup
from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

_env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"), autoescape=select_autoescape(["j2"], default=True))
# CSS string literal: no way to break out of the quotes in @page content.
_env.filters["cs"] = lambda s: Markup("".join(f"\\{ord(c):x} " if c in '"\\\n\r<>&' else c for c in str(s)))


def render(model: dict, path: str) -> None:
    html = _env.get_template("report.html.j2").render(m=model)
    tmp = f"{path}.tmp"
    HTML(string=html).write_pdf(tmp)
    os.replace(tmp, path)  # a reader never sees a half-written file
