"""Sphinx configuration for the Pistis documentation."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

project = "Pistis"
author = "Pistis contributors"
copyright = "2026, Pistis contributors"
release = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

extensions = ["myst_parser"]
source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}
master_doc = "index"
exclude_patterns = ["_build", ".DS_Store", "Thumbs.db"]

html_theme = "sphinx_rtd_theme"
html_title = f"Pistis {release}"
html_static_path = ["_static"]
html_css_files = ["pistis.css"]
html_show_sourcelink = True

myst_heading_anchors = 3
