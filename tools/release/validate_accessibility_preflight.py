#!/usr/bin/env python3
"""Static accessibility/reflow preflight for the selected ATLAS Tauri desktop host.

This is deliberately not a substitute for the packaged Windows/Narrator review
required by PPR-07. It prevents known source-level regressions before that review.
"""
from __future__ import annotations

import json
import sys
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INDEX = ROOT / "benchmarks/desktop/phase56/candidates/tauri/www/index.html"
CSS = ROOT / "benchmarks/desktop/phase56/candidates/tauri/www/styles.css"
JS = ROOT / "benchmarks/desktop/phase56/candidates/tauri/www/main.js"
TAURI = ROOT / "benchmarks/desktop/phase56/candidates/tauri/tauri.conf.json"


class AuditParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.elements: list[tuple[str, dict[str, str]]] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        self.elements.append((tag, {k: (v or "") for k, v in attrs}))


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def first(parser: AuditParser, tag: str | None = None, element_id: str | None = None):
    for found_tag, attrs in parser.elements:
        if tag is not None and found_tag != tag:
            continue
        if element_id is not None and attrs.get("id") != element_id:
            continue
        return found_tag, attrs
    return None


def main() -> int:
    errors: list[str] = []
    for path in (INDEX, CSS, JS, TAURI):
        if not path.is_file():
            fail(errors, f"missing accessibility preflight input: {path.relative_to(ROOT)}")

    if errors:
        print("\n".join(errors))
        return 1

    html = INDEX.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")
    js = JS.read_text(encoding="utf-8")
    config = json.loads(TAURI.read_text(encoding="utf-8"))

    parser = AuditParser()
    parser.feed(html)

    html_node = first(parser, "html")
    if not html_node or not html_node[1].get("lang"):
        fail(errors, "document must declare a non-empty html lang")

    skip = None
    for tag, attrs in parser.elements:
        if tag == "a" and attrs.get("class") == "skip-link":
            skip = attrs
            break
    if not skip or skip.get("href") != "#workspace":
        fail(errors, "keyboard skip-link must target #workspace")

    workspace = first(parser, "main", "workspace")
    if not workspace or workspace[1].get("tabindex") != "-1":
        fail(errors, "#workspace must be programmatically focusable with tabindex=-1")

    nav = first(parser, "aside")
    if not nav or not nav[1].get("aria-label"):
        fail(errors, "primary navigation must expose an aria-label")

    global_notice = first(parser, element_id="globalNotice")
    if not global_notice or global_notice[1].get("role") != "status" or global_notice[1].get("aria-live") != "polite":
        fail(errors, "globalNotice must remain a polite status live region")

    pack_result = first(parser, element_id="packActionResult")
    if not pack_result or pack_result[1].get("aria-live") != "polite":
        fail(errors, "packActionResult must remain an aria-live region")

    refresh = first(parser, "button", "refreshStatus")
    if not refresh or not refresh[1].get("aria-label"):
        fail(errors, "icon-only refreshStatus button requires aria-label")

    labels_for = {
        attrs.get("for")
        for tag, attrs in parser.elements
        if tag == "label" and attrs.get("for")
    }
    for tag, attrs in parser.elements:
        if tag not in {"input", "select"}:
            continue
        element_id = attrs.get("id")
        if not element_id:
            fail(errors, f"{tag} control missing id")
            continue
        if element_id not in labels_for and not attrs.get("aria-label"):
            fail(errors, f"{tag}#{element_id} has no associated label or aria-label")

    css_required = (
        "body{min-width:0}",
        "button:focus-visible",
        'body[data-theme="high-contrast"]',
        "@media(max-width:880px)",
        "@media(max-width:680px)",
    )
    for token in css_required:
        if token not in css:
            fail(errors, f"CSS accessibility/reflow invariant missing: {token}")
    if ".compact-form label{display:none}" in css:
        fail(errors, "responsive CSS must not hide graph form labels with display:none")

    js_required = (
        "$('workspace').focus({ preventScroll: true })",
        "button.setAttribute('aria-current', 'page')",
        "button.removeAttribute('aria-current')",
        "FAIL-CLOSED:",
    )
    for token in js_required:
        if token not in js:
            fail(errors, f"UI behavior accessibility invariant missing: {token}")

    windows = config.get("app", {}).get("windows", [])
    if len(windows) != 1:
        fail(errors, "selected desktop host must retain exactly one primary window")
    else:
        window = windows[0]
        if window.get("resizable") is not True:
            fail(errors, "primary window must remain resizable")
        min_width = window.get("minWidth")
        if not isinstance(min_width, int) or min_width > 800:
            fail(errors, "primary window minWidth must be <= 800 logical pixels for scaling/reflow review")
        min_height = window.get("minHeight")
        if not isinstance(min_height, int) or min_height > 640:
            fail(errors, "primary window minHeight must be <= 640 logical pixels")

    if errors:
        print("PPR-07 static accessibility preflight FAILED:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("PPR-07 static accessibility preflight passed.")
    print("Manual exact-package Windows/Narrator/DPI review remains mandatory for PPR-07 PASS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
