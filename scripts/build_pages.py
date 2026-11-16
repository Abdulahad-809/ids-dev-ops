"""Build the static frontend for GitHub Pages into ./site.

GitHub Pages cannot run Flask or Python, so this renders templates/index.html
once, copies static/ and exports the trained model to static/model.json. The
page then runs the Random Forest in the browser (static/js/engine.js).

Run from the project root:  python scripts/build_pages.py
"""

import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from flask import render_template  # noqa: E402

from app import create_app  # noqa: E402
from ids.export import export_forest  # noqa: E402
from ids.model import IntrusionDetector  # noqa: E402
from ids.samples import SAMPLES  # noqa: E402

OUT = os.path.join(ROOT, "site")


def git_sha():
    sha = os.environ.get("GITHUB_SHA")
    if sha:
        return sha[:7]
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                                       text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return "local"


def main():
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    shutil.copytree(os.path.join(ROOT, "static"), os.path.join(OUT, "static"))

    detector = IntrusionDetector()
    bundle = export_forest(detector)
    bundle["info"] = detector.info()
    bundle["samples"] = SAMPLES
    with open(os.path.join(OUT, "static", "model.json"), "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, separators=(",", ":"))

    app = create_app()
    with app.test_request_context("/"):
        html = render_template("index.html", static_build=True, build_sha=git_sha())
    # Pages serves the site under /<repo>/, so asset paths must be relative.
    html = html.replace('"/static/', '"static/')
    with open(os.path.join(OUT, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(html)
    # Serve files as-is (no Jekyll processing on Pages).
    open(os.path.join(OUT, ".nojekyll"), "w").close()

    size_kb = os.path.getsize(os.path.join(OUT, "static", "model.json")) / 1024
    print(f"Built {OUT} (model.json {size_kb:.0f} KB, {len(bundle['trees'])} trees)")


if __name__ == "__main__":
    main()
