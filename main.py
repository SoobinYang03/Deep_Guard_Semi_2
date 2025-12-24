# main.py
from __future__ import annotations

import sys
from pathlib import Path

from deepguard.pipeline import run_pipeline
from analysis.interpretation import build_interpretation
from analysis.report_generator import generate_report


def main(apk_path: str) -> None:
    print("[*] Starting Deep Guard pipeline")
    print(f"[*] Target APK: {apk_path}")

    Path("out").mkdir(exist_ok=True)

    # 1) Static pipeline -> out/evidence.json (+ out/reports/report.txt)
    run_pipeline(apk_path)

    # 2) Interpretation -> out/interpretation.json
    #    (IOC + evasion detection + MITRE mapping)
    build_interpretation(
        evidence_path="out/evidence.json",
        out_path="out/interpretation.json",
        jadx_dir="out/jadx",
        apktool_dir="out/apktool",
        frida_events_path="out/dynamic/frida_events.jsonl",
    )

    # 3) Report -> out/report.md
    generate_report("out/interpretation.json", "out/evidence.json", "out/report.md")
    print("[✓] DONE")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py /path/to/sample.apk")
        raise SystemExit(2)
    main(sys.argv[1])
