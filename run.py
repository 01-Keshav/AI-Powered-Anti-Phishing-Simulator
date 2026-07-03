#!/usr/bin/env python3
"""Entry point for AI-Powered Anti-Phishing Simulator."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main():
    app_path = ROOT / "app" / "main.py"
    subprocess.run([sys.executable, "-m", "streamlit", "run", str(app_path), "--server.headless", "true"], check=False)


if __name__ == "__main__":
    main()
