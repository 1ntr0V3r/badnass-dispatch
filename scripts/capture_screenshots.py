"""BADNASS Transit & Logistics — Automated Screenshot Capture Suite.

Captures high-resolution, enterprise daylight UI screenshots for report figures.
"""

import os
import sys
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE_URL = "http://127.0.0.1:8001/ui"
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "reports" / "figures"


def capture_all_screenshots():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[*] Target figures directory: {OUTPUT_DIR}")

    with sync_playwright() as p:
        # Launch Chromium with fallback to installed system Edge/Chrome
        browser = None
        for channel in [None, "msedge", "chrome"]:
            try:
                if channel:
                    browser = p.chromium.launch(channel=channel, headless=True)
                else:
                    browser = p.chromium.launch(headless=True)
                print(f"[*] Successfully launched browser (channel={channel or 'default'}).")
                break
            except Exception as e:
                continue

        if not browser:
            raise RuntimeError("Failed to launch any browser instance.")

        context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            device_scale_factor=2,  # Retina / High-DPI clarity
        )
        page = context.new_page()

        print(f"[*] Navigating to {BASE_URL} ...")
        page.goto(BASE_URL, wait_until="networkidle")
        time.sleep(1)

        # Clear any existing local storage session to start on portal landing
        page.evaluate("localStorage.clear()")
        page.reload(wait_until="networkidle")
        time.sleep(0.5)

        # ── 1. Portal Landing Page ──────────────────────────────────────────
        print("[1/5] Capturing ui_01_portal_landing.png ...")
        page.evaluate("navigateTo('portal-home')")
        time.sleep(0.5)
        page.screenshot(
            path=str(OUTPUT_DIR / "ui_01_portal_landing.png"),
            full_page=False,
        )

        # ── 2. Public Tracking View ─────────────────────────────────────────
        print("[2/5] Capturing ui_02_public_tracking.png ...")
        page.evaluate("navigateTo('portal-tracking')")
        page.fill("#dedicated-tracking-input", "TR-EXP-2026-104")
        page.evaluate("quickTrack('TR-EXP-2026-104')")
        time.sleep(0.5)
        page.screenshot(
            path=str(OUTPUT_DIR / "ui_02_public_tracking.png"),
            full_page=False,
        )

        # ── 3. Internal Operations Dashboard ─────────────────────────────────
        print("[3/5] Capturing ui_03_dashboard_console.png ...")
        page.evaluate("showDashboardView()")
        page.evaluate("switchTab('tab-shipments')")
        time.sleep(0.5)
        page.screenshot(
            path=str(OUTPUT_DIR / "ui_03_dashboard_console.png"),
            full_page=False,
        )

        # ── 4. TIR Overweight Alert Modal ────────────────────────────────────
        print("[4/5] Capturing ui_04_tir_overweight_modal.png ...")
        page.evaluate("openOrderModal()")
        time.sleep(0.3)
        # Input 46,500 kg to trigger overweight warning
        page.fill("#gross_weight", "46500")
        page.evaluate("""() => {
            const input = document.getElementById('gross_weight');
            input.dispatchEvent(new Event('input', { bubbles: true }));
        }""")
        time.sleep(0.5)
        page.screenshot(
            path=str(OUTPUT_DIR / "ui_04_tir_overweight_modal.png"),
            full_page=False,
        )

        # ── 5. Weighbridge Scale & Telemetry ─────────────────────────────────
        print("[5/5] Capturing ui_05_weighbridge_gauge.png ...")
        page.evaluate("closeOrderModal()")
        page.evaluate("switchTab('tab-scale')")
        page.evaluate("setPresetWeight(38400)")
        time.sleep(0.5)
        page.screenshot(
            path=str(OUTPUT_DIR / "ui_05_weighbridge_gauge.png"),
            full_page=False,
        )

        browser.close()
        print("[+] All 5 screenshots successfully captured!")


if __name__ == "__main__":
    capture_all_screenshots()
