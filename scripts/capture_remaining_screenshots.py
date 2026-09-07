"""BADNASS Transit & Logistics — Comprehensive Screenshot Capture Suite.

Captures all 10 detailed operational, interactive, and validation views for reports.
"""

import time
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE_URL = "http://127.0.0.1:8001/ui"
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "reports" / "figures"


def capture_all_detailed_views():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[*] Target figures directory: {OUTPUT_DIR}")

    with sync_playwright() as p:
        browser = None
        for channel in [None, "msedge", "chrome"]:
            try:
                if channel:
                    browser = p.chromium.launch(channel=channel, headless=True)
                else:
                    browser = p.chromium.launch(headless=True)
                print(f"[*] Successfully launched browser (channel={channel or 'default'}).")
                break
            except Exception:
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

        # Clear any stored session
        page.evaluate("localStorage.clear()")
        page.reload(wait_until="networkidle")
        time.sleep(0.5)

        # ── 1. ui_02_portal_services.png ─────────────────────────────────────
        print("[1/10] Capturing ui_02_portal_services.png ...")
        page.evaluate("navigateTo('portal-services')")
        time.sleep(0.6)
        page.screenshot(path=str(OUTPUT_DIR / "ui_02_portal_services.png"), full_page=False)

        # ── 2. ui_03_portal_tracking_result.png ──────────────────────────────
        print("[2/10] Capturing ui_03_portal_tracking_result.png ...")
        page.evaluate("navigateTo('portal-tracking')")
        page.fill("#dedicated-tracking-input", "TR-EXP-2026-104")
        page.evaluate("quickTrack('TR-EXP-2026-104')")
        time.sleep(0.6)
        page.screenshot(path=str(OUTPUT_DIR / "ui_03_portal_tracking_result.png"), full_page=False)

        # ── 3. ui_04_portal_regulations.png ──────────────────────────────────
        print("[3/10] Capturing ui_04_portal_regulations.png ...")
        page.evaluate("navigateTo('portal-regulations')")
        time.sleep(0.6)
        page.screenshot(path=str(OUTPUT_DIR / "ui_04_portal_regulations.png"), full_page=False)

        # ── 4. ui_05_portal_contact_quote.png ────────────────────────────────
        print("[4/10] Capturing ui_05_portal_contact_quote.png ...")
        page.evaluate("navigateTo('portal-contact')")
        page.fill("#quote-company", "Renault Tanger Exploitation")
        page.fill("#quote-email", "logistique.tanger@renault.com")
        page.fill("#quote-origin", "Tanger Med (TFZ)")
        page.fill("#quote-dest", "Port d'Algésiras (ES-ALG)")
        page.fill("#quote-notes", "Affrètement hebdomadaire de 12 convois Ro-Ro sous carnet TIR.")
        time.sleep(0.6)
        page.screenshot(path=str(OUTPUT_DIR / "ui_05_portal_contact_quote.png"), full_page=False)

        # ── 5. ui_06_login_modal_open.png ────────────────────────────────────
        print("[5/10] Capturing ui_06_login_modal_open.png ...")
        page.evaluate("navigateTo('portal-home')")
        page.evaluate("openLoginModal()")
        page.fill("#login-username", "ktazi")
        page.fill("#login-password", "TransitPass2026!")
        time.sleep(0.6)
        page.screenshot(path=str(OUTPUT_DIR / "ui_06_login_modal_open.png"), full_page=False)

        # ── 6. ui_08_dossier_modal_nominal.png ───────────────────────────────
        print("[6/10] Capturing ui_08_dossier_modal_nominal.png ...")
        page.evaluate("closeLoginModal()")
        page.evaluate("showDashboardView()")
        page.evaluate("openOrderModal()")
        page.fill("#gross_weight", "24500")
        page.evaluate("""() => {
            const input = document.getElementById('gross_weight');
            input.dispatchEvent(new Event('input', { bubbles: true }));
        }""")
        time.sleep(0.6)
        page.screenshot(path=str(OUTPUT_DIR / "ui_08_dossier_modal_nominal.png"), full_page=False)

        # ── 7. ui_09_dossier_modal_tir_warning.png ───────────────────────────
        print("[7/10] Capturing ui_09_dossier_modal_tir_warning.png ...")
        page.fill("#gross_weight", "46800")
        page.evaluate("""() => {
            const input = document.getElementById('gross_weight');
            input.dispatchEvent(new Event('input', { bubbles: true }));
        }""")
        time.sleep(0.6)
        page.screenshot(path=str(OUTPUT_DIR / "ui_09_dossier_modal_tir_warning.png"), full_page=False)

        # ── 8. ui_10_dossier_consult_drawer.png ──────────────────────────────
        print("[8/10] Capturing ui_10_dossier_consult_drawer.png ...")
        page.evaluate("closeOrderModal()")
        page.evaluate("switchTab('tab-shipments')")
        page.evaluate("viewShipmentDetail('TR-EXP-2026-104')")
        time.sleep(0.6)
        page.screenshot(path=str(OUTPUT_DIR / "ui_10_dossier_consult_drawer.png"), full_page=False)

        # ── 9. ui_11_weighbridge_overload.png ────────────────────────────────
        print("[9/10] Capturing ui_11_weighbridge_overload.png ...")
        page.evaluate("closeDetailsModal()")
        page.evaluate("switchTab('tab-scale')")
        page.evaluate("setPresetWeight(45800)")
        time.sleep(0.6)
        page.screenshot(path=str(OUTPUT_DIR / "ui_11_weighbridge_overload.png"), full_page=False)

        # ── 10. ui_12_audit_ledger_worm.png ──────────────────────────────────
        print("[10/10] Capturing ui_12_audit_ledger_worm.png ...")
        page.evaluate("switchTab('tab-audit')")
        time.sleep(0.6)
        page.screenshot(path=str(OUTPUT_DIR / "ui_12_audit_ledger_worm.png"), full_page=False)

        browser.close()
        print("[+] All 10 detailed screenshot views successfully captured!")


if __name__ == "__main__":
    capture_all_detailed_views()
