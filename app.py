"""
WS1 UEM Sync Tool — Flask backend
"""

import json
import logging
import os
import queue
import threading
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, send_file, stream_with_context

from ws1_api import WS1Client, STANDARD_OG_TYPES

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)


@app.errorhandler(Exception)
def handle_exception(e):
    log.exception("Unhandled exception")
    return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 500

app.secret_key = "ws1-sync-tool-2024"

CONFIG_FILE = Path("config.json")
DATA_DIR = Path("saved_data")
DATA_DIR.mkdir(exist_ok=True)

# Keyed by env: _data_store["prod"] and _data_store["uat"]
# Using a dict avoids global-rebinding issues in nested closures.
_data_store: dict = {"prod": {}, "uat": {}}

# Single cancel event — set by /api/cancel, cleared at the start of each operation
_cancel_event = threading.Event()

# Per-category key used to identify items by name for comparison
_NAME_KEYS: dict = {
    "org_types":             "Type",
    "organizational_groups": "GroupId",
    "tags":                  "TagName",
    "smart_groups":          "Name",
    "profiles":              "ProfileName",
    "compliance_policies":   "name",
    "scripts":               "name",
    "sensors":               "name",
    "apps_internal":         "ApplicationName",
    "apps_public":           "ApplicationName",
    "apps_purchased":        "ApplicationName",
    "product_provisioning":  "Name",
}

# ------------------------------------------------------------------ config

DEFAULT_CONFIG = {
    "prod": {
        "server_url": "https://as2419.awmdm.com",
        "username": "",
        "password": "",
        "api_key": "",
        "p12_path": "",
        "p12_password": "",
        "verify_ssl": True,
    },
    "uat": {
        "server_url": "https://as2679.awmdm.com",
        "username": "",
        "password": "",
        "api_key": "",
        "p12_path": "",
        "p12_password": "",
        "verify_ssl": True,
    },
}


def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
            for env in ("prod", "uat"):
                for k, v in DEFAULT_CONFIG[env].items():
                    cfg.setdefault(env, {})[k] = cfg[env].get(k, v)
            return cfg
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(cfg: dict):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def make_client(env_cfg: dict, on_request=None, is_cancelled=None) -> WS1Client:
    return WS1Client(
        server_url=env_cfg["server_url"],
        username=env_cfg["username"],
        password=env_cfg["password"],
        api_key=env_cfg["api_key"],
        p12_path=env_cfg.get("p12_path") or None,
        p12_password=env_cfg.get("p12_password") or None,
        verify_ssl=env_cfg.get("verify_ssl", True),
        on_request=on_request,
        is_cancelled=is_cancelled,
    )


def _sse(event: dict) -> str:
    """Format a dict as a Server-Sent Event line."""
    return f"data: {json.dumps(event, default=str)}\n\n"


def _topo_sort_ogs(items: list) -> list:
    """
    Sort OGs so every parent appears before its children.
    OGs whose _ParentName is not in the synced set (i.e. already exist in the
    target environment) are treated as roots and placed first.
    """
    name_to_item = {item["Name"]: item for item in items if item.get("Name")}
    syncing_names = set(name_to_item.keys())
    result: list = []
    visited: set = set()

    def visit(name: str):
        if name in visited:
            return
        visited.add(name)
        item = name_to_item.get(name)
        if item is None:
            return
        parent_name = item.get("_ParentName")
        if parent_name and parent_name in syncing_names:
            visit(parent_name)
        result.append(item)

    for name in list(name_to_item.keys()):
        visit(name)

    # Preserve any items that had no Name (safety)
    unnamed = [item for item in items if not item.get("Name")]
    return result + unnamed


def _custom_og_types_from_results(results: dict) -> list:
    custom = []
    if "org_types" in results:
        for item in results["org_types"].get("items", []):
            if not item.get("IsStandard", True):
                custom.append(item["Type"])
    elif "organizational_groups" in results:
        seen: set = set()
        for og in results["organizational_groups"].get("items", []):
            t = og.get("LocationGroupType")
            if t and t not in STANDARD_OG_TYPES and t not in seen:
                custom.append(t)
                seen.add(t)
    return custom


# ------------------------------------------------------------------ routes

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/cancel", methods=["POST"])
def cancel_operation():
    _cancel_event.set()
    log.info("Cancel requested by user")
    return jsonify({"ok": True})


@app.route("/api/config", methods=["GET"])
def get_config():
    cfg = load_config()
    safe = json.loads(json.dumps(cfg))
    for env in ("prod", "uat"):
        if safe[env].get("password"):
            safe[env]["password"] = "••••••••"
        if safe[env].get("p12_password"):
            safe[env]["p12_password"] = "••••••••"
    return jsonify(safe)


@app.route("/api/config", methods=["POST"])
def set_config():
    new_cfg = request.json or {}
    cfg = load_config()
    for env in ("prod", "uat"):
        if env in new_cfg:
            for k, v in new_cfg[env].items():
                if v == "••••••••":
                    continue
                cfg[env][k] = v
    save_config(cfg)
    return jsonify({"ok": True})


@app.route("/api/test-connection", methods=["POST"])
def test_connection():
    body = request.json or {}
    env = body.get("env", "prod")
    cfg = load_config()
    try:
        client = make_client(cfg[env])
        info = client.test_connection()
        client.cleanup()
        return jsonify({"ok": True, "info": info})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/fetch", methods=["POST"])
def fetch_data():
    body = request.json or {}
    categories = body.get("categories", [])
    env = body.get("env", "prod")   # "prod" or "uat"

    cfg = load_config()
    env_cfg = cfg.get(env, {})
    if not env_cfg.get("server_url") or not env_cfg.get("api_key"):
        return jsonify({"ok": False, "error": f"{env.upper()} environment not configured."})

    _cancel_event.clear()

    def generate():
        eq: queue.Queue = queue.Queue()

        def emit(event: dict):
            eq.put(event)

        def on_request(method, path, status, count):
            emit({"type": "api_call", "method": method, "path": path,
                  "status": status, "count": count})

        client = make_client(env_cfg, on_request=on_request,
                             is_cancelled=_cancel_event.is_set)

        # organizational_groups must come before org_types so the OG tree is
        # cached on the first real API call; org_types then derives from the
        # cache at zero additional cost.
        FETCHERS = {
            "organizational_groups": ("Organizational Groups", client.get_organizational_groups),
            "org_types":             ("Org Type List",         client.get_org_types),
            "tags":                  ("Tags",                  client.get_tags),
            "smart_groups":          ("Smart Groups",          client.get_smart_groups),
            "profiles":              ("Profiles",              client.get_profiles),
            "compliance_policies":   ("Compliance Policies",   client.get_compliance_policies),
            "apps_internal":         ("Apps (Internal)",       client.get_apps_internal),
            "apps_public":           ("Apps (Public)",         client.get_apps_public),
            "apps_purchased":        ("Apps (Purchased/VPP)",  client.get_apps_purchased),
            "scripts":               ("Scripts",               client.get_scripts),
            "sensors":               ("Sensors",               client.get_sensors),
            "product_provisioning":  ("Product Provisioning",  client.get_product_provisioning),
        }

        requested = set(categories) if categories else set(FETCHERS.keys())
        # Always iterate in FETCHERS order so dependency order is respected
        cats = [c for c in FETCHERS if c in requested]
        results: dict = {}
        errors: dict = {}

        def run():
            env_label = "Production" if env == "prod" else "UAT"
            emit({"type": "log", "msg": f"Starting fetch of {len(cats)} categor{'y' if len(cats)==1 else 'ies'} from {env_label}…", "level": "info"})
            for key in cats:
                if _cancel_event.is_set():
                    break
                label, fn = FETCHERS[key]
                emit({"type": "category_start", "key": key, "label": label})
                try:
                    items, debug = fn()
                    results[key] = {"label": label, "items": items,
                                    "count": len(items), "debug": debug}
                    emit({"type": "category_done", "key": key, "label": label,
                          "count": len(items)})
                except InterruptedError:
                    emit({"type": "category_error", "key": key, "label": label,
                          "error": "Cancelled"})
                    break
                except Exception as e:
                    log.warning("Failed to fetch %s: %s", label, e)
                    errors[key] = str(e)
                    emit({"type": "category_error", "key": key, "label": label,
                          "error": str(e)})

            client.cleanup()

            if _cancel_event.is_set():
                emit({"type": "cancelled"})
            else:
                _data_store[env] = {**results, "_fetched_at": datetime.now().isoformat()}
                custom_og_types = _custom_og_types_from_results(results)
                slim = {k: {kk: vv for kk, vv in v.items() if kk != "items"}
                        for k, v in results.items()}
                emit({"type": "complete", "ok": True, "results": slim,
                      "errors": errors, "custom_og_types": custom_og_types})

            eq.put(None)  # sentinel

        t = threading.Thread(target=run, daemon=True)
        t.start()

        while True:
            event = eq.get()
            if event is None:
                break
            yield _sse(event)

    headers = {"X-Accel-Buffering": "no", "Cache-Control": "no-cache",
               "Access-Control-Allow-Origin": "*"}
    return Response(stream_with_context(generate()),
                    content_type="text/event-stream", headers=headers)


@app.route("/api/data", methods=["GET"])
def get_fetched_data():
    out = {}
    for k, v in _data_store["prod"].items():
        if k.startswith("_"):
            out[k] = v
        else:
            out[k] = {kk: vv for kk, vv in v.items() if kk != "debug"}
    return jsonify(out)


@app.route("/api/debug", methods=["GET"])
def get_debug_info():
    out = {}
    for k, v in _data_store["prod"].items():
        if k.startswith("_"):
            continue
        out[k] = {"label": v.get("label", k), "count": v.get("count", 0),
                  "debug": v.get("debug", {})}
    return jsonify(out)


@app.route("/api/compare", methods=["GET"])
def compare_data():
    """Compare PROD vs UAT fetched data by name, returning delta per category."""
    prod = _data_store["prod"]
    uat  = _data_store["uat"]
    if not prod:
        return jsonify({"ok": False, "error": "No PROD data — fetch PROD first (Step 2)."})
    if not uat:
        return jsonify({"ok": False, "error": "No UAT data — fetch UAT first (Step 3)."})

    comparison: dict = {}
    for key, name_key in _NAME_KEYS.items():
        if key not in prod:
            continue
        prod_items = prod[key].get("items", [])
        uat_items  = uat.get(key, {}).get("items", [])
        label      = prod[key].get("label", key)

        # Case-insensitive name sets
        uat_names  = {(item.get(name_key) or "").strip().lower() for item in uat_items}
        prod_names = {(item.get(name_key) or "").strip().lower() for item in prod_items}

        missing_indices: list = []
        missing_names:   list = []
        exists_count = 0

        for i, item in enumerate(prod_items):
            name = (item.get(name_key) or "").strip().lower()
            if not name:
                continue
            if name in uat_names:
                exists_count += 1
            else:
                missing_indices.append(i)
                missing_names.append(item.get(name_key, ""))

        uat_only = [item.get(name_key, "") for item in uat_items
                    if (item.get(name_key) or "").strip().lower() not in prod_names]

        comparison[key] = {
            "label":           label,
            "prod_count":      len(prod_items),
            "uat_count":       len(uat_items),
            "missing_count":   len(missing_indices),
            "missing_indices": missing_indices,
            "missing_names":   missing_names[:200],
            "exists_count":    exists_count,
            "uat_only_count":  len(uat_only),
            "uat_only_names":  uat_only[:50],
        }

    return jsonify({"ok": True, "comparison": comparison})


@app.route("/api/probe", methods=["POST"])
def probe_endpoint():
    body = request.json or {}
    path = body.get("path", "")
    env = body.get("env", "prod")
    params = body.get("params", {})
    if not path:
        return jsonify({"ok": False, "error": "path is required"})
    cfg = load_config()
    try:
        client = make_client(cfg[env])
        result = client.probe_endpoint(path, params=params or None)
        client.cleanup()
        return jsonify({"ok": True, **result})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/save", methods=["POST"])
def save_data():
    body = request.json or {}
    categories = body.get("categories")
    filename = body.get("filename") or f"ws1_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    if not filename.endswith(".json"):
        filename += ".json"
    prod = _data_store["prod"]
    if not prod:
        return jsonify({"ok": False, "error": "No data fetched yet."})
    to_save: dict = {"_saved_at": datetime.now().isoformat()}
    keys = categories if categories else [k for k in prod if not k.startswith("_")]
    for cat in keys:
        if cat in prod:
            entry = prod[cat]
            to_save[cat] = {"label": entry.get("label", cat),
                            "count": entry.get("count", 0),
                            "items": entry.get("items", [])}
    out_path = DATA_DIR / filename
    with open(out_path, "w") as f:
        json.dump(to_save, f, indent=2, default=str)
    log.info("Saved data to %s", out_path)
    return jsonify({"ok": True, "path": str(out_path), "filename": filename})


@app.route("/api/download/<filename>")
def download_file(filename: str):
    path = DATA_DIR / filename
    if not path.exists() or not path.is_file():
        return jsonify({"error": "File not found"}), 404
    return send_file(path, as_attachment=True, download_name=filename)


@app.route("/api/saved-files", methods=["GET"])
def list_saved_files():
    files = [
        {"name": p.name, "size": p.stat().st_size,
         "modified": datetime.fromtimestamp(p.stat().st_mtime).isoformat()}
        for p in sorted(DATA_DIR.glob("*.json"), reverse=True)
    ]
    return jsonify(files)


@app.route("/api/sync", methods=["POST"])
def sync_to_uat():
    body = request.json or {}
    selections = body.get("selections", {})
    chunk_size = int(body.get("chunk_size", 25))
    acknowledge_custom_types = bool(body.get("acknowledge_custom_types", False))

    cfg = load_config()
    uat_cfg = cfg.get("uat", {})
    if not uat_cfg.get("server_url") or not uat_cfg.get("api_key"):
        return jsonify({"ok": False, "error": "UAT environment not configured."})

    # Custom-type pre-flight (must happen before streaming starts so we can return JSON on failure)
    sync_warnings: list = []
    if selections.get("organizational_groups"):
        custom_in_sel = {og.get("LocationGroupType") for og in selections["organizational_groups"]
                         if og.get("LocationGroupType") not in STANDARD_OG_TYPES}
        custom_in_sel.discard(None)
        if custom_in_sel and not acknowledge_custom_types:
            return jsonify({
                "ok": False,
                "error": "custom_og_types_unacknowledged",
                "custom_og_types": sorted(custom_in_sel),
                "message": (
                    "Non-standard OG types found: " + ", ".join(sorted(custom_in_sel))
                    + ". Add them in UAT first (All Settings → System → Organization Group Types), "
                    "then re-sync with acknowledgement."
                ),
            })
        if custom_in_sel:
            sync_warnings.append(
                f"Custom OG types acknowledged: {', '.join(sorted(custom_in_sel))}. "
                "Ensure these types exist in UAT before proceeding."
            )

    _cancel_event.clear()

    def generate():
        eq: queue.Queue = queue.Queue()

        def emit(event: dict):
            eq.put(event)

        def on_request(method, path, status, count):
            emit({"type": "api_call", "method": method, "path": path,
                  "status": status, "count": count})

        client = make_client(uat_cfg, on_request=on_request,
                             is_cancelled=_cancel_event.is_set)

        # Canonical sync order — enforced server-side regardless of client selection order.
        # Dependencies must come first: OGs → Tags → Smart Groups (tags referenced by SGs).
        SYNC_ORDER = [
            "org_types",
            "organizational_groups",
            "tags",               # must precede smart_groups
            "smart_groups",
            "scripts",
            "sensors",
            "compliance_policies",
            "profiles",
            "apps_internal",
            "apps_public",
            "apps_purchased",
            "product_provisioning",
        ]
        SYNC_SUPPORTED = {
            "org_types":             None,
            "organizational_groups": client.create_organizational_group,
            "tags":                  client.create_tag,
            "smart_groups":          client.create_smart_group,
            "scripts":               client.create_script,
            "sensors":               client.create_sensor,
            "compliance_policies":   client.create_compliance_policy,
            "profiles":              client.create_profile,
        }
        MANUAL_ONLY = {
            "apps_internal":        "Internal apps require the binary — upload manually.",
            "apps_public":          "Public app assignments are console-only.",
            "apps_purchased":       "VPP/Purchased apps are licence-linked — assign manually.",
            "product_provisioning": "Product Provisioning must be configured manually.",
        }

        results: dict = {}

        def run():
            emit({"type": "log",
                  "msg": f"Starting sync to UAT — {sum(len(v) for v in selections.values() if isinstance(v, list))} items across {len(selections)} categories",
                  "level": "info"})

            # Build PROD→UAT OG ID remap table before any category is synced.
            # Tags and smart groups reference PROD OG IDs that must be translated to
            # UAT OG IDs. Use stored PROD OG data when available; otherwise fetch
            # the PROD OG tree on-the-fly using a temporary PROD client.
            prod_ogs = _data_store["prod"].get("organizational_groups", {}).get("items", [])
            if not prod_ogs:
                prod_cfg = cfg.get("prod", {})
                if prod_cfg.get("server_url") and prod_cfg.get("api_key"):
                    emit({"type": "log",
                          "msg": "PROD OG data not pre-fetched — fetching OG tree now for ID remap…",
                          "level": "info"})
                    try:
                        prod_client = make_client(prod_cfg)
                        prod_ogs, _ = prod_client.get_organizational_groups()
                        prod_client.cleanup()
                        emit({"type": "log",
                              "msg": f"Fetched {len(prod_ogs)} PROD OGs for remap",
                              "level": "info"})
                    except Exception as exc:
                        emit({"type": "log",
                              "msg": f"⚠ Could not fetch PROD OGs for remap: {exc}",
                              "level": "warn"})

            if prod_ogs:
                client.build_og_remap(prod_ogs)
                emit({"type": "log",
                      "msg": f"OG ID remap ready — {len(client._og_prod_to_uat)} PROD OGs mapped to UAT",
                      "level": "info"})
            else:
                emit({"type": "log",
                      "msg": "⚠ OG ID remap unavailable — check PROD connection settings.",
                      "level": "warn"})

            # Build PROD→UAT Smart Group ID remap for profile assignment translation.
            # Uses stored PROD SG data; falls back to fetching from PROD on-the-fly.
            prod_sgs = _data_store["prod"].get("smart_groups", {}).get("items", [])
            if not prod_sgs:
                prod_cfg = cfg.get("prod", {})
                if prod_cfg.get("server_url") and prod_cfg.get("api_key"):
                    emit({"type": "log",
                          "msg": "PROD Smart Group data not pre-fetched — fetching for SG ID remap…",
                          "level": "info"})
                    try:
                        prod_client = make_client(prod_cfg)
                        prod_sgs, _ = prod_client.get_smart_groups()
                        prod_client.cleanup()
                    except Exception as exc:
                        emit({"type": "log",
                              "msg": f"⚠ Could not fetch PROD Smart Groups for remap: {exc}",
                              "level": "warn"})

            if prod_sgs:
                client.build_sg_remap(prod_sgs)
                emit({"type": "log",
                      "msg": f"SG ID remap ready — {len(client._sg_prod_to_uat)} PROD SGs mapped to UAT",
                      "level": "info"})

            for warning in sync_warnings:
                emit({"type": "log", "msg": f"⚠ {warning}", "level": "warn"})

            for category in SYNC_ORDER:
                if category not in selections:
                    continue
                items = selections[category]
                if _cancel_event.is_set():
                    break
                if not isinstance(items, list):
                    continue

                cat_info = {"key": category, "total": len(items)}

                if category in MANUAL_ONLY:
                    results[category] = {"status": "skipped", "reason": MANUAL_ONLY[category], "count": len(items)}
                    emit({"type": "category_skipped", **cat_info, "reason": MANUAL_ONLY[category]})
                    continue

                if category not in SYNC_SUPPORTED:
                    results[category] = {"status": "skipped", "reason": "Automatic sync not supported.", "count": len(items)}
                    emit({"type": "category_skipped", **cat_info, "reason": "Not supported"})
                    continue

                creator = SYNC_SUPPORTED[category]
                if creator is None:
                    results[category] = {"status": "informational",
                                         "reason": "Org Type List is reference data — no action needed in UAT.",
                                         "count": len(items)}
                    emit({"type": "category_skipped", **cat_info, "reason": "Informational only"})
                    continue

                # Topological sort for OGs ensures parents are created before children
                if category == "organizational_groups":
                    items = _topo_sort_ogs(items)
                    emit({"type": "log",
                          "msg": f"Sorted {len(items)} OGs by parent-child depth for creation order",
                          "level": "info"})

                emit({"type": "category_start", **cat_info})
                success_count = 0
                failed: list = []

                for i in range(0, len(items), chunk_size):
                    if _cancel_event.is_set():
                        break
                    for item in items[i: i + chunk_size]:
                        if _cancel_event.is_set():
                            break
                        item_name = (item.get("Name") or item.get("name")
                                     or item.get("ProfileName") or item.get("SmartGroupName")
                                     or item.get("TagName") or f"item[{i}]")
                        try:
                            creator(item)
                            success_count += 1
                            emit({"type": "item_done", "key": category, "name": item_name})
                        except InterruptedError:
                            break
                        except Exception as e:
                            failed.append({"name": item_name, "error": str(e)})
                            emit({"type": "item_error", "key": category,
                                  "name": item_name, "error": str(e)})

                results[category] = {"status": "done", "success": success_count,
                                     "failed": len(failed), "failures": failed[:50]}
                emit({"type": "category_done", "key": category,
                      "success": success_count, "failed": len(failed)})

            client.cleanup()

            if _cancel_event.is_set():
                emit({"type": "cancelled"})
            else:
                emit({"type": "complete", "ok": True, "results": results,
                      "warnings": sync_warnings})

            eq.put(None)

        t = threading.Thread(target=run, daemon=True)
        t.start()

        while True:
            event = eq.get()
            if event is None:
                break
            yield _sse(event)

    headers = {"X-Accel-Buffering": "no", "Cache-Control": "no-cache",
               "Access-Control-Allow-Origin": "*"}
    return Response(stream_with_context(generate()),
                    content_type="text/event-stream", headers=headers)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
