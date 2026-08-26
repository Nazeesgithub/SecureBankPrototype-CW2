import json
import subprocess
from datetime import datetime

PROFILE_QUERY_SCRIPT = (
    "Get-NetFirewallProfile | "
    "Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | "
    "ConvertTo-Json"
)

APP_RULE_QUERY_SCRIPT = (
    "Get-NetFirewallRule -Enabled True | "
    "Where-Object { $_.DisplayName -match 'python|flask|node' } | "
    "Select-Object DisplayName, Direction, Action, Profile | "
    "ConvertTo-Json"
)

APP_PORTS = [
    {"port": 5000, "protocol": "TCP", "purpose": "Flask backend (HTTPS)"},
    {"port": 5173, "protocol": "TCP", "purpose": "React frontend (Vite dev server)"},
]


def _run_powershell(script: str):
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "PowerShell command failed.")
    return result.stdout.strip()


def _parse_json_array(raw: str):
    if not raw:
        return []
    parsed = json.loads(raw)
    if isinstance(parsed, dict):
        return [parsed]
    return parsed


def get_firewall_profiles():
    raw = _run_powershell(PROFILE_QUERY_SCRIPT)
    profiles = _parse_json_array(raw)
    result = {}
    for profile in profiles:
        name = profile.get("Name", "")
        result[name.lower()] = {
            "enabled": bool(profile.get("Enabled")),
            "defaultInboundAction": "Block" if profile.get("DefaultInboundAction") == 1 else "Allow",
            "defaultOutboundAction": "Block" if profile.get("DefaultOutboundAction") == 1 else "Allow",
        }
    return result


def get_app_related_rules():
    raw = _run_powershell(APP_RULE_QUERY_SCRIPT)
    rules = _parse_json_array(raw)
    action_map = {2: "Allow", 4: "Block"}
    direction_map = {1: "Inbound", 2: "Outbound"}
    seen = set()
    deduped = []
    for rule in rules:
        name = rule.get("DisplayName", "")
        direction = direction_map.get(rule.get("Direction"), str(rule.get("Direction")))
        action = action_map.get(rule.get("Action"), str(rule.get("Action")))
        key = (name, direction, action)
        if key in seen:
            continue
        seen.add(key)
        deduped.append({"name": name, "direction": direction, "action": action})
    return deduped


def firewall_status_payload():
    fetched_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        profiles = get_firewall_profiles()
        overall_enabled = any(p["enabled"] for p in profiles.values()) if profiles else False
        try:
            rules = get_app_related_rules()
            rules_error = None
        except Exception as exc:  # noqa: BLE001 - surface any PowerShell failure to the UI
            rules = []
            rules_error = str(exc)

        return {
            "ok": True,
            "source": "Windows Defender Firewall (live query via PowerShell)",
            "firewallEnabled": overall_enabled,
            "domainProfile": profiles.get("domain"),
            "privateProfile": profiles.get("private"),
            "publicProfile": profiles.get("public"),
            "appRules": rules,
            "appRulesError": rules_error,
            "appPorts": APP_PORTS,
            "lastUpdated": fetched_at,
        }
    except Exception as exc:  # noqa: BLE001 - surface any PowerShell failure to the UI
        return {
            "ok": False,
            "message": f"Unable to read Windows Defender Firewall status: {exc}",
            "source": "Windows Defender Firewall (live query via PowerShell)",
            "appPorts": APP_PORTS,
            "lastUpdated": fetched_at,
        }
