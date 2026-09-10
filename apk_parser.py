"""
Person A Module — Ingestion & Parsing
Android Malware Static Analysis Framework

Responsibilities:
  1. APK intake & validation
  2. AndroidManifest.xml deep parsing
  3. Certificate & signing analysis (incl. debug-cert detection)
  4. Resource & asset inspection (embedded payload detection)
  5. Structural/packaging anomaly checks
  6. Unified JSON output — the contract handed to Person B / Person C

Usage:
    python apk_parser.py <path_to_apk> [-o output.json]
"""

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path

from androguard.core.apk import APK

# ----------------------------------------------------------------------
# Known indicators — tune these as you learn more during the project
# ----------------------------------------------------------------------

DEBUG_CERT_SUBJECTS = ["androiddebugkey", "cn=android debug"]

SUSPICIOUS_EMBEDDED_EXTENSIONS = {".dex", ".so", ".jar", ".apk", ".exe", ".sh"}

PERSISTENCE_INTENT_ACTIONS = {
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.QUICKBOOT_POWERON",
    "android.intent.action.MY_PACKAGE_REPLACED",
}


# ----------------------------------------------------------------------
# 1. APK intake & validation
# ----------------------------------------------------------------------

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_of_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_apk(path):
    """Raise ValueError with a clear reason if this isn't a usable APK."""
    if not Path(path).exists():
        raise ValueError("File does not exist")
    if not zipfile.is_zipfile(path):
        raise ValueError("Not a valid ZIP/APK container (corrupted or not an APK)")
    with zipfile.ZipFile(path) as z:
        bad_file = z.testzip()
        if bad_file is not None:
            raise ValueError(f"Corrupted entry inside archive: {bad_file}")
        names = z.namelist()
        if "AndroidManifest.xml" not in names:
            raise ValueError("Missing AndroidManifest.xml — not a valid APK")
        if "classes.dex" not in names and not any(
            n.startswith("classes") and n.endswith(".dex") for n in names
        ):
            raise ValueError("No classes.dex found — not a valid APK")
    return True


# ----------------------------------------------------------------------
# 2. AndroidManifest.xml deep parsing
# ----------------------------------------------------------------------

def _is_exported(apk, tag, name):
    """
    Determine if a component is exported.
    Android default: if the component has an intent-filter and no explicit
    'exported' attribute, it is exported by default (pre-API 31 behavior
    still relevant for many real-world apps).
    """
    val = apk.get_element(tag, "exported", name=name)
    if val is not None:
        return str(val).lower() == "true"
    # fall back: exported by default if it declares an intent-filter
    return apk.get_intent_filters(tag, name) != {}


def get_intent_filters_summary(apk, tag, name):
    filters = apk.get_intent_filters(tag, name)
    return filters if filters else {}


def extract_manifest_info(apk: APK):
    activities = apk.get_activities()
    services = apk.get_services()
    receivers = apk.get_receivers()
    providers = apk.get_providers()

    def component_details(tag, names):
        details = []
        for n in names:
            exported = _is_exported(apk, tag, n)
            intent_filters = get_intent_filters_summary(apk, tag, n)
            details.append({
                "name": n,
                "exported": exported,
                "has_permission": apk.get_element(tag, "permission", name=n) is not None,
                "intent_filters": intent_filters,
            })
        return details

    activity_details = component_details("activity", activities)
    service_details = component_details("service", services)
    receiver_details = component_details("receiver", receivers)

    # Security finding: exported + no permission guard = any app can invoke it
    unprotected_exported = [
        {"type": t, "name": d["name"]}
        for t, details in [("activity", activity_details),
                            ("service", service_details),
                            ("receiver", receiver_details)]
        for d in details
        if d["exported"] and not d["has_permission"]
    ]

    # Persistence indicator: BOOT_COMPLETED receiver
    persistence_receivers = [
        d["name"] for d in receiver_details
        if any(
            action in PERSISTENCE_INTENT_ACTIONS
            for actions in d["intent_filters"].get("action", [])
            for action in [actions] if isinstance(actions, str)
        ) or any(
            act in PERSISTENCE_INTENT_ACTIONS
            for act in d["intent_filters"].get("action", [])
        )
    ]

    return {
        "package_name": apk.get_package(),
        "app_name": apk.get_app_name(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "max_sdk": apk.get_max_sdk_version(),
        "permissions": apk.get_permissions(),
        "declared_permissions": list(apk.get_declared_permissions()),
        "custom_permissions": [
            p for p in apk.get_declared_permissions()
            if not p.startswith("android.permission.")
        ],
        "activities": activity_details,
        "services": service_details,
        "receivers": receiver_details,
        "providers": providers,
        "main_activity": apk.get_main_activity(),
        "is_multidex": apk.is_multidex(),
        "libraries": apk.get_libraries(),
        "uses_features": apk.get_features(),
        # --- security findings ---
        "unprotected_exported_components": unprotected_exported,
        "has_persistence_receiver": len(persistence_receivers) > 0,
        "persistence_receivers": persistence_receivers,
    }


# ----------------------------------------------------------------------
# 3. Certificate & signing analysis
# ----------------------------------------------------------------------

def extract_cert_info(apk: APK):
    certs = []
    try:
        for cert in apk.get_certificates():
            subject = str(cert.subject.human_friendly)
            issuer = str(cert.issuer.human_friendly)
            is_debug = any(marker in subject.lower() for marker in DEBUG_CERT_SUBJECTS)

            certs.append({
                "subject": subject,
                "issuer": issuer,
                "serial_number": str(cert.serial_number),
                "not_before": str(cert.not_valid_before),
                "not_after": str(cert.not_valid_after),
                "sha256_fingerprint": cert.sha256_fingerprint.replace(" ", ""),
                "is_self_signed": subject == issuer,
                "is_debug_certificate": is_debug,
            })
    except Exception as e:
        certs.append({"error": f"Certificate parsing failed: {e}"})
    return certs


def get_signature_schemes(apk: APK):
    return {
        "v1_signed": apk.is_signed_v1(),
        "v2_signed": apk.is_signed_v2(),
        "v3_signed": apk.is_signed_v3(),
    }


# ----------------------------------------------------------------------
# 4. Resource & asset inspection
# ----------------------------------------------------------------------

def inspect_assets_and_resources(apk_path):
    findings = {
        "suspicious_embedded_files": [],
        "native_libraries": [],
        "architectures": set(),
        "asset_file_count": 0,
        "res_file_count": 0,
    }

    with zipfile.ZipFile(apk_path) as z:
        for info in z.infolist():
            name = info.filename

            if name.startswith("assets/"):
                findings["asset_file_count"] += 1
            if name.startswith("res/"):
                findings["res_file_count"] += 1

            if name.startswith("lib/"):
                findings["native_libraries"].append(name)
                parts = name.split("/")
                if len(parts) > 1:
                    findings["architectures"].add(parts[1])

            # Flag suspicious embedded payloads outside the expected dex slots
            suffix = Path(name).suffix.lower()
            if suffix in SUSPICIOUS_EMBEDDED_EXTENSIONS:
                is_expected_dex = name in ("classes.dex",) or (
                    name.startswith("classes") and suffix == ".dex"
                )
                is_expected_native_lib = name.startswith("lib/") and suffix == ".so"
                if not is_expected_dex and not is_expected_native_lib:
                    findings["suspicious_embedded_files"].append({
                        "path": name,
                        "size_bytes": info.file_size,
                        "compressed_size_bytes": info.compress_size,
                    })

    findings["architectures"] = list(findings["architectures"])
    return findings


# ----------------------------------------------------------------------
# 5. Structural/packaging anomaly checks
# ----------------------------------------------------------------------

def check_structural_anomalies(apk_path):
    anomalies = []

    with zipfile.ZipFile(apk_path) as z:
        names = z.namelist()

        # Duplicate entries (a known Android zip-parsing confusion vector)
        seen = set()
        duplicates = set()
        for n in names:
            if n in seen:
                duplicates.add(n)
            seen.add(n)
        if duplicates:
            anomalies.append({
                "type": "duplicate_zip_entries",
                "detail": list(duplicates),
                "severity": "high",
            })

        # Zip bomb heuristic: absurd compression ratio on any single entry
        for info in z.infolist():
            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > 500 and info.file_size > 10_000_000:
                    anomalies.append({
                        "type": "possible_zip_bomb",
                        "detail": f"{info.filename} ratio={ratio:.0f}x",
                        "severity": "high",
                    })

        # Unusually large file for an APK (rough heuristic, tune later)
        total_uncompressed = sum(i.file_size for i in z.infolist())
        if total_uncompressed > 2_000_000_000:  # 2 GB uncompressed
            anomalies.append({
                "type": "abnormally_large_uncompressed_size",
                "detail": f"{total_uncompressed} bytes",
                "severity": "medium",
            })

    return anomalies


# ----------------------------------------------------------------------
# 6. Orchestration — produces the unified JSON contract
# ----------------------------------------------------------------------

def parse_apk(apk_path):
    apk_path = str(apk_path)
    result = {
        "file_name": Path(apk_path).name,
        "file_size_bytes": Path(apk_path).stat().st_size if Path(apk_path).exists() else None,
        "sha256": None,
        "md5": None,
        "status": "success",
        "error": None,
    }

    try:
        validate_apk(apk_path)
    except ValueError as e:
        result["status"] = "invalid"
        result["error"] = str(e)
        return result

    result["sha256"] = sha256_of_file(apk_path)
    result["md5"] = md5_of_file(apk_path)

    try:
        apk = APK(apk_path)
        result["manifest"] = extract_manifest_info(apk)
        result["certificates"] = extract_cert_info(apk)
        result["signature_schemes"] = get_signature_schemes(apk)
        result["is_signed"] = apk.is_signed()
        result["assets_and_resources"] = inspect_assets_and_resources(apk_path)
        result["structural_anomalies"] = check_structural_anomalies(apk_path)
    except Exception as e:
        result["status"] = "parse_error"
        result["error"] = f"{type(e).__name__}: {e}"

    return result


# ----------------------------------------------------------------------
# CLI entry point
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Person A — APK Ingestion & Parsing Module")
    parser.add_argument("apk_path", help="Path to the APK file")
    parser.add_argument("-o", "--output", help="Write JSON output to this file instead of stdout")
    args = parser.parse_args()

    output = parse_apk(args.apk_path)
    text = json.dumps(output, indent=2, default=str)

    if args.output:
        Path(args.output).write_text(text)
        print(f"Wrote result to {args.output}")
    else:
        print(text)

    sys.exit(0 if output["status"] == "success" else 1)


if __name__ == "__main__":
    main()
