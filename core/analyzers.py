import re
import zipfile
from pathlib import Path
from .utils import printable_strings

PERMISSION_RE = re.compile(r"android\.permission\.[A-Z0-9_]+")
PACKAGE_RE = re.compile(r"\bpackage\s*=\s*['\"]([^'\"]+)")

PATTERNS = {
    "Accessibility": [
        "android.accessibilityservice.AccessibilityService",
        "canRetrieveWindowContent", "canPerformGestures",
        "onAccessibilityEvent", "AccessibilityEvent"
    ],
    "MediaProjection / capture écran": [
        "MediaProjection", "createScreenCaptureIntent",
        "ImageReader", "acquireLatestImage", "onScreenShot"
    ],
    "VPN": ["android.net.VpnService", "BIND_VPN_SERVICE", "addRoute"],
    "Device Admin": [
        "DeviceAdminReceiver", "force-lock", "reset-password",
        "wipe-data", "watch-login"
    ],
    "Installation d'application": [
        "REQUEST_INSTALL_PACKAGES", "PackageInstaller",
        "ACTION_INSTALL_PACKAGE"
    ],
    "Données / réseau": [
        "HttpURLConnection", "Socket", "OkHttpClient",
        "WebSocket", "content://"
    ],
    "Démarrage automatique": [
        "RECEIVE_BOOT_COMPLETED", "BOOT_COMPLETED"
    ]
}

def analyze_archive(apk_path, extract_dir, max_extract_mb=500, max_file_mb=100):
    findings = []
    inventory = {"dex": [], "native": [], "xml": [], "assets": [], "other": []}
    manifest_bytes = b""
    total = 0
    max_total = max_extract_mb * 1024 * 1024
    max_file = max_file_mb * 1024 * 1024

    with zipfile.ZipFile(apk_path) as zf:
        try:
            bad = zf.testzip()
            if bad:
                findings.append({
                    "severity": "info", "category": "Archive",
                    "title": "Entrée ZIP illisible ou chiffrée",
                    "evidence": f"testzip signale : {bad}",
                    "interpretation": "Peut être un fichier chiffré ou endommagé; à vérifier."
                })
        except Exception as exc:
            findings.append({
                "severity": "info", "category": "Archive",
                "title": "Vérification ZIP partielle",
                "evidence": str(exc),
                "interpretation": "Une entrée peut être chiffrée ou non lisible par zipfile; cela ne prouve pas une corruption."
            })

        for info in zf.infolist():
            name = info.filename
            if info.is_dir():
                continue
            low = name.lower()
            if name == "AndroidManifest.xml":
                try:
                    manifest_bytes = zf.read(info)
                except Exception:
                    pass
            if low.endswith(".dex"):
                inventory["dex"].append({"name": name, "size": info.file_size})
            elif low.endswith(".so"):
                inventory["native"].append({"name": name, "size": info.file_size})
            elif low.endswith(".xml"):
                inventory["xml"].append({"name": name, "size": info.file_size})
            elif name.startswith("assets/"):
                inventory["assets"].append({"name": name, "size": info.file_size})
            else:
                inventory["other"].append({"name": name, "size": info.file_size})

            # Extract only bounded, safe artifacts; no path traversal.
            if info.file_size > max_file or total + info.file_size > max_total:
                continue
            target = (extract_dir / name).resolve()
            if extract_dir.resolve() not in target.parents and target != extract_dir.resolve():
                findings.append({
                    "severity": "high", "category": "Archive",
                    "title": "Chemin ZIP dangereux",
                    "evidence": name,
                    "interpretation": "Entrée dont le chemin sort du dossier d'extraction."
                })
                continue
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as dst:
                    while True:
                        chunk = src.read(1024 * 1024)
                        if not chunk:
                            break
                        dst.write(chunk)
                total += info.file_size
            except Exception as exc:
                findings.append({
                    "severity": "info", "category": "Extraction",
                    "title": "Fichier non extrait",
                    "evidence": f"{name}: {exc}",
                    "interpretation": "Fichier ignoré; vérifier s'il est chiffré ou invalide."
                })

    manifest_text = manifest_bytes.decode("utf-8", errors="ignore")
    # Binary XML often stores strings in UTF-8/UTF-16; inspect both safely.
    manifest_strings = set(printable_strings(manifest_bytes, 4))
    manifest_strings.update(
        s.decode("utf-16le", errors="ignore")
        for s in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", manifest_bytes)
    )
    manifest_text += "\n" + "\n".join(manifest_strings)

    permissions = sorted(set(PERMISSION_RE.findall(manifest_text)))
    package_match = PACKAGE_RE.search(manifest_text)
    package = package_match.group(1) if package_match else None

    for permission in permissions:
        findings.append({
            "severity": "info", "category": "Permission",
            "title": permission,
            "evidence": permission,
            "interpretation": "Permission déclarée; son usage effectif n'est pas établi."
        })

    all_strings = set(manifest_strings)
    for item in inventory["xml"] + inventory["assets"]:
        p = extract_dir / item["name"]
        if p.is_file() and p.stat().st_size <= max_file:
            try:
                raw = p.read_bytes()
                all_strings.update(printable_strings(raw, 5))
                all_strings.update(
                    s.decode("utf-16le", errors="ignore")
                    for s in re.findall(rb"(?:[\x20-\x7e]\x00){5,}", raw)
                )
            except Exception:
                pass

    for group, terms in PATTERNS.items():
        matched = sorted(t for t in terms if any(t.lower() in s.lower() for s in all_strings))
        if matched:
            findings.append({
                "severity": "medium" if group in ("Accessibility", "MediaProjection / capture écran", "VPN", "Device Admin") else "low",
                "category": "Capacité potentielle",
                "title": group,
                "evidence": matched,
                "interpretation": "Chaînes ou références détectées; confirmer dans le code et le flux d'exécution."
            })

    return {
        "package": package,
        "permissions": permissions,
        "manifest_strings": sorted(manifest_strings)[:500],
        "inventory": inventory,
        "findings": findings
    }
