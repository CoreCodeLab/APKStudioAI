"""
Report Generator for APKStudioAI 2.1
Generates HTML, JSON, and TXT reports
"""
import json
import html
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List


class ReportGenerator:
    def __init__(self, project_dir: Path):
        self.project_dir = Path(project_dir)
        self.reports_dir = self.project_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_all(self, result: Dict[str, Any]) -> Dict[str, str]:
        """Generate all report formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        apk_name = Path(result.get('apk_path', 'unknown')).stem
        base_name = f"{apk_name}_{timestamp}"

        paths = {}
        paths['html'] = self.generate_html(result, base_name)
        paths['json'] = self.generate_json(result, base_name)
        paths['txt'] = self.generate_txt(result, base_name)

        return paths

    def generate_html(self, result: Dict[str, Any], base_name: str) -> str:
        """Generate professional HTML report"""
        output_path = self.reports_dir / f"{base_name}.html"

        html_content = self._build_html_report(result)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return str(output_path)

    def generate_json(self, result: Dict[str, Any], base_name: str) -> str:
        """Generate JSON report"""
        output_path = self.reports_dir / f"{base_name}.json"

        # Make JSON serializable
        serializable = self._make_serializable(result)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(serializable, f, indent=2, ensure_ascii=False, default=str)

        return str(output_path)

    def generate_txt(self, result: Dict[str, Any], base_name: str) -> str:
        """Generate text report"""
        output_path = self.reports_dir / f"{base_name}.txt"

        txt_content = self._build_txt_report(result)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(txt_content)

        return str(output_path)

    def _make_serializable(self, obj: Any) -> Any:
        """Convert object to JSON serializable"""
        if isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        elif isinstance(obj, (list, tuple)):
            return [self._make_serializable(item) for item in obj]
        elif isinstance(obj, dict):
            return {key: self._make_serializable(value) for key, value in obj.items()}
        elif hasattr(obj, '__dict__'):
            return self._make_serializable(obj.__dict__)
        else:
            return str(obj)

    def _build_html_report(self, result: Dict[str, Any]) -> str:
        """Build complete HTML report"""
        risk = result.get('risk', {})
        score = risk.get('score', 0)
        level = risk.get('risk_level', 'UNKNOWN')
        manifest = result.get('manifest', {})
        perm_analysis = result.get('permission_analysis', {})
        malware = result.get('malware', {})
        network = result.get('network', {})
        native = result.get('native', {})
        jni = result.get('jni', {})
        strings = result.get('strings', {})
        ai = result.get('ai_analysis', {})

        # Risk color
        risk_colors = {
            'FAIBLE': '#4caf50', 'MODÉRÉ': '#ff9800', 'ÉLEVÉ': '#ff5722',
            'TRÈS ÉLEVÉ': '#e65100', 'CRITIQUE': '#d32f2f', 'UNKNOWN': '#9e9e9e'
        }
        risk_color = risk_colors.get(level, '#9e9e9e')

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APKStudioAI 2.1 - Rapport d'analyse: {html.escape(Path(result.get('apk_path', '')).name)}</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #1e3a5f 0%, #2c5f8a 100%); color: white; padding: 30px; }}
        .header h1 {{ margin: 0; font-size: 2.5em; font-weight: 300; }}
        .header .subtitle {{ margin-top: 10px; opacity: 0.9; }}
        .header .meta {{ margin-top: 15px; font-size: 0.9em; opacity: 0.8; }}
        .risk-banner {{ padding: 20px 30px; display: flex; align-items: center; gap: 30px; border-bottom: 1px solid #eee; }}
        .risk-score {{ font-size: 4em; font-weight: 700; color: {risk_color}; }}
        .risk-level {{ font-size: 1.5em; text-transform: uppercase; color: {risk_color}; font-weight: 600; }}
        .risk-desc {{ flex: 1; }}
        .content {{ padding: 30px; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{ color: #1e3a5f; border-bottom: 2px solid #1e3a5f; padding-bottom: 10px; margin-bottom: 20px; font-weight: 500; }}
        .section h3 {{ color: #2c5f8a; margin-top: 25px; margin-bottom: 10px; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; color: #333; }}
        tr:hover {{ background: #f8f9fa; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 0.8em; font-weight: 600; text-transform: uppercase; }}
        .badge-critical {{ background: #ffebee; color: #c62828; }}
        .badge-high {{ background: #fff3e0; color: #ef6c00; }}
        .badge-medium {{ background: #fffde7; color: #f9a825; }}
        .badge-low {{ background: #e8f5e9; color: #2e7d32; }}
        .badge-normal {{ background: #f5f5f5; color: #616161; }}
        .badge-confirmed {{ background: #ffcdd2; color: #b71c1c; }}
        .badge-likely {{ background: #ffe0b2; color: #e65100; }}
        .badge-possible {{ background: #fff9c4; color: #f9a825; }}
        .badge-suspected {{ background: #e8f5e9; color: #2e7d32; }}
        .code {{ font-family: 'Consolas', 'Monaco', monospace; background: #f5f5f5; padding: 15px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }}
        .card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #1e3a5f; }}
        .card h4 {{ margin: 0 0 10px 0; color: #1e3a5f; font-size: 1em; }}
        .card .value {{ font-size: 2em; font-weight: 700; color: #333; }}
        .tree {{ font-family: 'Consolas', monospace; font-size: 0.9em; line-height: 1.8; }}
        .tree .folder {{ color: #1e3a5f; font-weight: 600; }}
        .tree .file {{ color: #333; margin-left: 20px; }}
        .tree .exported {{ color: #d32f2f; }}
        .tree .not-exported {{ color: #4caf50; }}
        .evidence-section {{ margin-bottom: 15px; }}
        .evidence-section h4 {{ margin: 0 0 10px 0; color: #2c5f8a; }}
        .footer {{ background: #f8f9fa; padding: 20px 30px; text-align: center; color: #666; font-size: 0.9em; border-top: 1px solid #eee; }}
        .collapsible {{ cursor: pointer; }}
        .collapsible-content {{ display: none; margin-top: 10px; }}
        .collapsible.open + .collapsible-content {{ display: block; }}
        .mitre-tag {{ background: #e3f2fd; color: #1565c0; padding: 2px 8px; border-radius: 3px; font-size: 0.8em; margin: 2px; display: inline-block; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>APKStudioAI 2.1</h1>
            <div class="subtitle">Rapport d'analyse statique de malware Android</div>
            <div class="meta">
                <strong>Fichier:</strong> {html.escape(Path(result.get('apk_path', '')).name)} |
                <strong>SHA256:</strong> {html.escape(result.get('sha256', 'N/A'))} |
                <strong>Date:</strong> {html.escape(result.get('scan_time', 'N/A'))}
            </div>
        </div>

        <div class="risk-banner">
            <div class="risk-score">{score}/100</div>
            <div>
                <div class="risk-level">{html.escape(level)}</div>
                <div class="risk-desc">{html.escape(risk.get('summary', {}).get('description', 'N/A'))}</div>
            </div>
        </div>

        <div class="content">
"""

        # APK Information
        html += self._html_section_apk_info(result, manifest)

        # Permissions
        html += self._html_section_permissions(perm_analysis)

        # Manifest Components
        html += self._html_section_manifest(manifest)

        # DEX Analysis
        html += self._html_section_dex(result.get('dex', {}))

        # Native Libraries
        html += self._html_section_native(native)

        # JNI Analysis
        html += self._html_section_jni(jni)

        # Network IOCs
        html += self._html_section_network(network, strings)

        # Malware Detections
        html += self._html_section_malware(malware)

        # AI Analysis
        html += self._html_section_ai(ai)

        # Risk Factors
        html += self._html_section_risk_factors(risk)

        html += """
        </div>
        <div class="footer">
            Généré par APKStudioAI 2.1 - Advanced Android Malware Analysis Platform<br>
            Analyse statique uniquement - Aucun code n'a été exécuté
        </div>
    </div>
    <script>
        document.querySelectorAll('.collapsible').forEach(btn => {
            btn.addEventListener('click', function() {
                this.classList.toggle('open');
            });
        });
    </script>
</body>
</html>"""

        return html

    def _html_section_apk_info(self, result: Dict, manifest: Dict) -> str:
        """HTML section for APK info"""
        return f"""
        <div class="section">
            <h2>📱 Informations APK</h2>
            <div class="grid">
                <div class="card"><h4>Package</h4><div class="value">{html.escape(manifest.get('package', 'N/A'))}</div></div>
                <div class="card"><h4>Version</h4><div class="value">{html.escape(manifest.get('version_name', 'N/A'))}</div></div>
                <div class="card"><h4>Version Code</h4><div class="value">{html.escape(str(manifest.get('version_code', 'N/A')))}</div></div>
                <div class="card"><h4>Min SDK</h4><div class="value">{html.escape(str(manifest.get('min_sdk', 'N/A')))}</div></div>
                <div class="card"><h4>Target SDK</h4><div class="value">{html.escape(str(manifest.get('target_sdk', 'N/A')))}</div></div>
                <div class="card"><h4>Taille</h4><div class="value">{self._format_size(Path(result.get('apk_path', '')).stat().st_size if Path(result.get('apk_path', '')).exists() else 0)}</div></div>
            </div>
        </div>
"""

    def _html_section_permissions(self, perm_analysis: Dict) -> str:
        """HTML section for permissions"""
        html = """
        <div class="section">
            <h2>🔐 Analyse des Permissions</h2>
            <div class="grid">
"""
        for level in ['critical', 'high', 'medium', 'low', 'normal']:
            count = len(perm_analysis.get('by_risk', {}).get(level, []))
            color = {'critical': '#d32f2f', 'high': '#f57c00', 'medium': '#fbc02d', 'low': '#388e3c', 'normal': '#9e9e9e'}.get(level, '#9e9e9e')
            html += f'<div class="card" style="border-left-color: {color};"><h4>{level.capitalize()}</h4><div class="value" style="color: {color};">{count}</div></div>'

        html += """
            </div>
            <h3>Détail des permissions</h3>
            <table>
                <thead><tr><th>Permission</th><th>Risque</th><th>Description</th><th>Capacité</th><th>MITRE ATT&CK</th></tr></thead>
                <tbody>
"""

        for level in ['critical', 'high', 'medium', 'low', 'normal']:
            for perm in perm_analysis.get('by_risk', {}).get(level, []):
                mitre_tags = ''.join(f'<span class="mitre-tag">{html.escape(m)}</span>' for m in perm.get('mitre', []))
                html += f"""<tr>
                    <td><code>{html.escape(perm.get('permission', ''))}</code></td>
                    <td><span class="badge badge-{level}">{level.upper()}</span></td>
                    <td>{html.escape(perm.get('description', ''))}</td>
                    <td>{html.escape(perm.get('capability', ''))}</td>
                    <td>{mitre_tags}</td>
                </tr>"""

        html += """
                </tbody>
            </table>
        </div>
"""
        return html

    def _html_section_manifest(self, manifest: Dict) -> str:
        """HTML section for manifest components"""
        html = """
        <div class="section">
            <h2>📋 Composants AndroidManifest.xml</h2>
            <table>
                <thead><tr><th>Type</th><th>Nom</th><th>Exported</th><th>Permission</th></tr></thead>
                <tbody>
"""

        for comp_type in ['activities', 'services', 'receivers', 'providers']:
            for comp in manifest.get(comp_type, []):
                exported = "✓ Oui" if comp.get('exported') else "✗ Non"
                exp_class = "exported" if comp.get('exported') else "not-exported"
                perm = comp.get('permission', '—')
                html += f"""<tr>
                    <td>{html.escape(comp_type[:-1].capitalize())}</td>
                    <td><code>{html.escape(comp.get('name', 'N/A'))}</code></td>
                    <td class="{exp_class}">{html.escape(exported)}</td>
                    <td>{html.escape(perm)}</td>
                </tr>"""

        html += """
                </tbody>
            </table>
            <h3>Propriétés de l'application</h3>
            <div class="grid">
"""

        props = [
            ('Debuggable', str(manifest.get('debuggable', False))),
            ('Allow Backup', str(manifest.get('allow_backup', True))),
            ('Supports Screens', str(manifest.get('supports_screens', 'N/A'))),
        ]
        for label, value in props:
            html += f'<div class="card"><h4>{label}</h4><div class="value">{html.escape(value)}</div></div>'

        html += """
            </div>
        </div>
"""
        return html

    def _html_section_dex(self, dex: Dict) -> str:
        """HTML section for DEX analysis"""
        html = """
        <div class="section">
            <h2>📦 Analyse DEX</h2>
            <table>
                <thead><tr><th>Fichier</th><th>SHA256</th><th>Taille</th><th>Valide</th><th>Classes</th><th>Méthodes</th><th>API Level</th></tr></thead>
                <tbody>
"""
        for dex_file in dex.get('dex_files', []):
            html += f"""<tr>
                <td><code>{html.escape(dex_file.get('name', ''))}</code></td>
                <td><code>{html.escape(dex_file.get('sha256', '')[:32])}...</code></td>
                <td>{self._format_size(dex_file.get('size', 0))}</td>
                <td>{'✓' if dex_file.get('valid') else '✗'}</td>
                <td>{dex_file.get('class_count', 0)}</td>
                <td>{dex_file.get('method_count', 0)}</td>
                <td>{dex_file.get('api_level', 'N/A')}</td>
            </tr>"""

        html += """
                </tbody>
            </table>
        </div>
"""
        return html

    def _html_section_native(self, native: Dict) -> str:
        """HTML section for native libraries"""
        html = """
        <div class="section">
            <h2>🔧 Bibliothèques Natives (ELF)</h2>
"""
        if not native.get('libraries'):
            html += "<p>Aucune bibliothèque native détectée.</p>"
        else:
            html += """
            <table>
                <thead><tr><th>Nom</th><th>Architecture</th><th>Chemin</th><th>Taille</th><th>Méthodes JNI</th><th>Exports</th><th>Imports</th></tr></thead>
                <tbody>
"""
            for lib in native.get('libraries', []):
                html += f"""<tr>
                    <td><code>{html.escape(lib.get('name', ''))}</code></td>
                    <td>{html.escape(lib.get('architecture', ''))}</td>
                    <td><code>{html.escape(lib.get('path', ''))}</code></td>
                    <td>{self._format_size(lib.get('size', 0))}</td>
                    <td>{len(lib.get('native_methods', []))}</td>
                    <td>{len(lib.get('exports', []))}</td>
                    <td>{len(lib.get('imports', []))}</td>
                </tr>"""

            html += """
                </tbody>
            </table>
"""

            # Details for each library
            for lib in native.get('libraries', []):
                html += f"""
            <div class="collapsible" style="margin-top: 20px; padding: 10px; background: #f8f9fa; border-radius: 4px;">
                <strong>📄 {html.escape(lib.get('name', ''))} - Détails</strong>
            </div>
            <div class="collapsible-content">
"""
                # ELF Header
                if lib.get('elf_header'):
                    eh = lib['elf_header']
                    html += f"""
                <h4>En-tête ELF</h4>
                <div class="grid">
                    <div class="card"><h4>Classe</h4><div class="value">{html.escape(str(eh.get('class', 'N/A')))}</div></div>
                    <div class="card"><h4>Endianness</h4><div class="value">{html.escape(str(eh.get('endianness', 'N/A')))}</div></div>
                    <div class="card"><h4>Machine</h4><div class="value">{html.escape(str(eh.get('machine', 'N/A')))}</div></div>
                    <div class="card"><h4>Type</h4><div class="value">{html.escape(str(eh.get('type', 'N/A')))}</div></div>
                    <div class="card"><h4>Entry Point</h4><div class="value">{html.escape(hex(eh.get('entry_point', 0)))}</div></div>
                </div>
"""
                # Sections
                if lib.get('sections'):
                    html += "<h4>Sections</h4><table><thead><tr><th>Nom</th><th>Type</th><th>Adresse</th><th>Taille</th><th>Flags</th></tr></thead><tbody>"
                    for sec in lib['sections'][:20]:
                        html += f"""<tr><td>{html.escape(sec.get('name', ''))}</td><td>{html.escape(str(sec.get('type', '')))}</td><td>{html.escape(hex(sec.get('addr', 0)))}</td><td>{html.escape(str(sec.get('size', 0)))}</td><td>{html.escape(str(sec.get('flags', '')))}</td></tr>"""
                    html += "</tbody></table>"

                # Imports
                if lib.get('imports'):
                    html += "<h4>Imports</h4><div class='code'>" + ", ".join(html.escape(i) for i in lib['imports'][:50]) + "</div>"

                # Exports
                if lib.get('exports'):
                    html += "<h4>Exports</h4><div class='code'>" + ", ".join(html.escape(e) for e in lib['exports'][:50]) + "</div>"

                # Strings
                if lib.get('interesting_strings'):
                    html += "<h4>Chaînes intéressantes</h4><div class='code'>" + "<br>".join(html.escape(s) for s in lib['interesting_strings'][:30]) + "</div>"

                html += "</div>"

        html += """
        </div>
"""
        return html

    def _html_section_jni(self, jni: Dict) -> str:
        """HTML section for JNI analysis"""
        html = """
        <div class="section">
            <h2>🔗 Analyse JNI</h2>
"""
        if not jni.get('libraries'):
            html += "<p>Aucune analyse JNI disponible.</p>"
        else:
            for lib_jni in jni.get('libraries', []):
                html += f"""
            <h3>Bibliothèque: {html.escape(lib_jni.get('library', ''))}</h3>
            <div class="grid">
                <div class="card"><h4>JNI_OnLoad</h4><div class="value">{'✓ Trouvé' if lib_jni.get('jni_onload', {}).get('found') else '✗ Non trouvé'}</div></div>
                <div class="card"><h4>RegisterNatives</h4><div class="value">{'✓ Trouvé' if lib_jni.get('register_natives', {}).get('found') else '✗ Non trouvé'}</div></div>
                <div class="card"><h4>Méthodes mappées</h4><div class="value">{len(lib_jni.get('mapped_methods', []))}</div></div>
            </div>
"""
                # JNI_OnLoad details
                jni_onload = lib_jni.get('jni_onload', {})
                if jni_onload.get('found'):
                    html += f"""
            <h4>JNI_OnLoad</h4>
            <div class="code">Adresse: {html.escape(hex(jni_onload.get('address', 0)))}\nSignature: {html.escape(str(jni_onload.get('signature', 'N/A')))}</div>
"""

                # RegisterNatives details
                reg_natives = lib_jni.get('register_natives', {})
                if reg_natives.get('found'):
                    html += f"""
            <h4>RegisterNatives</h4>
            <div class="code">Adresse: {html.escape(hex(reg_natives.get('address', 0)))}\nMéthodes enregistrées: {len(reg_natives.get('methods', []))}</div>
"""
                    # Methods table
                    if reg_natives.get('methods'):
                        html += """
            <table>
                <thead><tr><th>Classe Java</th><th>Méthode</th><th>Signature JNI</th><th>Fonction native</th><th>Adresse</th></tr></thead>
                <tbody>
"""
                        for m in reg_natives['methods'][:50]:
                            html += f"""<tr>
                                <td><code>{html.escape(m.get('class_name', ''))}</code></td>
                                <td><code>{html.escape(m.get('method_name', ''))}</code></td>
                                <td><code>{html.escape(m.get('signature', ''))}</code></td>
                                <td><code>{html.escape(m.get('native_function', ''))}</code></td>
                                <td>{html.escape(hex(m.get('address', 0)))}</td>
                            </tr>"""
                        html += "</tbody></table>"

                # Mapped methods
                if lib_jni.get('mapped_methods'):
                    html += """
            <h4>Méthodes mappées (Java ↔ Native)</h4>
            <table>
                <thead><tr><th>Classe Java</th><th>Méthode Java</th><th>Signature JNI</th><th>Fonction native</th><th>Adresse</th></tr></thead>
                <tbody>
"""
                    for m in lib_jni['mapped_methods'][:50]:
                        html += f"""<tr>
                            <td><code>{html.escape(m.get('java_class', ''))}</code></td>
                            <td><code>{html.escape(m.get('java_method', ''))}</code></td>
                            <td><code>{html.escape(m.get('jni_signature', ''))}</code></td>
                            <td><code>{html.escape(m.get('native_function', ''))}</code></td>
                            <td>{html.escape(hex(m.get('address', 0)))}</td>
                        </tr>"""
                    html += "</tbody></table>"

        html += """
        </div>
"""
        return html

    def _html_section_network(self, network: Dict, strings: Dict) -> str:
        """HTML section for network IOCs"""
        html = """
        <div class="section">
            <h2>🌐 Indicateurs de Compromission Réseau</h2>
            <div class="grid">
"""

        stats = [
            ('URLs', len(network.get('urls', []))),
            ('Domaines', len(network.get('domains', []))),
            ('Adresses IP', len(network.get('ips', []))),
            ('Firebase', len(network.get('firebase_config', []))),
            ('Telegram Bots', len(network.get('telegram_bots', []))),
            ('Config C2', len(network.get('c2_config', []))),
            ('WebSockets', len(network.get('websocket', []))),
            ('Chaînes décodées', len(strings.get('decoded_strings', []))),
        ]

        for label, value in stats:
            html += f'<div class="card"><h4>{label}</h4><div class="value">{value}</div></div>'

        html += """
            </div>
"""

        # URLs
        if network.get('urls'):
            html += """
            <h3>URLs détectées</h3>
            <table>
                <thead><tr><th>URL</th><th>Source</th></tr></thead>
                <tbody>
"""
            for url in network['urls'][:50]:
                html += f"<tr><td><code>{html.escape(url)}</code></td><td>Strings</td></tr>"
            html += "</tbody></table>"

        # Domains
        if network.get('domains'):
            html += """
            <h3>Domaines</h3>
            <table>
                <thead><tr><th>Domaine</th><th>Source</th></tr></thead>
                <tbody>
"""
            for domain in network['domains'][:50]:
                html += f"<tr><td><code>{html.escape(domain)}</code></td><td>Strings</td></tr>"
            html += "</tbody></table>"

        # IPs
        if network.get('ips'):
            html += """
            <h3>Adresses IP</h3>
            <table>
                <thead><tr><th>IP</th><th>Source</th></tr></thead>
                <tbody>
"""
            for ip in network['ips'][:20]:
                html += f"<tr><td><code>{html.escape(ip)}</code></td><td>Strings</td></tr>"
            html += "</tbody></table>"

        # Firebase
        if network.get('firebase_config'):
            html += """
            <h3>Configuration Firebase</h3>
            <div class="code">
"""
            for fb in network['firebase_config']:
                html += html.escape(json.dumps(fb, indent=2)) + "\n\n"
            html += "</div>"

        # Telegram
        if network.get('telegram_bots'):
            html += """
            <h3>⚠️ Bots Telegram détectés (C2 potentiel)</h3>
            <table>
                <thead><tr><th>Token/Config</th><th>Source</th></tr></thead>
                <tbody>
"""
            for tel in network['telegram_bots']:
                html += f"<tr><td><code>{html.escape(str(tel)[:100])}</code></td><td>Strings</td></tr>"
            html += "</tbody></table>"

        # C2 Config
        if network.get('c2_config'):
            html += """
            <h3>Configurations C2</h3>
            <div class="code">
"""
            for c2 in network['c2_config']:
                html += html.escape(json.dumps(c2, indent=2)) + "\n\n"
            html += "</div>"

        # Decoded strings
        if strings.get('decoded_strings'):
            html += """
            <h3>Chaînes décodées (Base64/Hex/XOR)</h3>
            <table>
                <thead><tr><th>Méthode</th><th>Original</th><th>Décodé</th></tr></thead>
                <tbody>
"""
            for ds in strings['decoded_strings'][:30]:
                html += f"""<tr>
                    <td><span class="badge badge-low">{html.escape(ds.get('method', '?'))}</span></td>
                    <td><code>{html.escape(ds.get('original', '')[:80])}...</code></td>
                    <td><code>{html.escape(ds.get('decoded', '')[:200])}</code></td>
                </tr>"""
            html += "</tbody></table>"

        html += """
        </div>
"""
        return html

    def _html_section_malware(self, malware: Dict) -> str:
        """HTML section for malware detections"""
        html = """
        <div class="section">
            <h2>🦠 Détections de Malware</h2>
            <div class="grid">
"""
        summary = malware.get('summary', {})
        for key in ['total', 'confirmed', 'likely', 'possible', 'suspected']:
            color = {'confirmed': '#d32f2f', 'likely': '#f57c00', 'possible': '#fbc02d', 'suspected': '#388e3c', 'total': '#1e3a5f'}.get(key, '#1e3a5f')
            html += f'<div class="card" style="border-left-color: {color};"><h4>{key.capitalize()}</h4><div class="value" style="color: {color};">{summary.get(key, 0)}</div></div>'

        html += """
            </div>

            <h3>Détections détaillées</h3>
            <table>
                <thead><tr><th>Catégorie</th><th>Classification</th><th>Confiance</th><th>Indicateurs</th><th>Requis</th><th>MITRE ATT&CK</th></tr></thead>
                <tbody>
"""
        for det in malware.get('detections', []):
            classification = det.get('classification', 'suspected')
            mitre_tags = ''.join(f'<span class="mitre-tag">{html.escape(m)}</span>' for m in det.get('mitre_techniques', []))
            html += f"""<tr>
                <td><strong>{html.escape(det.get('category', '').upper())}</strong></td>
                <td><span class="badge badge-{classification}">{classification.upper()}</span></td>
                <td>{det.get('confidence_score', 0)}%</td>
                <td>{det.get('matched_indicators', 0)}</td>
                <td>{det.get('required_indicators', 0)}</td>
                <td>{mitre_tags}</td>
            </tr>"""

        html += """
                </tbody>
            </table>
"""

        # Evidence details for confirmed/likely
        for det in malware.get('detections', []):
            if det.get('classification') in ['confirmed', 'likely']:
                html += f"""
            <div class="collapsible" style="margin-top: 15px;">
                <strong>🔍 Preuves pour {html.escape(det.get('category', '').upper())} ({html.escape(det.get('classification', ''))})</strong>
            </div>
            <div class="collapsible-content">
"""
                ev = det.get('evidence', {})
                for ev_type in ['indicators', 'capabilities', 'confirmed', 'hypothesis', 'unverifiable']:
                    items = ev.get(ev_type, [])
                    if items:
                        html += f"<h4>{ev_type.capitalize()}</h4>"
                        for item in items[:10]:
                            html += f"<div class='evidence-section'><code>{html.escape(json.dumps(item, ensure_ascii=False))}</code></div>"

                html += "</div>"

        # Matched signatures
        if malware.get('matched_signatures'):
            html += """
            <h3>Signatures connues détectées</h3>
            <table>
                <thead><tr><th>Signature</th><th>Type</th><th>Indicateurs matchés</th><th>Confiance</th></tr></thead>
                <tbody>
"""
            for sig in malware['matched_signatures']:
                html += f"""<tr>
                    <td><strong>{html.escape(sig.get('name', ''))}</strong></td>
                    <td>{html.escape(sig.get('type', ''))}</td>
                    <td>{sig.get('match_count', 0)}</td>
                    <td>{sig.get('confidence', 0)}%</td>
                </tr>"""
            html += "</tbody></table>"

        html += """
        </div>
"""
        return html

    def _html_section_ai(self, ai: Dict) -> str:
        """HTML section for AI analysis"""
        html = """
        <div class="section">
            <h2>🤖 Analyse IA (Ollama)</h2>
"""
        if ai.get('success'):
            analysis = ai.get('analysis', {})
            html += f"""
            <div class="grid">
                <div class="card"><h4>Catégorie</h4><div class="value">{html.escape(analysis.get('malware_category', 'inconnu').upper())}</div></div>
                <div class="card"><h4>Confiance</h4><div class="value">{analysis.get('confidence', 0)}%</div></div>
                <div class="card"><h4>Niveau de risque</h4><div class="value">{html.escape(analysis.get('risk_level', 'INCONNU'))}</div></div>
            </div>

            <h3>Résumé</h3>
            <div class="code">{html.escape(analysis.get('summary', 'N/A'))}</div>

            <h3>Détails</h3>
            <div class="code">{html.escape(analysis.get('details', 'N/A'))}</div>

            <h3>Indicateurs clés</h3>
            <ul>
"""
            for ind in analysis.get('key_indicators', []):
                html += f"<li>{html.escape(ind)}</li>"

            html += """
            </ul>

            <h3>Recommandations</h3>
            <ul>
"""
            for rec in analysis.get('recommendations', []):
                html += f"<li>{html.escape(rec)}</li>"

            html += """
            </ul>

            <h3>Limites</h3>
            <div class="code">{html.escape(analysis.get('limitations', 'N/A'))}</div>
"""
        else:
            html += f"<p class='badge badge-critical'>Échec de l'analyse IA: {html.escape(ai.get('error', 'Inconnue'))}</p>"

        html += """
        </div>
"""
        return html

    def _html_section_risk_factors(self, risk: Dict) -> str:
        """HTML section for risk factors"""
        html = """
        <div class="section">
            <h2>⚠️ Facteurs de risque identifiés</h2>
"""
        factors = risk.get('risk_factors', [])
        if not factors:
            html += "<p>Aucun facteur de risque majeur identifié.</p>"
        else:
            html += """
            <table>
                <thead><tr><th>Sévérité</th><th>Facteur</th><th>Détail</th></tr></thead>
                <tbody>
"""
            for rf in factors:
                severity = rf.get('severity', 'low').upper()
                html += f"""<tr>
                    <td><span class="badge badge-{rf.get('severity', 'low')}">{severity}</span></td>
                    <td><strong>{html.escape(rf.get('factor', ''))}</strong></td>
                    <td>{html.escape(rf.get('detail', ''))}</td>
                </tr>"""
            html += "</tbody></table>"

        html += """
        </div>
"""
        return html

    def _build_txt_report(self, result: Dict[str, Any]) -> str:
        """Build text report"""
        lines = []
        lines.append("=" * 80)
        lines.append("APKStudioAI 2.1 - RAPPORT D'ANALYSE STATIQUE ANDROID")
        lines.append("=" * 80)
        lines.append(f"Fichier: {Path(result.get('apk_path', '')).name}")
        lines.append(f"SHA256: {result.get('sha256', 'N/A')}")
        lines.append(f"Date: {result.get('scan_time', 'N/A')}")
        lines.append("")

        # Risk
        risk = result.get('risk', {})
        lines.append(f"SCORE DE RISQUE: {risk.get('score', 0)}/100 ({risk.get('risk_level', 'UNKNOWN')})")
        lines.append(f"Description: {risk.get('summary', {}).get('description', 'N/A')}")
        lines.append("")

        # APK Info
        manifest = result.get('manifest', {})
        lines.append("-" * 40)
        lines.append("INFORMATIONS APK")
        lines.append("-" * 40)
        lines.append(f"Package: {manifest.get('package', 'N/A')}")
        lines.append(f"Version: {manifest.get('version_name', 'N/A')} ({manifest.get('version_code', 'N/A')})")
        lines.append(f"Min SDK: {manifest.get('min_sdk', 'N/A')}")
        lines.append(f"Target SDK: {manifest.get('target_sdk', 'N/A')}")
        lines.append("")

        # Permissions
        perm = result.get('permission_analysis', {})
        lines.append("-" * 40)
        lines.append(f"PERMISSIONS ({perm.get('total_count', 0)} total)")
        lines.append("-" * 40)
        for level in ['critical', 'high', 'medium', 'low', 'normal']:
            perms = perm.get('by_risk', {}).get(level, [])
            if perms:
                lines.append(f"\n{level.upper()} ({len(perms)}):")
                for p in perms[:10]:
                    lines.append(f"  - {p.get('permission')}: {p.get('description')}")
        lines.append("")

        # Malware
        malware = result.get('malware', {})
        lines.append("-" * 40)
        lines.append("DÉTECTIONS MALWARE")
        lines.append("-" * 40)
        for det in malware.get('detections', []):
            lines.append(f"\n{det.get('category', '').upper()}: {det.get('classification', '').upper()} ({det.get('confidence_score', 0)}%)")
            lines.append(f"  Description: {det.get('description', 'N/A')}")
            if det.get('mitre_techniques'):
                lines.append(f"  MITRE: {', '.join(det['mitre_techniques'])}")
        lines.append("")

        # Network
        network = result.get('network', {})
        lines.append("-" * 40)
        lines.append("IOC RÉSEAU")
        lines.append("-" * 40)
        lines.append(f"URLs: {len(network.get('urls', []))}")
        lines.append(f"Domaines: {len(network.get('domains', []))}")
        lines.append(f"IPs: {len(network.get('ips', []))}")
        if network.get('telegram_bots'):
            lines.append(f"⚠️ Telegram Bots: {len(network['telegram_bots'])}")
        if network.get('c2_config'):
            lines.append(f"C2 Configs: {len(network['c2_config'])}")
        lines.append("")

        # Native
        native = result.get('native', {})
        lines.append("-" * 40)
        lines.append(f"BIBLIOTHÈQUES NATIVES ({len(native.get('libraries', []))})")
        lines.append("-" * 40)
        for lib in native.get('libraries', []):
            lines.append(f"  - {lib.get('name')} ({lib.get('architecture')}) - {len(lib.get('native_methods', []))} méthodes JNI")
        lines.append("")

        # JNI
        jni = result.get('jni', {})
        lines.append("-" * 40)
        lines.append("ANALYSE JNI")
        lines.append("-" * 40)
        for lib_jni in jni.get('libraries', []):
            lines.append(f"  {lib_jni.get('library')}: JNI_OnLoad={'Oui' if lib_jni.get('jni_onload', {}).get('found') else 'Non'}, RegisterNatives={'Oui' if lib_jni.get('register_natives', {}).get('found') else 'Non'}, Méthodes mappées={len(lib_jni.get('mapped_methods', []))}")
        lines.append("")

        # AI
        ai = result.get('ai_analysis', {})
        lines.append("-" * 40)
        lines.append("ANALYSE IA")
        lines.append("-" * 40)
        if ai.get('success'):
            a = ai.get('analysis', {})
            lines.append(f"Catégorie: {a.get('malware_category', 'N/A')}")
            lines.append(f"Confiance: {a.get('confidence', 0)}%")
            lines.append(f"Risque: {a.get('risk_level', 'N/A')}")
            lines.append(f"Résumé: {a.get('summary', 'N/A')}")
        else:
            lines.append(f"Échec: {ai.get('error', 'N/A')}")
        lines.append("")

        # Risk factors
        lines.append("-" * 40)
        lines.append("FACTEURS DE RISQUE")
        lines.append("-" * 40)
        for rf in risk.get('risk_factors', []):
            lines.append(f"  [{rf.get('severity', '').upper()}] {rf.get('factor')}: {rf.get('detail')}")
        lines.append("")

        lines.append("=" * 80)
        lines.append("FIN DU RAPPORT - APKStudioAI 2.1")
        lines.append("Analyse statique uniquement - Aucun code n'a été exécuté")
        lines.append("=" * 80)

        return "\n".join(lines)

    def _format_size(self, size: int) -> str:
        """Format file size"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"