# APKStudioAI 2.1 — Advanced Android APK Malware Analysis Platform

> **Laboratoire local d'analyse statique Android** — Analyse automatique des APK complexes, DEX, bibliothèques natives ELF et méthodes JNI, avec assistance IA locale (Ollama) et rapports professionnels.

---

## 🎯 Vue d'ensemble

APKStudioAI 2.1 est une plateforme professionnelle d'analyse statique de malwares Android, conçue pour transformer n'importe quel APK en un rapport d'analyse complet, exploitable par un analyste cybersécurité.

### Fonctionnalités principales

| Module | Description |
|--------|-------------|
| 📦 **Archive Analyzer** | Structure ZIP, SHA256, détection fichiers chiffrés/corrompus, DEX cachés, PNG append |
| 📋 **Manifest Analyzer** | AndroidManifest.xml binaire + fallback Apktool, composants, permissions, intent-filters |
| 📦 **DEX Analyzer** | Multi-DEX (classes.dex, classes2.dex...), vérification signatures, JADX par DEX |
| ☕ **Java Decompiler (JADX)** | Décompilation complète, extraction code source, détection patterns suspects |
| 📝 **Smali Analyzer (Apktool)** | Analyse Smali indépendante, ressource decoding |
| 🔧 **Native/ELF Analyzer** | arm64-v8a, armeabi-v7a, x86, x86_64 — headers, sections, symboles, imports/exports |
| 🔗 **JNI Analyzer** | **Prioritaire** — JNI_OnLoad, RegisterNatives, tables JNINativeMethod, mapping Java↔Native |
| 🔍 **String Analyzer** | Extraction + décodage Base64/Hex/XOR, IOCs (URLs, domaines, IPs, Firebase, Telegram) |
| 🔐 **Permission Analyzer** | 100+ permissions mappées (risque, capacité, MITRE ATT&CK) |
| 🧠 **Behavior Analyzer** | 20 catégories de patterns malveillants (spyware, RAT, banker, dropper, etc.) |
| 🌐 **Network Analyzer** | C2 config, certificate pinning, WebSocket, proxy, DGA, Firebase, Telegram |
| 🦠 **Malware Detector** | Moteur de règles 20 catégories + signatures connues (Anubis, Cerberus, SpyMax, etc.) |
| ⚖️ **Risk Engine** | Score 0-100 (Faible→Critique) basé sur preuves, fiabilité, gravité, corrélations |
| 🤖 **AI Analysis (Ollama)** | qwen2.5-coder:3b local — explication code, corrélation Java/Smali/Manifest/ELF/JNI |
| 📊 **GUI Professionnelle** | 12 onglets : Overview, Manifest, Permissions, DEX, Java, Smali, Native, JNI, Network, Malware, AI, Logs |
| 📄 **Rapports** | HTML professionnel, JSON structuré, TXT lisible — preuves, sources, offsets, confiance |

---

## 🏗️ Architecture

```
APKStudioAI/
├── main.py                 # CLI entry point
├── gui.py                  # Interface graphique (12 onglets)
├── config.json             # Configuration (chemins outils, Ollama)
├── requirements.txt        # Dépendances Python
├── install.bat             # Installation complète (Windows)
├── start.bat               # Lancement GUI
├── diagnostic.bat          # Diagnostique système
├── core/
│   ├── scanner.py          # Orchestrateur principal (15 étapes)
│   ├── archive_analyzer.py # Analyse archive APK
│   ├── manifest_analyzer.py# AndroidManifest.xml
│   ├── dex_analyzer.py     # Fichiers DEX
│   ├── jadx_engine.py      # Wrapper JADX
│   ├── apktool_engine.py   # Wrapper Apktool
│   ├── native_analyzer.py  # Bibliothèques .so
│   ├── elf_analyzer.py     # Parseur ELF (pyelftools/readelf)
│   ├── jni_analyzer.py     # Analyse JNI approfondie
│   ├── string_analyzer.py  # Strings + décodage + IOCs
│   ├── permission_analyzer.py # 100+ permissions + MITRE
│   ├── behavior_analyzer.py# 20 patterns comportementaux
│   ├── network_analyzer.py # IOCs réseau + C2
│   ├── malware_detector.py # Moteur détection 20 catégories
│   ├── risk_engine.py      # Scoring 0-100
│   ├── ollama_client.py    # Client IA locale
│   ├── reporter.py         # Génération rapports HTML/JSON/TXT
│   └── utils.py            # Utilitaires communs
├── analysis/
│   ├── rules.json          # Règles détection malware (20 catégories)
│   ├── signatures.json     # Signatures connues (50+ familles)
│   └── behavior_rules.json # Règles analyse comportementale
├── reports/                # Rapports générés
├── workspace/              # Espace de travail temporaire
├── logs/                   # Journaux d'analyse
├── cache/                  # Cache
├── tools/                  # Outils externes (JADX, Apktool)
└── tests/                  # Tests unitaires
```

---

## 🚀 Installation

### Prérequis

| Outil | Version | Installation |
|-------|---------|--------------|
| **Windows** | 10/11 | — |
| **Python** | 3.11+ | <https://python.org> (✓ "Add to PATH") |
| **Java** | 11+ (JDK) | <https://adoptium.net/> |
| **Ollama** | Latest | <https://ollama.ai/> + `ollama pull qwen2.5-coder:3b` |

### Installation automatique (Windows)

```cmd
# 1. Cloner/extraire le projet dans C:\APKStudioAI
# 2. Lancer en tant qu'administrateur :
install.bat
```

Le script `install.bat` :
- Crée l'environnement virtuel Python
- Installe les dépendances (`requirements.txt`)
- Télécharge **JADX 1.5.1** et **Apktool 2.10.0**
- Configure `config.json` avec les bons chemins
- Vérifie Ollama et le modèle `qwen2.5-coder:3b`

### Installation manuelle (si auto échoue)

```cmd
# Environnement virtuel
python -m venv venv
call venv\Scripts\activate.bat
pip install -r requirements.txt

# JADX : télécharger depuis https://github.com/skylot/jadx/releases/tag/v1.5.1
# Extraire dans C:\APKStudioAI\tools\jadx\

# Apktool : télécharger depuis https://github.com/iBotPeaches/Apktool/releases/tag/v2.10.0
# Placer apktool_2.10.0.jar dans C:\APKStudioAI\tools\apktool.jar

# Ollama
ollama pull qwen2.5-coder:3b
```

---

## 🖥️ Utilisation

### Interface Graphique (GUI)

```cmd
start.bat
```
Ou :
```cmd
call venv\Scripts\activate.bat
python gui.py
```

**Workflow GUI :**
1. Cliquer **📁 Parcourir** → sélectionner un APK
2. Le SHA256 se calcule automatiquement
3. Cliquer **▶ ANALYSE COMPLÈTE**
4. Suivre la progression (15 étapes, barre de progression, logs temps réel)
5. Explorer les **12 onglets** de résultats
6. Rapports générés automatiquement dans `reports/`

### Ligne de commande (CLI)

```cmd
# Analyse simple
python main.py "E:\MALWARE\sample.apk"

# Sans IA (plus rapide)
python main.py "E:\MALWARE\sample.apk" --no-ai

# Sortie JSON
python main.py "E:\MALWARE\sample.apk" --json --output result.json

# Analyse par lot (dossier)
python main.py --batch "E:\MALWARE"

# Avec config personnalisée
python main.py "sample.apk" --config custom_config.json
```

**Codes de sortie :**
- `0` : Succès
- `1` : Erreur argument / fichier introuvable
- `2` : Erreur d'analyse
- `3` : Erreur configuration / outils manquants

---

## 📋 Les 12 Onglets de la GUI

| Onglet | Contenu |
|--------|---------|
| **📊 Overview** | Score risque, infos APK, stats rapides, facteurs de risque |
| **📋 Manifest** | Composants (activities, services, receivers, providers), permissions, XML brut |
| **🔐 Permissions** | Tableau filtrable par risque (critique→normal), capacités, MITRE ATT&CK |
| **📦 DEX** | Liste fichiers DEX (SHA256, validité, classes, méthodes), détails |
| **☕ Java** | Arborescence packages/classes JADX, code source avec recherche |
| **📝 Smali** | Arborescence fichiers Smali Apktool, code avec recherche |
| **🔧 Native** | Bibliothèques .so par archi, détails ELF (sections, symboles, imports, strings) |
| **🔗 JNI** | JNI_OnLoad, RegisterNatives, table mapping Java↔Native (classe, méthode, signature, adresse) |
| **🌐 Network IOC** | URLs, domaines, IPs, Firebase, Telegram bots, C2 configs, chaînes décodées |
| **🦠 Malware** | 20 catégories avec classification (confirmé/likely/possible), preuves détaillées, signatures connues |
| **🤖 AI Analysis** | Analyse Ollama : catégorie, confiance, risque, résumé, détails, recommandations, limites |
| **📜 Logs** | Journal complet avec filtres niveau (INFO/WARNING/ERROR/DEBUG), export |

---

## 🦠 Catégories de Malware Détectées (20)

| Catégorie | Sévérité | Description |
|-----------|----------|-------------|
| **spyware** | Critique | Surveillance : audio, vidéo, localisation, contacts, SMS |
| **rat** | Critique | Remote Access Trojan : contrôle total, C2, exécution commandes |
| **trojan** | Élevée | Overlay, installation packages, device admin abuse |
| **banker** | Critique | Ciblage credentials bancaires via overlay + accessibility |
| **dropper** | Élevée | Télécharge et installe payloads additionnels |
| **downloader** | Élevée | Récupère et exécute du code additionnel |
| **screen_capture** | Élevée | Capture écran (MediaProjection) |
| **keylogger** | Élevée | Enregistrement frappes clavier |
| **accessibility_abuse** | Élevée | Abus service accessibilité (automation, overlay) |
| **device_admin_abuse** | Critique | Lock/wipe/policy via DeviceAdmin |
| **vpn_abuse** | Élevée | Interception trafic via VpnService |
| **overlay_attack** | Élevée | Phishing/credential theft via SYSTEM_ALERT_WINDOW |
| **sms_stealer** | Élevée | Interception/envoi/lecture SMS |
| **credential_theft** | Critique | Vol credentials (AccountManager, WebView, accessibility) |
| **data_exfiltration** | Élevée | Collecte + exfiltration données sensibles |
| **dynamic_code_loading** | Élevée | DexClassLoader, reflection, chargement runtime |
| **persistence** | Élevée | Boot receiver, foreground service, admin, accessibility |
| **anti_analysis** | Moyenne | Détection émulateur, debugger, root, signature |
| **obfuscation** | Moyenne | ProGuard, DexGuard, chiffrement strings, control flow |
| **hidden_payload** | Élevée | Payload chiffré/caché dans assets/resources |
| **ransomware** | Critique | Chiffrement fichiers + rançon (admin + overlay + persistence) |

---

## ⚖️ Système de Scoring (0-100)

| Score | Niveau | Couleur |
|-------|--------|---------|
| 0-19 | **Faible** | 🟢 Vert |
| 20-39 | **Modéré** | 🟡 Jaune |
| 40-59 | **Élevé** | 🟠 Orange |
| 60-79 | **Très Élevé** | 🔴 Rouge foncé |
| 80-100 | **Critique** | 🔴 Rouge |

**Pondération :**
- Permissions : 30%
- Détections malware : 40%
- Comportements : 20%
- Réseau : 15%
- Code natif : 10%
- Anti-analyse : 10%
- Propre (bonus) : -10%

**Classification des preuves :**
- **Indicateur** : Détecté statiquement
- **Capacité** : Permission/API présente
- **Confirmé** : Comportement malveillant prouvé statiquement
- **Hypothèse** : Pattern suggérant mais non confirmant
- **Non vérifiable** : Nécessite analyse dynamique

---

## 🤖 Analyse IA Locale (Ollama)

**Configuration par défaut :**
- API : `http://127.0.0.1:11434`
- Modèle : `qwen2.5-coder:3b`

**Fonctionnement :**
1. L'IA reçoit des **résumés structurés** par module (pas l'APK complet)
2. Explique le code suspect, corrèle Java/Smali/Manifest/ELF/JNI
3. Identifie comportements possibles, résume IOCs
4. Produit conclusion argumentée avec **limites explicites**
5. **Ne jamais invente de preuves** — sépare analyse IA des preuves extractes

**Mode sans IA :** `--no-ai` (CLI) ou si Ollama indisponible

---

## 📄 Rapports Générés

Chaque analyse produit 3 formats dans `reports/` :

| Format | Usage |
|--------|-------|
| **HTML** | Rapport professionnel navigable, sections repliables, coloration risques |
| **JSON** | Structuré, exploitable programmatiquement, toutes données brutes |
| **TXT** | Lisible en console, format compact pour logs/archives |

**Contenu standard :**
- Infos APK + SHA256
- Résultats chaque module d'analyse
- Permissions + composants Android
- DEX + bibliothèques natives + JNI
- IOCs réseau + chaînes décodées
- Indicateurs suspects + score risque
- Analyse IA + limites
- Conclusion

---

## 🛡️ Robustesse & Sécurité

- ✅ **Jamais d'installation APK** — analyse purement statique
- ✅ **Jamais d'exécution code** — pas d'émulation, pas de runtime
- ✅ **Jamais de lancement .so** — analyse ELF passive seulement
- ✅ **Pas de contact réseau** vers IOCs extraits (analyse statique only)
- ✅ **Protection ZIP Slip** — extraction sécurisée avec validation paths
- ✅ **Protection archive explosive** — limites taille fichiers extraits
- ✅ **Timeouts** sur tous outils externes (JADX, Apktool, Ollama)
- ✅ **Threads contrôlés** — GUI non-bloquante, cancellation possible
- ✅ **Gestion RAM** — nettoyage workspace, streaming gros fichiers
- ✅ **Continuité** — un échec d'outil n'arrête pas l'analyse complète

---

## 🧪 Tests

```cmd
# Tests unitaires (core modules)
python -m pytest tests/ -v

# Test sur APK réels (si disponibles)
python main.py "E:\MALWARE\DecorAI33.apk" --json
python main.py "E:\MALWARE\DramaSpool.apk" --json
```

**Cas de test couverts :**
- Archive : ZIP corrompu, entrées chiffrées, DEX cachés, PNG append
- DEX : Multi-DEX, DEX invalides, JADX failures partiels
- Manifest : XML binaire, Apktool fallback, ressources chiffrées
- Native : ELF 32/64-bit, ARM/x86, sections manquantes, symbols stripped
- JNI : RegisterNatives direct/indirect, relocations, pointeurs obfusqués
- Scoring : Pondérations, déduplication indicateurs, classification preuves
- Rapports : Génération HTML/JSON/TXT, encodage UTF-8
- Ollama : Timeout, fallback sans IA, chunking gros contextes

---

## 📁 Fichiers de Configuration

### `config.json`
```json
{
  "tools": {
    "jadx_path": "C:/APKStudioAI/tools/jadx/bin/jadx.bat",
    "apktool_path": "C:/APKStudioAI/tools/apktool.jar",
    "java_path": "java"
  },
  "ollama": {
    "api_url": "http://127.0.0.1:11434",
    "model": "qwen2.5-coder:3b",
    "timeout": 120
  },
  "analysis": {
    "max_strings_length": 100000,
    "max_dex_size_mb": 50,
    "enable_ai": true
  }
}
```

### `analysis/rules.json` — Règles détection 20 catégories
### `analysis/signatures.json` — 50+ signatures familles connues
### `analysis/behavior_rules.json` — Patterns API + combinaisons permissions

---

## 🔧 Dépannage

| Problème | Solution |
|----------|----------|
| `JADX not found` | Vérifier `config.json` → `tools.jadx_path` ou relancer `install.bat` |
| `Apktool not found` | Vérifier `tools.apktool_path` ou télécharger manuellement |
| `Ollama connection refused` | Lancer `ollama serve` dans un terminal |
| `Model not found` | `ollama pull qwen2.5-coder:3b` |
| `MemoryError` | Réduire `max_strings_length` dans config, fermer autres apps |
| `GUI freeze` | Vérifier threads, utiliser `--no-ai` pour test |
| `Permission denied` | Lancer `install.bat` en administrateur |

**Diagnostic complet :**
```cmd
diagnostic.bat
```

---

## 📦 Empaquetage / Distribution

Pour créer un ZIP distribuable (sans APK malveillants, sans venv, sans cache) :

```cmd
# Depuis le répertoire parent
powershell Compress-Archive -Path "APKStudioAI\*" -DestinationPath "APKStudioAI_2.1_Windows.zip" -Force
```

**Contenu du ZIP :**
- Tous fichiers Python (`core/`, `gui.py`, `main.py`, etc.)
- `config.json`, `requirements.txt`
- `install.bat`, `start.bat`, `diagnostic.bat`
- `analysis/rules.json`, `signatures.json`, `behavior_rules.json`
- `README.md`
- Dossiers vides : `reports/`, `workspace/`, `logs/`, `cache/`, `tools/`, `tests/`

**Exclus :** `venv/`, `*.apk`, `__pycache__/`, `*.pyc`, `.git/`

---

## 📚 Références & Remerciements

### Outils utilisés
- **JADX** — Dex to Java decompiler (skylot/jadx)
- **Apktool** — Android asset decoding (iBotPeaches/Apktool)
- **pyelftools** — ELF parsing (eliben/pyelftools)
- **Capstone** — Disassembly framework (capstone-engine/capstone)
- **Ollama** — Local LLM runtime (ollama/ollama)

### Standards & Frameworks
- **MITRE ATT&CK®** — Matrice techniques adverses
- **Android Permissions** — Documentation officielle Google
- **ELF Specification** — Tool Interface Standard (TIS)

---

## ⚠️ Avertissement Légal

**APKStudioAI 2.1 est un outil d'analyse statique à des fins éducatives, de recherche en sécurité et d'audit autorisé uniquement.**

- ❌ Ne pas utiliser pour analyser des APK sans autorisation
- ❌ Ne pas utiliser pour développer des malwares
- ✅ Autorisé : pentesting engagé, CTF, recherche sécurité, audit interne, éducation
- 📋 Respecter les lois locales sur la cybersécurité et la propriété intellectuelle

L'analyse est **purement statique** — aucun code n'est exécuté, aucune installation n'est effectuée, aucun serveur n'est contacté.

---

## 📄 Licence

Projet privé — Usage personnel et professionnel autorisé dans le cadre d'activités légitimes de cybersécurité.

---

## 🤝 Contribution

Ce projet suit une méthodologie rigoureuse :
1. **Inspection** → Comprendre l'existant
2. **Audit** → Lister fonctionnalités/limites
3. **Architecture** → Définir cible modulaire
4. **Développement** → Modules incrémentaux testés
5. **Intégration** → GUI + CLI unifiés
6. **Tests** → Validation sur APK réels
7. **Livraison** → Package complet

Pour contribuer : respecter l'architecture modulaire, ajouter tests, documenter les changements.

---

**APKStudioAI 2.1** — *Véritables laboratoires d'analyse statique Android locaux*  
*Construit avec rigueur pour les analystes malware professionnels*