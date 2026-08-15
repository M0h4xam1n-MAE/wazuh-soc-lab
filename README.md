# wazuh-soc-lab

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.x-0078d4)](https://wazuh.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org)

**SOC Detection Engineering Lab** — Windows + Sysmon + Wazuh.

Dépôt de use cases de détection prêts à l'emploi : règles Wazuh, documentation
d'investigation, mapping MITRE ATT&CK et analyse de faux positifs.

## Architecture du lab

```
┌──────────────────────┐         ┌──────────────────────────┐
│ Windows 10/11 (VM)   │         │ Wazuh Manager (Linux VM) │
│ Sysmon (Event 1, 22) │  TCP    │  rules 100001-100009     │
│ Wazuh Agent          │ ──────► │  alerts → dashboard      │
└──────────────────────┘  1514   └──────────────────────────┘
```

## Modules disponibles

| ID | Use case | Statut |
|----|----------|--------|
| SOC-001 | Suspicious PowerShell Activity | ✅ Prêt |
| SOC-002 | (à venir) | 🚧 Planifié |

## Quick start

1. `git clone https://github.com/<TON_USER>/wazuh-soc-lab.git`
2. Suivre `modules/001-suspicious-powershell/README.md`
3. Déployer Sysmon → configurer l'agent → installer les règles → simuler → vérifier

## Documentation

| Doc | Lien |
|-----|------|
| Détection | `modules/001-suspicious-powershell/docs/01-detection.md` |
| Investigation SOC | `modules/001-suspicious-powershell/docs/02-investigation.md` |
| MITRE ATT&CK | `modules/001-suspicious-powershell/docs/03-mitre-attack.md` |
| Faux positifs | `modules/001-suspicious-powershell/docs/04-false-positives.md` |

## Contribuer

Voir `CONTRIBUTING.md` — format imposé pour chaque nouveau module de détection.

## Licence

MIT — voir [LICENSE](LICENSE). Usage : lab / éducation / recherche.
