# SOC-001 — Procédure d'investigation : Suspicious PowerShell Activity

## 1. Triage (10 premières minutes)
| # | Action | Outil / requête |
|---|--------|-----------------|
| 1 | Confirmer que l'alerte vient d'une règle du module et copier l'événement complet | Dashboard : `rule.id:10000*` |
| 2 | Enregistrer : agent, horodatage, utilisateur, processus parent, ligne de commande, hashes | JSON d'alerte (`data.win.eventdata.*`) |
| 3 | Évaluer : la ligne de commande exécute-t-elle réellement du contenu contrôlé par l'attaquant ? | Lire `commandLine` attentivement |
| 4 | Vérifier la criticité de l'actif et les privilèges de l'utilisateur (admin vs standard) | Inventaire des actifs, AD |
| 5 | Décider la sévérité : L3 contexte seul / L8-10 revue / L12+ incident | Matrice d'escalade (§7) |

## 2. Enrichissement
- **Réputation de hash** : soumettre `data.win.eventdata.hashes` (SHA256) à VirusTotal / votre sandbox.
- **Chaîne parent** : vérifier `parentImage`/`parentCommandLine` — Explorer (clic utilisateur),
  Office (macro), svchost (tâche planifiée), ou un autre shell (mouvement latéral).
- **Contexte utilisateur** : connexions récentes, appartenance aux groupes, comptes de service.
- **Réseau** : corréler avec Sysmon Event 22 (DNS) dans la même fenêtre temporelle.

## 3. Reconstruction de la chronologie (requêtes dashboard Wazuh)
```text
# Toutes les alertes du module pour l'hôte
rule.id:10000* and agent.name:<HOST>

# Toute l'activité de processus PowerShell autour de l'alerte (Sysmon Event 1)
agent.name:<HOST> and data.win.system.eventID:1 and data.win.eventdata.image:*powershell.exe

# Requêtes DNS autour de l'événement (corrélation download cradle)
agent.name:<HOST> and data.win.system.eventID:22

# Fichiers écrits juste après l'événement (staging de payload)
agent.name:<HOST> and data.win.system.eventID:11

# Vérifications de persistance (registre)
agent.name:<HOST> and data.win.system.eventID:13
```

## 4. Collecte d'artefacts sur l'hôte (sur l'endpoint, avec approbation)
| Artefact | Emplacement / source | Répond à |
|----------|----------------------|----------|
| ScriptBlock Logging PowerShell | Event 4104 (Microsoft-Windows-PowerShell/Operational) | Contenu complet du script — valeur maximale |
| Journaux Module/Engine PowerShell | Events 4103 / 400 / 800 | Appels de modules, détails pipeline |
| Historique PSReadLine | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | Commandes interactives |
| Enrichissement Sysmon | Events 11 (fichier), 13 (registre), 22 (DNS), 23 (suppression), 25 (changement processus) | Artefacts latéraux |
| AV/AMSI | Events Defender 1116/1117 | Corroboration de détection malware |
| Prefetch | `C:\Windows\Prefetch\POWERSHELL*.pf` | Preuve de première exécution |
| Vérification persistance | Run keys, dossier Startup, Tâches planifiées, abonnements WMI, Services | Empreinte post-exploitation |

Note forensique : collecter la mémoire (`procdump -ma` du PID suspect uniquement, sous
supervision IR) et une copie de triage de `C:\Windows\System32\winevt\Logs\*.evtx`
avant toute remédiation.

## 5. Confinement (selon politique ; aucune action destructive sans approbation)
1. Isoler l'endpoint (désactiver la NIC dans l'hyperviseur pour les VM de lab).
2. Désactiver ou réinitialiser le compte utilisateur affecté ; révoquer les jetons.
3. Bloquer les domaines/IP de C2 ou de staging issus des requêtes DNS au pare-feu.
4. Geler les identifiants cloud/on-prem utilisés par l'hôte.

## 6. Éradication → Récupération → Retour d'expérience
1. Tuer les processus malveillants confirmés (vérifier l'identité d'abord, collecter la
   mémoire avant de tuer).
2. Supprimer la persistance (Run keys, tâches planifiées, abonnements WMI) — documenter chaque modification.
3. Faire tourner les identifiants de l'utilisateur compromis et les secrets des comptes machine.
4. Réinstaller l'hôte depuis une image connue-bonne si la non-persistance ne peut être prouvée.
5. Retour d'expérience : analyse des lacunes de détection, tuning des règles, sensibilisation
   utilisateurs, backlog de durcissement (voir `04-false-positives.md` §4).

## 7. Matrice d'escalade
| Alerte | Classification initiale | Action |
|--------|-------------------------|--------|
| 100002 encodée / 100005 cradle / 100007 identifiants / 100009 office | **Incident (P1/P2)** | Playbook complet, confinement, forensique |
| 100003 masquée / 100004 bypass / 100006 réflexion | **Revue (P3)** | Enrichir, valider la légitimité, clore ou escalader |
| 100001 / 100008 | **Contexte / anomalie** | Triage, note, corrélation ; escalader en cas de répétition |
