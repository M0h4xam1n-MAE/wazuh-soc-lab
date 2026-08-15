# Module SOC-001 — Suspicious PowerShell Activity

| Champ | Valeur |
|-------|--------|
| Module ID | SOC-001 |
| Catégorie | Detection Engineering / SOC Use Case |
| Source de données | Windows Event Log → Sysmon Event ID 1 (Process Creation) |
| Plateforme | Windows 10/11, Sysmon ≥ 13 (schéma 4.90), Wazuh 4.x |
| Rule IDs | 100001 – 100009 |
| MITRE ATT&CK | T1059.001, T1027, T1140, T1105, T1564.003, T1003.001, T1562.001, T1204.002 |
| Sévérité | Niveau 3 (contexte) – 13 (critique) |

## Quick start

1. **Déployer Sysmon** (PowerShell admin sur le lab Windows) :
   ```powershell
   .\sysmon64.exe -accepteula -i .\config\sysmon-config.xml
   ```
2. **Transmettre les événements Sysmon** — ajouter le bloc `config/ossec-agent-sysmon.conf`
   dans `C:\Program Files (x86)\ossec-agent\ossec.conf`, puis :
   ```powershell
   Restart-Service -Name Wazuh
   ```
3. **Installer les règles** sur le manager Wazuh :
   ```bash
   sudo cp rules/100001-suspicious-powershell.xml /var/ossec/etc/rules/
   sudo chown root:wazuh /var/ossec/etc/rules/100001-suspicious-powershell.xml
   sudo /var/ossec/bin/wazuh-logtest     # valider avec un événement Sysmon
   sudo systemctl restart wazuh-manager
   ```
4. **Valider de bout en bout** :
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\simulate-suspicious-powershell.ps1
   ```
5. **Confirmer les alertes** dans le dashboard Wazuh : `rule.id:10000*`

## Documentation

| Doc | Lien |
|-----|------|
| Détection | `docs/01-detection.md` |
| Investigation SOC | `docs/02-investigation.md` |
| MITRE ATT&CK | `docs/03-mitre-attack.md` |
| Faux positifs & réponse défensive | `docs/04-false-positives.md` |
