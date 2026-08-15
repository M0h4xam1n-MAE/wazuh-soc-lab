# Contributing

Chaque module de détection doit respecter :

1. Un identifiant unique `SOC-NNN` et un dossier `modules/NNN-nom-du-use-case/`
2. Une règle Wazuh custom dans la plage `100000-120000`
3. Les 4 documents obligatoires : détection, investigation, MITRE, faux positifs
4. Un script de simulation **inoffensif** (aucune action destructive)
5. Aucun secret, aucune donnée d'infrastructure réelle

Les PR doivent passer le workflow de validation XML (`.github/workflows/validate-rules.yml`).
