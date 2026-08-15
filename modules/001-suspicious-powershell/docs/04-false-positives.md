# SOC-001 — Faux positifs & réponse défensive

## 1. Sources de faux positifs connues (lab & réel)
| Source légitime | Règles déclenchées | Pourquoi |
|-----------------|--------------------|----------|
| Automatisation RMM (PDQ, SCCM, Ansible, Intune) | 100004 (bypass), 100008 (rafale) | Le déploiement de masse utilise `-ExecutionPolicy Bypass` |
| Gestionnaires de paquets (chocolatey, winget) | 100004, 100006 (Add-Type) | Les scripts d'installation contournent la politique, compilent des helpers |
| Scripts admin/DevOps (agents CI/CD) | 100003 (masquée), 100005 (IWR pour mises à jour) | L'automatisation légitime masque les fenêtres, télécharge des actifs |
| Outillage sécurité (mises à jour AV, EDR) | 100001, 100008 | Créations PowerShell fréquentes |
| Automatisation support/helpdesk | 100002 (enc) | Encode de longues commandes pour commodité de citation |
| Scripts applicatifs spécifiques | 100006 (Add-Type), 100005 (HttpClient) | Interop .NET et clients HTTP légitimes |

## 2. Stratégie de tuning (par ordre de préférence)
1. **Liste blanche par parent de confiance** (règle enfant avec `negate="yes"` sur
   parentImage, ex. binaire de service PDQ, ccmexec de SCCM) — le plus sûr, conserve la
   détection pour tout le reste.
2. **Liste blanche par utilisateur/compte de service** (`win.eventdata.user` negate) pour
   les comptes d'automatisation connus.
3. **Liste blanche par hôte** pour les hôtes lab non critiques (niveau réduit, pas de suppression).
4. **Liste blanche de hash** des hôtes de scripts connus-bons.
5. **Supprimer des motifs bénins exacts** (ex. lignes de commande connues de l'updater) —
   dernier recours, documenter pourquoi.
6. **Baisser les niveaux** seulement après 30 jours de données ; préférer des règles enfants
   avec `level` inférieur plutôt que supprimer des règles.

Exemple de règle enfant de suppression (à ajouter au XML du module) :
```xml
<rule id="100010" level="0">
  <if_sid>100004</if_sid>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)\\PDQDeployRunner\.exe$</field>
  <description>PowerShell - Execution policy bypass (parent PDQ en liste blanche) - informatif uniquement</description>
  <group>powershell,</group>
</rule>
```

## 3. Mesure de la qualité
Suivre sur 30 jours : total des alertes du module, taux de FP (objectif < 20%), MTTA/MTTR,
règles qui ne déclenchent jamais (revoir la regex), et règles qui ne déclenchent que sur
simulation (valider la regex). Ne tuner qu'avec des données — jamais préventivement.

## 4. Réponse défensive (durcissement de la baseline du lab)
| Contrôle | Implémentation |
|----------|----------------|
| ScriptBlock + Module logging | GPO : `Turn on PowerShell Script Block Logging` + `Module Logging` (Events 4104/4103) |
| AMSI | S'assurer que Windows Defender / AMSI est activé ; bloquer les motifs de bypass `-AMSI` dans les règles 4104 |
| Constrained Language Mode | CLM pour les utilisateurs non-admin ; WDAC pour un contrôle total |
| Contrôle d'applications | AppLocker/WDAC : autoriser uniquement PowerShell Microsoft signé, bloquer `-enc` pour les non-admin |
| Politique d'exécution | GPO `Set-ExecutionPolicy RemoteSigned` pour les utilisateurs (défense en profondeur, pas une frontière de sécurité) |
| Protection LSASS | Activer RunAsPPL (protection LSA) + Credential Guard ; restreindre SeDebugPrivilege |
| Audit & journalisation | Activer les canaux Sysmon, PowerShell et Windows Defender ; tout transmettre à Wazuh |
| Moindre privilège | Retirer l'admin local des analystes/utilisateurs du lab ; admin local unique type LAPS |
| Préparation de réponse | Procédure d'isolation pré-agréée, runbook de rotation des identifiants, réinstallation image connue-bonne |

## 5. Rappel d'escalade
Les alertes de niveau ≥ 12 (100002, 100005, 100007, 100009) sont **incident-worthy par
défaut** : ouvrir un cas IR, préserver les preuves, suivre `02-investigation.md` avant
toute remédiation.
