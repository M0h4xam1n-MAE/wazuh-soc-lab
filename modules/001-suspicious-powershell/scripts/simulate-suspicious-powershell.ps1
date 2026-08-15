<#
.SYNOPSIS
  Simulateur de motifs de détection inoffensif pour Wazuh SOC Lab - Module SOC-001.

.DESCRIPTION
  Lance de courts processus powershell.exe dont les lignes de commande correspondent
  aux règles custom du module (100001-100008), générant la télémétrie Sysmon Event 1.
  GARANTIES DE SÉCURITÉ :
    - Aucune commande destructive, aucune suppression, aucune persistance, aucun accès aux identifiants.
    - Aucun réseau externe : la simulation de download cradle cible 127.0.0.1 sur un
      port fermé et échoue immédiatement.
    - Tous les payloads simulés sont inertes (Write-Output / opérations triviales).

.NOTES
  À exécuter sur un endpoint de lab isolé (Windows 10/11) avec Sysmon et l'agent Wazuh installés.
  Usage : powershell -ExecutionPolicy Bypass -File .\simulate-suspicious-powershell.ps1
  Optionnel : -Correlation lance le test de volume pour la règle 100008.
#>
param([switch]$Correlation)
$ErrorActionPreference = 'Continue'
$Log = Join-Path $env:TEMP 'wazuh-soc-lab-sim.log'

function Write-SimLog { param($Msg) $line = "[$(Get-Date -Format s)] $Msg"; $line | Tee-Object -FilePath $Log -Append }

# --- Simulation 1+3 : Commande encodée + fenêtre masquée (règles 100001, 100002, 100003) ---
Write-SimLog "Sim 1: EncodedCommand + Hidden window"
$plain = "Write-Output 'SOC-001 encoded command simulation - harmless'"
$b64   = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($plain))
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-EncodedCommand",$b64 -WindowStyle Hidden

# --- Simulation 2 : Contournement de politique d'exécution (règles 100001, 100004) ---
Write-SimLog "Sim 2: ExecutionPolicy Bypass"
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-Command","Write-Output 'SOC-001 bypass simulation'"

# --- Simulation 4 : Motif download cradle, AUCUN réseau externe (règles 100001, 100005) ---
# 127.0.0.1:9 (port discard) - la connexion est refusée immédiatement, rien n'est téléchargé.
Write-SimLog "Sim 3: Download cradle pattern (localhost only)"
$cradle = "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:9/soc001')"
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-Command",$cradle

# --- Simulation 5 : Réflexion / Add-Type (règles 100001, 100006) ---
Write-SimLog "Sim 4: Add-Type reflection pattern"
$reflection = "Add-Type -TypeDefinition 'public class SocLabSim { public static string Ping() { return \"ok\"; } }'; [SocLabSim]::Ping()"
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-Command",$reflection

# --- Simulation 6 : Chaînes de mots-clés d'identifiants, inertes (règles 100001, 100007) ---
Write-SimLog "Sim 5: Credential keyword strings (echo only)"
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-Command","Write-Output 'SOC-001 keyword simulation: mimikatz sekurlsa'"

# --- Simulation 7 (optionnelle) : rafale pour la règle de corrélation 100008 ---
if ($Correlation) {
    Write-SimLog "Sim 6: Correlation burst (10 spawns, rule 100008)"
    1..10 | ForEach-Object {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-Command","Start-Sleep -Milliseconds 50"
        Start-Sleep -Milliseconds 200
    }
}

Start-Sleep -Seconds 3
Write-SimLog "Done. Verify locally:"
Write-SimLog "  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 30 | Where-Object { \$_.Message -match 'powershell.exe' } | Select-Object TimeCreated, Message | Format-List"
Write-SimLog "Then check the Wazuh dashboard: rule.id:10000*"
