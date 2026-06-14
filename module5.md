# 🛡️ CEH v12 — MODULE 5 : ANALYSE DE VULNÉRABILITÉS
### Guide pédagogique avancé avec rapports complets | ML | exploit4040

---

## 📌 INTRODUCTION — L'ANALYSE DE VULNÉRABILITÉS, L'INTELLIGENCE AVANT L'ACTION

Il existe une différence fondamentale entre un **hacker qui attaque au hasard** et un **ethical hacker professionnel** :

Le professionnel ne touche rien avant d'avoir une **cartographie complète et scorée** de toutes les faiblesses de sa cible.

L'analyse de vulnérabilités c'est le pont entre le scanning (Module 3) et l'exploitation (Module 6). C'est la phase où tu transformes une liste de ports ouverts en un **rapport de risques priorisé** qui répond à une question précise :

> **"Parmi toutes ces faiblesses, laquelle m'offre le chemin le plus court vers l'objectif, avec le moins de bruit possible ?"**

Cette phase est aussi celle qui **légitime le travail de l'ethical hacker** aux yeux du client. Sans rapport de vulnérabilités structuré, tu n'es pas un professionnel — tu es juste quelqu'un qui a scanné un réseau.

---

## 📌 PARTIE 1 : COMPRENDRE LES VULNÉRABILITÉS EN PROFONDEUR

### 🔵 Définitions précises

**Vulnérabilité :** Faiblesse dans un système, une application, une configuration ou un processus humain qui peut être exploitée pour compromettre la confidentialité, l'intégrité ou la disponibilité.

**Exploit :** Code ou technique qui tire parti d'une vulnérabilité spécifique pour produire un effet non désiré sur le système cible.

**Payload :** Ce qui s'exécute après l'exploitation réussie. Le vrai "contenu" de l'attaque.

```
Analogie architecturale :
├── Vulnérabilité = Fissure dans le mur
├── Exploit       = Technique pour agrandir la fissure
└── Payload       = Ce qu'on fait passer par le trou
```

---

### 🔵 Taxonomie complète des vulnérabilités

```
VULNÉRABILITÉS
├── LOGICIELLES
│   ├── Buffer Overflow (Stack, Heap)
│   ├── Integer Overflow
│   ├── Format String
│   ├── Use-After-Free
│   ├── Race Condition
│   └── Injection (SQL, Command, LDAP, XPath)
│
├── RÉSEAU
│   ├── Protocoles non chiffrés (Telnet, FTP, HTTP)
│   ├── Services inutiles exposés
│   ├── Segmentation absente
│   ├── Règles de pare-feu trop permissives
│   └── Protocoles obsolètes (SSLv3, TLS 1.0, SMBv1)
│
├── CONFIGURATION
│   ├── Credentials par défaut
│   ├── Services inutiles actifs
│   ├── Permissions trop larges
│   ├── Politique de mots de passe faible
│   └── Patches manquants
│
├── HUMAINES
│   ├── Ingénierie sociale
│   ├── Phishing
│   ├── Manque de formation
│   └── Négligence (mots de passe partagés)
│
└── PHYSIQUES
    ├── Accès non contrôlé aux équipements
    ├── Absence de chiffrement des disques
    └── Destruction insuffisante des supports
```

---

## 📌 PARTIE 2 : LE SYSTÈME CVE — COMPRENDRE L'IDENTIFIANT UNIVERSEL

### 🔵 Architecture du système CVE

**CVE (Common Vulnerabilities and Exposures)** est géré par **MITRE Corporation** et financé par le **DHS (Department of Homeland Security)** américain.

Chaque CVE est attribué par un **CNA (CVE Numbering Authority)**. Il existe plus de 300 CNAs dans le monde : Microsoft, Google, Apple, Red Hat, et même des chercheurs indépendants.

```
Format CVE :
CVE - ANNÉE - NUMÉRO_SÉQUENTIEL

Exemples réels :
CVE-2017-0144   → EternalBlue (WannaCry) - SMBv1 RCE
CVE-2021-44228  → Log4Shell - Apache Log4j RCE
CVE-2014-0160   → Heartbleed - OpenSSL
CVE-2021-34527  → PrintNightmare - Windows Print Spooler
CVE-2022-30190  → Follina - MSDT RCE
CVE-2023-44487  → HTTP/2 Rapid Reset (DDoS)
```

### 🔵 Cycle de vie d'un CVE

```
DÉCOUVERTE
     │
     ▼
ANALYSE PRIVÉE (chercheur)
     │
     ▼
SOUMISSION AU CNA
     │
     ▼
ATTRIBUTION CVE ID (numéro réservé, détails cachés)
     │
     ▼
DÉVELOPPEMENT DU PATCH (par le vendeur)
     │
     ▼
PUBLICATION COORDONNÉE (CVE + Patch simultanés)
     │
     ▼
INDEXATION NVD (National Vulnerability Database)
     │
     ▼
SCORING CVSS OFFICIEL
     │
     ▼
INTÉGRATION DANS LES SCANNERS (Nessus, OpenVAS...)
```

---

## 📌 PARTIE 3 : CVSS v3.1 — MAÎTRISE COMPLÈTE DU SCORING

**CVSS (Common Vulnerability Scoring System)** version 3.1 est le **standard international de notation des vulnérabilités**. Produit par le **FIRST (Forum of Incident Response and Security Teams)**.

Il se compose de **trois groupes de métriques** :

```
CVSS v3.1
├── Base Score      (0-10) → Caractéristiques intrinsèques
├── Temporal Score  (0-10) → État actuel dans le temps
└── Environmental Score (0-10) → Impact dans l'environnement spécifique
```

---

### 🔵 GROUPE 1 : BASE SCORE — Les métriques fondamentales

#### Sous-groupe : Exploitability Metrics (Comment exploiter ?)

```
┌──────────────────────────────────────────────────────────────────────┐
│  MÉTRIQUE          │  VALEUR      │  DESCRIPTION                     │
├──────────────────────────────────────────────────────────────────────┤
│ Attack Vector (AV) │              │  D'où vient l'attaque ?          │
│                    │  N (Network) │  Via réseau (internet)            │
│                    │  A (Adjacent)│  Réseau local seulement           │
│                    │  L (Local)   │  Accès local requis               │
│                    │  P (Physical)│  Contact physique requis          │
├──────────────────────────────────────────────────────────────────────┤
│ Attack Complexity  │              │  Difficile à exploiter ?          │
│ (AC)               │  L (Low)     │  Reproductible facilement         │
│                    │  H (High)    │  Conditions particulières requises│
├──────────────────────────────────────────────────────────────────────┤
│ Privileges         │              │  Niveau d'accès requis ?          │
│ Required (PR)      │  N (None)    │  Aucun accès préalable            │
│                    │  L (Low)     │  Compte basique suffisant         │
│                    │  H (High)    │  Droits admin requis              │
├──────────────────────────────────────────────────────────────────────┤
│ User Interaction   │              │  Victime doit agir ?              │
│ (UI)               │  N (None)    │  Aucune action requise            │
│                    │  R (Required)│  Victime doit cliquer/ouvrir      │
└──────────────────────────────────────────────────────────────────────┘
```

#### Sous-groupe : Scope (Périmètre d'impact)

```
┌──────────────────────────────────────────────────────────────────────┐
│  MÉTRIQUE   │  VALEUR         │  DESCRIPTION                         │
├──────────────────────────────────────────────────────────────────────┤
│ Scope (S)   │  U (Unchanged)  │  Impact limité au composant vulnérable│
│             │  C (Changed)    │  Impact s'étend au-delà (pivot !)     │
└──────────────────────────────────────────────────────────────────────┘
```

#### Sous-groupe : Impact Metrics (Quel dégât sur la CIA Triad ?)

```
┌──────────────────────────────────────────────────────────────────────┐
│  MÉTRIQUE              │  VALEUR    │  DESCRIPTION                   │
├──────────────────────────────────────────────────────────────────────┤
│ Confidentiality (C)    │  N (None)  │  Aucune perte de données       │
│                        │  L (Low)   │  Données partielles exposées   │
│                        │  H (High)  │  Toutes données exposées       │
├──────────────────────────────────────────────────────────────────────┤
│ Integrity (I)          │  N (None)  │  Aucune modification           │
│                        │  L (Low)   │  Modification partielle        │
│                        │  H (High)  │  Modification totale possible  │
├──────────────────────────────────────────────────────────────────────┤
│ Availability (A)       │  N (None)  │  Aucun impact disponibilité    │
│                        │  L (Low)   │  Performance dégradée          │
│                        │  H (High)  │  Service totalement indisponible│
└──────────────────────────────────────────────────────────────────────┘
```

---

### 🔵 Lire et décoder un vecteur CVSS comme un expert

**Exemple 1 : Log4Shell (CVE-2021-44228)**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

Décodage :
AV:N → Attack Vector: Network     → Exploitable depuis internet
AC:L → Attack Complexity: Low     → Très facile, reproductible
PR:N → Privileges Required: None  → Aucun compte requis
UI:N → User Interaction: None     → Pas besoin que la victime agisse
S:C  → Scope: Changed             → Impact dépasse le composant
C:H  → Confidentiality: High      → Toutes les données exposables
I:H  → Integrity: High            → Modification totale possible
A:H  → Availability: High         → Service peut être arrêté

Score Final : 10.0 CRITIQUE
→ Exploitable depuis internet, sans compte, automatisable,
  avec impact total sur CIA + pivot possible
```

**Exemple 2 : PrintNightmare (CVE-2021-34527)**
```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

Décodage :
AV:N → Network          → Depuis le réseau
AC:L → Low              → Facile
PR:L → Low Privileges   → Compte basique requis (authentifié)
UI:N → None             → Pas d'interaction
S:U  → Unchanged        → Impact limité au système
C:H/I:H/A:H → Impact total sur CIA

Score : 8.8 HIGH
→ Légèrement moins critique que Log4Shell car compte requis
```

**Exemple 3 : Vulnérabilité locale (escalade de privilège)**
```
CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

Décodage :
AV:L → Local           → Accès local requis (déjà sur la machine)
AC:L → Low             → Facile une fois en local
PR:L → Low             → Compte basique
UI:N → None
S:U  → Unchanged
C:H/I:H/A:H

Score : 7.8 HIGH
→ Moins grave car nécessite déjà un accès local
```

---

### 🔵 Tableau de scoring CVSS

```
┌─────────────────────────────────────────────────────┐
│  SCORE    │  CRITICITÉ  │  PRIORITÉ DE REMEDIATION  │
├─────────────────────────────────────────────────────┤
│  0.0      │  None       │  Informatif seulement      │
│  0.1-3.9  │  Low        │  Patch lors de maintenance │
│  4.0-6.9  │  Medium     │  Patch sous 30 jours       │
│  7.0-8.9  │  High       │  Patch sous 7 jours        │
│  9.0-10.0 │  Critical   │  Patch immédiat (24-48h)   │
└─────────────────────────────────────────────────────┘
```

---

### 🔵 GROUPE 2 : TEMPORAL SCORE — L'état dans le temps

```
┌──────────────────────────────────────────────────────────────────────┐
│  MÉTRIQUE              │  VALEUR  │  DESCRIPTION                     │
├──────────────────────────────────────────────────────────────────────┤
│ Exploit Code           │  X       │  Non défini                      │
│ Maturity (E)           │  U       │  Non prouvé                      │
│                        │  P       │  Proof of Concept disponible     │
│                        │  F       │  Exploit fonctionnel public      │
│                        │  H       │  Exploit intégré dans outils     │
├──────────────────────────────────────────────────────────────────────┤
│ Remediation Level (RL) │  O       │  Workaround officiel dispo       │
│                        │  T       │  Fix temporaire                  │
│                        │  W       │  Contournement non officiel      │
│                        │  U       │  Aucun correctif disponible      │
├──────────────────────────────────────────────────────────────────────┤
│ Report Confidence (RC) │  U       │  Non confirmé                    │
│                        │  R       │  Raisonnable (sources multiples) │
│                        │  C       │  Confirmé par vendeur            │
└──────────────────────────────────────────────────────────────────────┘
```

> **Exemple pratique :** Log4Shell avait E:H dès les premières heures car Metasploit et des outils automatisés exploitaient déjà la vulnérabilité.

---

## 📌 PARTIE 4 : CWE — COMMON WEAKNESS ENUMERATION

**CWE** classe les **types génériques de faiblesses** dans le code et l'architecture. Là où CVE décrit une instance spécifique, CWE décrit la famille.

### 🔵 CWE Top 25 Most Dangerous Software Weaknesses (2023)

```
┌──────────────────────────────────────────────────────────────────────┐
│  RANG  │  CWE ID  │  NOM                          │  EXEMPLE         │
├──────────────────────────────────────────────────────────────────────┤
│   1    │  CWE-787 │  Out-of-bounds Write           │  Buffer Overflow │
│   2    │  CWE-79  │  Cross-site Scripting (XSS)    │  Stored XSS      │
│   3    │  CWE-89  │  SQL Injection                 │  SQLi classique  │
│   4    │  CWE-416 │  Use After Free                │  Memory exploit  │
│   5    │  CWE-78  │  OS Command Injection          │  ; cat /etc/passwd│
│   6    │  CWE-20  │  Improper Input Validation     │  Upload bypass   │
│   7    │  CWE-125 │  Out-of-bounds Read            │  Heartbleed      │
│   8    │  CWE-22  │  Path Traversal                │  ../../etc/passwd│
│   9    │  CWE-352 │  CSRF                          │  Faux formulaire │
│  10    │  CWE-434 │  Unrestricted File Upload      │  Upload webshell │
│  11    │  CWE-862 │  Missing Authorization         │  IDOR            │
│  12    │  CWE-476 │  NULL Pointer Dereference      │  Crash système   │
│  13    │  CWE-287 │  Improper Authentication       │  Auth bypass     │
│  14    │  CWE-190 │  Integer Overflow              │  Calc erreur     │
│  15    │  CWE-502 │  Deserialization               │  Java RCE        │
│  16    │  CWE-77  │  Command Injection             │  Shell injection  │
│  17    │  CWE-119 │  Buffer Errors                 │  Stack overflow  │
│  18    │  CWE-798 │  Hard-coded Credentials        │  Password dans code│
│  19    │  CWE-918 │  SSRF                          │  AWS metadata    │
│  20    │  CWE-306 │  Missing Auth Critical Function│  No auth check   │
└──────────────────────────────────────────────────────────────────────┘
```

### 🔵 Relation CVE ↔ CWE ↔ CVSS

```
                    EXEMPLE CONCRET : Log4Shell

CWE-917 → Improper Neutralization of Special Elements in Expression Language
  │
  ▼
CVE-2021-44228 → Implémentation spécifique dans Apache Log4j 2.0-2.14.1
  │
  ▼
CVSS 10.0 → AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
  │
  ▼
Patch → Log4j 2.15.0 puis 2.17.1 (corrections multiples)
```

---

## 📌 PARTIE 5 : NESSUS — MAÎTRISE COMPLÈTE

**Nessus** de **Tenable** est le scanner de vulnérabilités le plus utilisé au monde avec plus de 160 000 plugins. Il est la référence absolue pour les examens CEH.

**Versions :**
```
┌────────────────────────────────────────────────────────────────┐
│  VERSION         │  CIBLE      │  PLUGINS  │  PRIX             │
├────────────────────────────────────────────────────────────────┤
│  Nessus Essentials│ 16 IPs max │  ~167 000 │  Gratuit          │
│  Nessus Pro      │  Illimité   │  ~167 000 │  ~4000$/an        │
│  Tenable.io      │  Cloud      │  ~167 000 │  Sur devis        │
│  Tenable.sc      │  Entreprise │  ~167 000 │  Sur devis        │
└────────────────────────────────────────────────────────────────┘
```

---

### 🛠️ Installation et accès

```bash
# Télécharger et installer (Kali/Debian)
dpkg -i Nessus-10.6.0-debian10_amd64.deb

# Démarrer le service
sudo systemctl start nessusd
sudo systemctl enable nessusd

# Accès interface web
https://localhost:8834
```

---

### 🛠️ Types de scans Nessus

```
┌────────────────────────────────────────────────────────────────┐
│  TYPE DE SCAN          │  DESCRIPTION                          │
├────────────────────────────────────────────────────────────────┤
│  Basic Network Scan    │  Scan standard, toutes vulnérabilités │
│  Advanced Scan         │  Paramètres fins, max contrôle        │
│  Credentialed Patch Audit│ Avec credentials → patches manquants│
│  Web Application Tests │  Spécifique apps web (SQLi, XSS...)   │
│  Malware Scan          │  Détection malwares actifs            │
│  Mobile Device Scan    │  Périphériques mobiles MDM            │
│  Policy Compliance     │  Conformité CIS, DISA STIG, PCI DSS  │
│  Internal PCI Network  │  Conformité PCI DSS réseau interne    │
└────────────────────────────────────────────────────────────────┘
```

---

### 📊 RAPPORT NESSUS COMPLET — Sortie réelle simulée

```
╔══════════════════════════════════════════════════════════════════╗
║          NESSUS SCAN REPORT                                      ║
║          Target: 192.168.1.10 (metasploitable)                   ║
║          Scan Date: 2024-11-15 16:00:00 - 16:23:45 CAT          ║
║          Plugin Feed: 202411150000                               ║
╚══════════════════════════════════════════════════════════════════╝

═══════════════════════════════
EXECUTIVE SUMMARY
═══════════════════════════════

Total Vulnerabilities Found: 127
  ┌─────────────────────────────────┐
  │  Critical : ████████████  47   │
  │  High      : ███████████  38   │
  │  Medium    : ████████     24   │
  │  Low       : ████          9   │
  │  Info      : ███           9   │
  └─────────────────────────────────┘

Risk Score: 10.0 / 10.0

═══════════════════════════════════════════════════════════════════
FINDING #001 — CRITICAL (10.0)
═══════════════════════════════════════════════════════════════════
Plugin ID   : 65999
Plugin Name : vsftpd 2.3.4 Backdoor Command Execution
CVE         : CVE-2011-2523
CVSS v3.1   : 10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
CWE         : CWE-78 (OS Command Injection)
Port        : 21/tcp (FTP)

DESCRIPTION:
The version of vsftpd (Very Secure FTP Daemon) installed on the
remote host contains a backdoor. The backdoor was introduced into
the vsftpd 2.3.4 source code by a malicious third party.

The backdoor is triggered when a user attempts to log in with a
username containing the string ":)" (smiley face). When triggered,
the backdoor opens a shell on TCP port 6200 of the remote host.

EVIDENCE:
  Service:  vsftpd 2.3.4
  Port:     21/tcp
  Banner:   220 (vsFTPd 2.3.4)
  Verified: Backdoor shell confirmed on port 6200

PROOF OF CONCEPT:
  USER exploit4040:)
  → Shell opens on 192.168.1.10:6200
  → uid=0(root) gid=0(root) groups=0(root)

SOLUTION:
  Upgrade to vsftpd 2.3.5 or later immediately.
  This version removes the backdoor entirely.

REFERENCES:
  CVE-2011-2523
  https://www.securityfocus.com/bid/48539
  https://www.exploit-db.com/exploits/17491

═══════════════════════════════════════════════════════════════════
FINDING #002 — CRITICAL (10.0)
═══════════════════════════════════════════════════════════════════
Plugin ID   : 56210
Plugin Name : Samba "username map script" Command Execution
CVE         : CVE-2007-2447
CVSS v3.1   : 10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
CWE         : CWE-78 (OS Command Injection)
Port        : 139/tcp, 445/tcp (SMB)

DESCRIPTION:
The version of Samba installed on the remote host is affected by
a command execution vulnerability. In Samba versions 3.0.0 through
3.0.25rc3, the MS-RPC functionality allows remote attackers to
execute arbitrary commands via shell metacharacters in the username
parameter of the SamrChangePassword function.

EVIDENCE:
  Service:  Samba smbd 3.0.20-Debian
  Ports:    139/tcp, 445/tcp
  Version:  3.0.20 (VULNERABLE range: 3.0.0 - 3.0.25rc3)

SOLUTION:
  Upgrade to Samba 3.0.25rc3 or higher.
  Apply Samba security patch 3.0.24 immediately.

═══════════════════════════════════════════════════════════════════
FINDING #003 — CRITICAL (9.8)
═══════════════════════════════════════════════════════════════════
Plugin ID   : 78479
Plugin Name : MySQL 5.x < 5.5.48 Multiple Vulnerabilities
CVE         : CVE-2016-0546, CVE-2016-0616
CVSS v3.1   : 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
CWE         : CWE-284 (Improper Access Control)
Port        : 3306/tcp (MySQL)

DESCRIPTION:
The version of MySQL running on the remote host is 5.0.51a,
which is affected by multiple critical vulnerabilities including:

  - Authentication bypass allowing unauthenticated root access
  - Remote code execution via UDF (User Defined Functions)
  - Privilege escalation via MySQL system tables

EVIDENCE:
  Version: MySQL 5.0.51a-3ubuntu5
  Root accessible without password:
  mysql -h 192.168.1.10 -u root -e "SELECT user();"
  → root@localhost (NO PASSWORD REQUIRED)

SOLUTION:
  Upgrade to MySQL 5.5.48 or 5.7.x minimum.
  Immediately set root password.
  Restrict 3306/tcp to localhost only.

═══════════════════════════════════════════════════════════════════
FINDING #004 — CRITICAL (9.8)
═══════════════════════════════════════════════════════════════════
Plugin ID   : 42411
Plugin Name : MS09-050: Microsoft Windows SMB2 Command Value
              Vulnerability (975497)
CVE         : CVE-2009-3103
CVSS v3.1   : 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
CWE         : CWE-399 (Resource Management Errors)
Port        : 445/tcp (SMB)

DESCRIPTION:
The remote Windows host has a vulnerability in its SMB2
implementation that can allow remote code execution. An attacker
can send specially crafted SMB2 packets to crash the system
or execute arbitrary code.

EVIDENCE:
  OS:   Windows Vista/2008 (detected)
  Port: 445/tcp open
  SMB2 negotiation response confirms vulnerable version

═══════════════════════════════════════════════════════════════════
FINDING #005 — HIGH (8.8)
═══════════════════════════════════════════════════════════════════
Plugin ID   : 73411
Plugin Name : VNC Server Unencrypted Communications
CVE         : CVE-2019-15239
CVSS v3.1   : 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
Port        : 5900/tcp (VNC)

DESCRIPTION:
A VNC server is running on the remote host using protocol version
3.3 which transmits all data unencrypted. An attacker with network
access can capture VNC sessions, including screenshots and
keystrokes, via a man-in-the-middle attack.

Additionally, the VNC server may be accessible with a weak or
default password.

EVIDENCE:
  Service:   VNC Protocol 3.3
  Port:      5900/tcp
  Encryption: NONE
  Authentication: Password only (no certificate)
  Test:      Authentication successful with password "password"

SOLUTION:
  Configure VNC to use TLS/SSL encryption.
  Use VNC over SSH tunnel.
  Upgrade to VNC protocol version 4+.
  Set strong password (16+ characters minimum).

═══════════════════════════════════════════════════════════════════
FINDING #006 — HIGH (7.5)
═══════════════════════════════════════════════════════════════════
Plugin ID   : 10386
Plugin Name : Web Server HTTP TRACE / TRACK Methods Allowed
CVE         : CVE-2004-2320
CVSS v3.1   : 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
CWE         : CWE-16 (Configuration)
Port        : 80/tcp (HTTP)

DESCRIPTION:
The remote web server supports TRACE and/or TRACK HTTP methods.
These methods are typically used for debugging web server
connections. They can be used by an attacker to obtain sensitive
information from HTTP headers that may contain authentication
credentials, cookies, and other sensitive data.

This is known as Cross-Site Tracing (XST).

EVIDENCE:
  Server:  Apache/2.2.8
  Method:  TRACE
  Request: TRACE / HTTP/1.1
  Response:
    HTTP/1.1 200 OK
    Content-Type: message/http
    TRACE / HTTP/1.1
    Host: 192.168.1.10
    Cookie: PHPSESSID=abc123def456 ← COOKIE EXPOSÉ !

SOLUTION:
  In Apache: Add "TraceEnable Off" to httpd.conf

═══════════════════════════════════════════════════════════════════
FINDING #007 — HIGH (7.5)
═══════════════════════════════════════════════════════════════════
Plugin ID   : 10881
Plugin Name : SSH Protocol Version 1 Supported
CVE         : CVE-2001-0572
CVSS v3.1   : 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
Port        : 22/tcp (SSH)

DESCRIPTION:
The remote SSH daemon supports connections made using the version 1
of the SSH protocol. SSH protocol v1 suffers from several
cryptographic flaws that make it possible for a passive observer
to obtain the cleartext of the encrypted session.

SOLUTION:
  Disable SSH protocol version 1 in sshd_config:
  Protocol 2

═══════════════════════════════════════════════════════════════════
FINDING #008 — MEDIUM (6.5)
═══════════════════════════════════════════════════════════════════
Plugin ID   : 35362
Plugin Name : SSL Certificate Cannot Be Trusted
CVE         : N/A
CVSS v3.1   : 6.5
Port        : 443/tcp (HTTPS)

DESCRIPTION:
The SSL certificate for this service cannot be trusted. This could
indicate a self-signed certificate or an expired certificate.
An attacker could use this to perform a man-in-the-middle attack.

EVIDENCE:
  Certificate Subject: CN=metasploitable
  Issuer: CN=metasploitable (SELF-SIGNED)
  Expiry: 2013-07-08 (EXPIRED 11 YEARS AGO)

SOLUTION:
  Purchase and install a valid SSL certificate from a
  trusted Certificate Authority (CA).

═══════════════════════════════════════════════════════════════════
FINDING #009 — MEDIUM (5.3)
═══════════════════════════════════════════════════════════════════
Plugin ID   : 17156
Plugin Name : MySQL Unpassworded Account Check
CVE         : CVE-2004-0627
CVSS v3.1   : 5.3
Port        : 3306/tcp (MySQL)

DESCRIPTION:
The MySQL installation on the remote host has an account with an
empty password. An attacker could use these credentials to read
or modify data stored in the database.

EVIDENCE:
  Account: root (empty password)
  Account: anonymous (empty password)
  Access: SELECT, INSERT, UPDATE, DELETE, DROP confirmed

═══════════════════════════════════════════════════════════════════
FINDING #010 — LOW (3.7)
═══════════════════════════════════════════════════════════════════
Plugin ID   : 53360
Plugin Name : SSL BEAST Attack
CVE         : CVE-2011-3389
CVSS v3.1   : 3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)
Port        : 443/tcp (HTTPS)

DESCRIPTION:
The remote host supports the use of SSL/TLS ciphers that operate
in CBC mode. These cipher suites offer an 'export grade' level of
encryption and may be vulnerable to the BEAST attack, which allows
man-in-the-middle attackers to obtain plaintext.

SOLUTION:
  Disable CBC ciphers. Prefer GCM ciphers.
  Upgrade to TLS 1.2 minimum, prefer TLS 1.3.

═══════════════════════════════════════════════════════════════════
VULNERABILITY SUMMARY TABLE
═══════════════════════════════════════════════════════════════════

PORT     PROTOCOL  SERVICE      CRITICAL  HIGH  MEDIUM  LOW
---------------------------------------------------------------
21/tcp   tcp       ftp          3         2     1       0
22/tcp   tcp       ssh          1         3     2       1
23/tcp   tcp       telnet       2         1     0       0
25/tcp   tcp       smtp         0         2     3       0
80/tcp   tcp       http         1         4     5       2
139/tcp  tcp       smb          4         3     1       0
443/tcp  tcp       https        0         1     4       3
445/tcp  tcp       microsoft-ds 5         2     1       0
3306/tcp tcp       mysql        4         2     3       1
5432/tcp tcp       postgresql   2         1     2       0
5900/tcp tcp       vnc          2         3     1       0
8180/tcp tcp       tomcat       3         4     2       1

═══════════════════════════════════════════════════════════════════
REMEDIATION PRIORITY
═══════════════════════════════════════════════════════════════════

IMMEDIATE (24-48h):
  1. vsftpd 2.3.4 backdoor → Désinstaller/Upgrader (CVE-2011-2523)
  2. Samba RCE             → Patcher Samba (CVE-2007-2447)
  3. MySQL root sans mdp   → Setter mot de passe root MySQL
  4. SMBv1 actif           → Désactiver SMBv1

URGENT (7 jours):
  5. SSH Protocol v1       → Désactiver SSHv1
  6. Telnet actif          → Remplacer par SSH
  7. VNC non chiffré       → Tunnel SSH ou TLS
  8. HTTP TRACE activé     → TraceEnable Off

PLANNED (30 jours):
  9.  Certificat SSL expiré → Renouveler certificat
  10. Apache 2.2.8          → Upgrader vers 2.4.x
  11. OpenSSH 4.7p1         → Upgrader vers 9.x
  12. PostgreSQL 8.3        → Upgrader vers 15.x
```

---

## 📌 PARTIE 6 : OPENVAS — SCANNER OPEN SOURCE DE RÉFÉRENCE

**OpenVAS (Open Vulnerability Assessment System)** est maintenu par **Greenbone Networks**. C'est l'alternative open source gratuite à Nessus, intégrée dans Kali Linux.

Architecture :
```
┌────────────────────────────────────────────────────────────────┐
│  COMPOSANT              │  RÔLE                                │
├────────────────────────────────────────────────────────────────┤
│  GSA (Greenbone         │  Interface web (port 9392)           │
│  Security Assistant)    │                                       │
│  GVM (Greenbone         │  Gestionnaire central                │
│  Vulnerability Manager) │                                       │
│  OpenVAS Scanner        │  Moteur de scan actif               │
│  NVT Feed               │  Base de ~150 000 tests             │
└────────────────────────────────────────────────────────────────┘
```

### 🛠️ Installation et lancement

```bash
# Installation sur Kali
sudo apt install gvm -y

# Configuration initiale
sudo gvm-setup

# Démarrage des services
sudo gvm-start

# Accès interface
https://localhost:9392
# Credentials générés lors du setup
```

---

### 📊 RAPPORT OPENVAS — Sortie réelle simulée

```
╔══════════════════════════════════════════════════════════════════╗
║  GREENBONE SECURITY ASSISTANT — SCAN REPORT                      ║
║  Task:    Full and Fast                                          ║
║  Target:  192.168.1.10                                           ║
║  Started: 2024-11-15 16:30 CAT                                   ║
║  Ended:   2024-11-15 17:15 CAT                                   ║
╚══════════════════════════════════════════════════════════════════╝

RESULTS OVERVIEW:
  High     : 34
  Medium   : 29
  Low      : 18
  Log      : 45
  Total    : 126

──────────────────────────────────────────────────────────────────
HIGH | OID: 1.3.6.1.4.1.25623.1.0.900612
      vsftpd 2.3.4 Backdoor Command Execution
      CVSS: 10.0
      Port: 21/tcp
      
      Summary:
      The host is running vsftpd 2.3.4 which contains a backdoor
      introduced into the source code. A remote attacker can exploit
      this to execute arbitrary commands with root privileges.
      
      Vulnerability Detection Result:
      It was possible to login and access port 6200 successfully.
      
      Result:
      id output: uid=0(root) gid=0(root) groups=0(root)
      
──────────────────────────────────────────────────────────────────
HIGH | OID: 1.3.6.1.4.1.25623.1.0.100261
      Samba Remote Code Execution Vulnerability
      CVSS: 10.0
      Port: 445/tcp

      Summary:
      Samba 3.0.20 is vulnerable to a remote code execution
      vulnerability via the "username map script" configuration
      option. Unauthenticated attackers can execute commands
      as the root user.

      Vulnerability Detection Result:
      Successful exploitation via Metasploit module
      exploit/multi/samba/usermap_script confirmed.
      Shell returned: root@metasploitable

──────────────────────────────────────────────────────────────────
HIGH | OID: 1.3.6.1.4.1.25623.1.0.103674
      PostgreSQL Multiple Security Vulnerabilities
      CVSS: 8.5
      Port: 5432/tcp
      
      Summary:
      PostgreSQL 8.3.0 is affected by authentication bypass and
      privilege escalation vulnerabilities.
      
      Vulnerability Detection Result:
      psql -h 192.168.1.10 -U postgres → Connected without password
      Confirmed: no authentication required for postgres superuser

──────────────────────────────────────────────────────────────────
MEDIUM | OID: 1.3.6.1.4.1.25623.1.0.80091
        SMTP Server Supports VRFY Command
        CVSS: 5.0
        Port: 25/tcp
        
        Summary:
        The SMTP server supports the VRFY command which can be used
        to enumerate valid usernames on the system.
        
        Vulnerability Detection Result:
        VRFY root → 252 root (valid)
        VRFY msfadmin → 252 msfadmin (valid)
        VRFY user → 252 user (valid)
        12 valid usernames confirmed via VRFY enumeration.

──────────────────────────────────────────────────────────────────
MEDIUM | OID: 1.3.6.1.4.1.25623.1.0.103239
        Anonymous FTP Access Possible
        CVSS: 6.4
        Port: 21/tcp
        
        Vulnerability Detection Result:
        Connected as anonymous user.
        FTP > ls
        drwxr-xr-x   pub/
        -rw-r--r--   backup.tar.gz (1.2 MB)
        -rw-r--r--   passwords_old.txt

        File 'passwords_old.txt' successfully downloaded.
        Contents reveal 23 cleartext passwords.
```

---

## 📌 PARTIE 7 : PROCESSUS COMPLET D'ANALYSE DE VULNÉRABILITÉS

### 🔵 Étape 1 : Identification des actifs

```
INVENTAIRE DES ACTIFS — 192.168.1.0/24
═══════════════════════════════════════════════════

ID    IP              HOSTNAME         OS                  CRITICITÉ
───────────────────────────────────────────────────────────────────
A001  192.168.1.1     ROUTER-CISCO     IOS 15.4            HAUTE
A002  192.168.1.10    METASPLOITABLE   Linux 2.6.24        CRITIQUE
A003  192.168.1.15    WIN-SERVER01     Windows Server 2019 CRITIQUE
A004  192.168.1.20    WIN7-CLIENT      Windows 10          MOYENNE
A005  192.168.1.100   RPI-IOT          Raspbian 10         BASSE
```

---

### 🔵 Étape 2 : Classification des vulnérabilités

```
MATRICE DE PRIORISATION
═══════════════════════════════════════════════════════════════════

         │  IMPACT FAIBLE  │  IMPACT MOYEN  │  IMPACT FORT   │
─────────┼─────────────────┼────────────────┼────────────────┤
PROB.    │                 │                │                │
FORTE    │     MOYEN       │     HAUT       │   CRITIQUE     │
─────────┼─────────────────┼────────────────┼────────────────┤
PROB.    │                 │                │                │
MOYENNE  │     FAIBLE      │     MOYEN      │     HAUT       │
─────────┼─────────────────┼────────────────┼────────────────┤
PROB.    │                 │                │                │
FAIBLE   │   INFORMATIONNEL│     FAIBLE     │     MOYEN      │
─────────┴─────────────────┴────────────────┴────────────────┘

Vulnérabilités placées dans la matrice :

CRITIQUE :
  → vsftpd 2.3.4 backdoor       (Prob: Forte / Impact: Fort)
  → Samba CVE-2007-2447          (Prob: Forte / Impact: Fort)
  → MySQL root sans mdp          (Prob: Forte / Impact: Fort)

HAUT :
  → SSH Protocol v1              (Prob: Moyenne / Impact: Fort)
  → VNC sans chiffrement         (Prob: Forte / Impact: Moyen)
  → HTTP TRACE activé            (Prob: Forte / Impact: Moyen)

MOYEN :
  → SSL expiré                   (Prob: Forte / Impact: Faible)
  → SNMP community "public"      (Prob: Moyenne / Impact: Moyen)
```

---

### 🔵 Étape 3 : Distinguer faux positifs et faux négatifs

```
FAUX POSITIF (False Positive) :
  Scanner signale une vulnérabilité qui N'EXISTE PAS réellement
  
  Exemple :
  Nessus détecte Apache 2.2.8 vulnérable à CVE-2017-7679
  Mais la distribution a backporté le patch → faux positif !
  
  Comment vérifier :
  → Test manuel (exploitation réelle possible ?)
  → Vérifier les changelogs de la distribution
  → Confirmer avec un deuxième scanner

FAUX NÉGATIF (False Negative) :
  Scanner ne détecte PAS une vulnérabilité qui EXISTE
  
  Causes :
  → Bannière modifiée (version masquée)
  → Pare-feu filtre les sondes du scanner
  → Plugin non disponible (zero-day)
  → Scan sans credentials (surface réduite)
  
  Contre-mesure :
  → Scans avec credentials (credentialed scan)
  → Combiner plusieurs scanners
  → Tests manuels de validation
```

---

### 🔵 Étape 4 : Scan avec credentials vs sans credentials

```
SANS CREDENTIALS :
  ─────────────────
  ✅ Simule un attaquant externe
  ✅ Aucun accès préalable requis
  ❌ Surface d'analyse limitée
  ❌ Plus de faux négatifs
  ❌ Ne voit pas les patches manquants

  Exemple de résultat :
  → 47 vulnérabilités critiques trouvées

AVEC CREDENTIALS (Credentialed Scan) :
  ──────────────────────────────────────
  ✅ Voit les patches manquants
  ✅ Analyse les configurations internes
  ✅ Inventaire logiciel complet
  ✅ Beaucoup moins de faux positifs
  ❌ Requiert des identifiants
  ❌ Simule une menace interne

  Exemple de résultat :
  → 127 vulnérabilités trouvées (2.7x plus)
  → 34 patches critiques manquants identifiés
  → Logiciels obsolètes non visibles en externe

Nessus — Configuration scan avec credentials :
┌─────────────────────────────────────────────┐
│ Settings → Credentials → Add                │
│ Category: Host                              │
│ Type: SSH (Linux) ou SMB/Windows            │
│ Username: root                              │
│ Password: ***                               │
│ → Elevation: sudo                           │
└─────────────────────────────────────────────┘
```

---

## 📌 PARTIE 8 : AUTRES SCANNERS — QUALYS, NEXPOSE, OPENVAS

### 🔵 QualysGuard

Scanner cloud de référence entreprise. Très utilisé pour les audits PCI DSS.

```
Caractéristiques :
├── SaaS (cloud) → Pas d'installation
├── Agents Qualys installés sur les endpoints
├── ~140 000 signatures de vulnérabilités
├── Conformité PCI DSS, ISO 27001, HIPAA intégrée
├── Tableau de bord temps réel
└── API REST complète pour automatisation
```

---

### 🔵 Nexpose (Rapid7)

Scanner intégré à l'écosystème **Metasploit**. Les vulnérabilités trouvées sont directement exploitables depuis Metasploit.

```
Rapport Nexpose — Extrait :

Asset: 192.168.1.10
Risk Score: 953 / 1000

ID      Title                               CVSS   Exploits
──────────────────────────────────────────────────────────
NX-1234 vsftpd 2.3.4 Backdoor              10.0   1 Metasploit
NX-2345 Samba Username Map Script RCE       10.0   2 Metasploit
NX-3456 Unreal IRCd Backdoor               10.0   1 Metasploit
NX-4567 MySQL < 5.0.96 Auth Bypass          9.8   1 Metasploit
NX-5678 NFS Exports World Readable          8.5   Manual

→ 5 vulnérabilités directement exploitables via Metasploit
```

---

## 📌 PARTIE 9 : LES MÉTRIQUES CVSS — EXERCICES PRATIQUES

### 🔵 Exercice 1 : Calculer le score d'une vulnérabilité

**Situation :** Un serveur web Apache sur internet a une faille XSS stockée. Quand un admin visite la page infectée, ses cookies sont volés. L'attaque ne nécessite aucun compte.

```
Analyse des métriques :
AV: N → Via réseau (internet)
AC: L → Facile à exploiter
PR: N → Aucun compte requis
UI: R → Admin doit visiter la page (interaction requise)
S:  C → Impact sur le navigateur admin (scope changed)
C:  H → Cookie volé = session compromise
I:  L → Modification partielle possible via session
A:  N → Pas d'impact disponibilité

Vecteur : AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N
Score approximatif : 8.2 — HIGH
```

---

### 🔵 Exercice 2 : Comparer deux vulnérabilités

```
Vulnérabilité A : CVE-2017-0144 (EternalBlue)
AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H → 8.1 HIGH

Vulnérabilité B : CVE-2021-44228 (Log4Shell)
AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0 CRITICAL

Pourquoi Log4Shell est plus critique qu'EternalBlue ?
→ AC:L vs AC:H : Log4Shell est plus facile à exploiter
→ S:C vs S:U  : Log4Shell a un impact étendu (pivot)
→ Les deux ont PR:N et UI:N (sans compte, sans interaction)
→ Mais Log4Shell = reproductible facilement + pivot possible
```

---

## 📌 PARTIE 10 : CONTRE-MESURES ET REMÉDIATION

```
PROCESSUS DE REMÉDIATION PROFESSIONNELLE
═════════════════════════════════════════

ÉTAPE 1 : TRIAGE ET PRIORISATION
  ├── Classer par score CVSS
  ├── Pondérer par criticité du système
  ├── Identifier les vulnérabilités exploitées activement
  └── Définir les délais de correction

ÉTAPE 2 : PATCH MANAGEMENT
  ├── CRITIQUE (9.0-10.0) → Patch sous 24-48h
  ├── HIGH (7.0-8.9)      → Patch sous 7 jours
  ├── MEDIUM (4.0-6.9)    → Patch sous 30 jours
  └── LOW (0.1-3.9)       → Patch lors de maintenance

ÉTAPE 3 : WORKAROUNDS (si patch impossible)
  ├── Désactiver le service vulnérable
  ├── Filtrer par pare-feu
  ├── Segmentation réseau
  └── Contrôles compensatoires

ÉTAPE 4 : VALIDATION
  ├── Rescan post-patch
  ├── Confirmer disparition de la vulnérabilité
  └── Documenter la correction

ÉTAPE 5 : REPORTING
  ├── Rapport technique (pour équipe IT)
  ├── Rapport exécutif (pour direction)
  └── Métriques : MTTD, MTTR, vulns actives
```

---

## 📌 RÉSUMÉ FINAL — CE QUE L'EXAMEN VA TESTER

```
✅ CVE format et signification — MITRE, NVD, CNA
✅ CVSS v3.1 — lire/décoder n'importe quel vecteur
✅ Toutes les métriques CVSS — AV, AC, PR, UI, S, C, I, A
✅ Tableau des scores 0-10 et criticités associées
✅ CWE vs CVE — différence et complémentarité
✅ CWE Top 25 — les plus importants par cœur
✅ Nessus — types de scans et lecture de rapport
✅ OpenVAS — architecture et usage
✅ Faux positif vs faux négatif — définitions et causes
✅ Credentialed vs uncredentialed scan — différences
✅ QualysGuard, Nexpose — utilités spécifiques
✅ Processus complet : identification → priorisation → patch
✅ Temporal Score — Exploit Maturity et Remediation Level
```

---

## 🧪 QUESTIONS TYPE EXAMEN CEH — MODULE 5

**Q1 :** Un vecteur CVSS indique `PR:N/UI:N`. Que signifient ces deux métriques ?
> **Réponse : PR:N = Aucun privilège requis, UI:N = Aucune interaction utilisateur nécessaire. Combinés = exploitable directement depuis internet sans compte.**

**Q2 :** Quelle est la différence entre un scan Nessus avec et sans credentials ?
> **Réponse : Avec credentials → voit les patches manquants, configurations internes, 2-3x plus de vulnérabilités. Sans credentials → simule un attaquant externe, surface réduite, plus de faux négatifs.**

**Q3 :** Un scan signale une vulnérabilité Apache mais la vérification manuelle montre que le patch a été backporté. Comment appelle-t-on ce résultat ?
> **Réponse : Faux positif (False Positive)**

**Q4 :** Quel score CVSS correspond à "Critique" et quel délai de remediation impose-t-il ?
> **Réponse : 9.0 à 10.0 = Critique → Patch immédiat sous 24-48 heures**

**Q5 :** Quelle différence fondamentale entre CVE et CWE ?
> **Réponse : CVE = instance spécifique d'une vulnérabilité dans un logiciel précis. CWE = type générique de faiblesse (famille). CVE-2021-44228 est une instance de CWE-917.**

**Q6 :** Quel scanner de vulnérabilités est directement intégré à Metasploit Framework ?
> **Réponse : Nexpose (Rapid7)**

**Q7 :** Une vulnérabilité a `S:C` dans son vecteur CVSS. Que signifie ce paramètre ?
> **Réponse : Scope Changed → l'impact dépasse le composant vulnérable et peut affecter d'autres systèmes. Typique des failles permettant le pivot.**

**Q8 :** Dans le Temporal Score CVSS, que signifie `E:H` ?
> **Réponse : Exploit Code Maturity: High → Un exploit fonctionnel est intégré dans des outils automatisés (Metasploit par exemple). Augmente urgence de la remediation.**

**Q9 :** Quel CWE correspond à la vulnérabilité SQL Injection ?
> **Réponse : CWE-89 — Improper Neutralization of Special Elements used in an SQL Command**

**Q10 :** Qu'est-ce qu'un faux négatif dans le contexte d'un scan de vulnérabilités et comment le réduire ?
> **Réponse : Faux négatif = vulnérabilité existante non détectée par le scanner. Réduction : scans avec credentials, combinaison de plusieurs scanners, tests manuels de validation, mise à jour des plugins.**
