# 🛡️ CEH v12 — MODULE 4 : ÉNUMÉRATION
### Guide pédagogique avancé avec sorties complètes | ML | exploit4040

---

## 📌 INTRODUCTION — L'ÉNUMÉRATION, LA PHASE QUI DÉCIDE TOUT

Si le scanning te dit **"la porte est ouverte"**, l'énumération te dit **"voici les noms de tous ceux qui vivent dedans, leurs clés, leurs habitudes, et le plan de la maison"**.

L'énumération c'est la **Phase 2 du scanning** mais beaucoup plus profonde. Tu passes d'une liste de ports ouverts à une **cartographie complète des ressources internes** : utilisateurs, groupes, partages, politiques de mots de passe, services, versions exactes.

> **Différence fondamentale :**
> - **Scanning** → Quel port est ouvert ?
> - **Énumération** → Qui tourne sur ce port, comment il est configuré, quels comptes existent, quels partages sont accessibles ?

L'énumération est **active** par nature — tu interagis directement avec les services. Elle est donc **détectable** si l'organisation a un monitoring en place.

---

## 📌 PARTIE 1 : ÉNUMÉRATION NETBIOS ET SMB

### 🔵 Comprendre NetBIOS en profondeur

**NetBIOS (Network Basic Input/Output System)** est un protocole développé par IBM en 1983 qui permet aux applications de communiquer sur un réseau local. Bien qu'ancien, il reste **massivement présent** dans les environnements Windows.

NetBIOS fonctionne sur trois ports :

```
┌──────────────────────────────────────────────────────────────┐
│  PORT   │  PROTOCOLE  │  SERVICE                            │
├──────────────────────────────────────────────────────────────┤
│  137    │    UDP      │  NetBIOS Name Service (NBNS)        │
│         │             │  → Résolution de noms NetBIOS       │
│  138    │    UDP      │  NetBIOS Datagram Service           │
│         │             │  → Communications sans connexion    │
│  139    │    TCP      │  NetBIOS Session Service            │
│         │             │  → Communications avec connexion    │
└──────────────────────────────────────────────────────────────┘
```

**SMB (Server Message Block)** est le protocole qui tourne **au-dessus de NetBIOS** pour le partage de fichiers, imprimantes et ressources réseau. Version moderne : **port 445 TCP directement**.

```
Architecture :
Application (partage fichier)
        ↓
      SMB
        ↓
  NetBIOS (port 139) ou Direct (port 445)
        ↓
     TCP/IP
```

---

### 🛠️ NBTSTAT — Enumération NetBIOS Windows

**nbtstat** est l'outil natif Windows pour interroger la table NetBIOS.

```cmd
# Afficher la table NetBIOS locale
nbtstat -n
```

**Sortie réelle :**
```
Wireless Network Connection:
Node IpAddress: [192.168.1.50] Scope Id: []

                NetBIOS Local Name Table

       Name               Type         Status
    -----------------------------------------------------
    WORKSTATION-01 <00>  UNIQUE      Registered
    WORKGROUP      <00>  GROUP       Registered
    WORKSTATION-01 <20>  UNIQUE      Registered
    WORKGROUP      <1E>  GROUP       Registered
    WORKGROUP      <1D>  UNIQUE      Registered
    ..__MSBROWSE__.<01>  GROUP       Registered
```

**Décodage des suffixes NetBIOS — CRITIQUE POUR LE CEH :**

```
┌─────────────────────────────────────────────────────────────────┐
│  SUFFIXE  │  TYPE    │  SIGNIFICATION                           │
├─────────────────────────────────────────────────────────────────┤
│  <00>     │  UNIQUE  │  Nom de l'ordinateur (Workstation)       │
│  <00>     │  GROUP   │  Nom du domaine/workgroup                │
│  <03>     │  UNIQUE  │  Service Messenger (utilisateur connecté)│
│  <06>     │  UNIQUE  │  RAS Server Service                      │
│  <1B>     │  UNIQUE  │  Domain Master Browser (PDC)            │
│  <1C>     │  GROUP   │  Domain Controllers du domaine           │
│  <1D>     │  UNIQUE  │  Master Browser local subnet             │
│  <1E>     │  GROUP   │  Browser Service Elections               │
│  <20>     │  UNIQUE  │  File Server Service (partage actif !)   │
│  <21>     │  UNIQUE  │  RAS Client Service                      │
│  <BE>     │  UNIQUE  │  Network Monitor Agent                   │
└─────────────────────────────────────────────────────────────────┘
```

> **Point clé CEH :** Voir `<20>` = le service de partage de fichiers est actif → cible prioritaire pour l'énumération SMB.

---

```cmd
# Afficher la table NetBIOS d'une machine distante
nbtstat -A 192.168.1.10
```

**Sortie réelle :**
```
NetBIOS Remote Machine Name Table

       Name               Type         Status
    -----------------------------------------------------
    METASPLOITABLE <00>  UNIQUE      Registered
    METASPLOITABLE <03>  UNIQUE      Registered
    METASPLOITABLE <20>  UNIQUE      Registered
    WORKGROUP      <00>  GROUP       Registered
    WORKGROUP      <1E>  GROUP       Registered

    MAC Address = 08:00:27:A1:BC:DE
```

**Analyse professionnelle :**
```
Informations extraites :
├── Nom machine    : METASPLOITABLE
├── Workgroup      : WORKGROUP (pas de domaine AD → réseau simple)
├── <20> présent   : Service de partage actif → SMB énumérable
├── <03> présent   : Utilisateur connecté (messenger service)
└── MAC Address    : 08:00:27 → Oracle VirtualBox (VM confirmée)

Prochaine étape → Énumération SMB complète
```

---

### 🛠️ NBTSCAN — Scan réseau NetBIOS

```bash
nbtscan 192.168.1.0/24
```

**Sortie réelle :**
```
Doing NBT name scan for addresses from 192.168.1.0/24

IP address       NetBIOS Name     Server    User             MAC address
------------------------------------------------------------------------------
192.168.1.1      ROUTEUR          <server>  <unknown>        c8:d7:19:ab:12:3f
192.168.1.10     METASPLOITABLE   <server>  METASPLOITABLE   08:00:27:a1:bc:de
192.168.1.15     WIN-SERVER01     <server>  Administrateur   00:50:56:c0:00:08
192.168.1.20     WIN7-CLIENT      <server>  jean.muamba      52:54:00:12:34:56
192.168.1.50     LAPTOP-ML        <server>  exploit4040      b8:27:eb:a1:23:45
```

**Analyse professionnelle :**
```
Découvertes critiques :
├── 192.168.1.15  → WIN-SERVER01, connecté en tant qu'Administrateur !
│                   → Compte admin actif, cible prioritaire
├── 192.168.1.20  → jean.muamba connecté
│                   → Nom d'utilisateur réel découvert → bruteforce possible
└── 192.168.1.50  → exploit4040 (c'est toi !)

→ En une seule commande : noms machines + utilisateurs connectés + MACs
```

---

### 🛠️ ENUM4LINUX — Énumération SMB Linux complète

**enum4linux** est l'outil de référence pour l'énumération SMB depuis Linux. Il combine plusieurs outils (smbclient, rpcclient, nmblookup) en une seule interface.

```bash
enum4linux -a 192.168.1.10
```

**Sortie réelle complète :**

```
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ )
 ==========================
|    Target Information    |
 ==========================
Target ........... 192.168.1.10
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

 ====================================================
|    Enumerating Workgroup/Domain on 192.168.1.10    |
 ====================================================
[+] Got domain/workgroup name: WORKGROUP

 ========================================
|    Nbtstat Information for 192.168.1.10|
 ========================================
Looking up status of 192.168.1.10
        METASPLOITABLE  <00> -         B <ACTIVE>
        METASPLOITABLE  <03> -         B <ACTIVE>
        METASPLOITABLE  <20> -         B <ACTIVE>
        WORKGROUP       <00> - <GROUP> B <ACTIVE>
        WORKGROUP       <1e> - <GROUP> B <ACTIVE>
        MAC Address = 08:00:27:A1:BC:DE

 ===================================
|    Session Check on 192.168.1.10  |
 ===================================
[+] Server 192.168.1.10 allows sessions using username '',
    password '' (NULL session!)

 ===============================================
|    Getting domain SID for 192.168.1.10        |
 ===============================================
Domain Name: WORKGROUP
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 =====================================
|    OS information on 192.168.1.10   |
 =====================================
[+] Got OS info for 192.168.1.10 from smbclient:
    Domain=[WORKGROUP] OS=[Unix] Server=[Samba 3.0.20-Debian]
[+] Got OS info for 192.168.1.10 from srvinfo:
    METASPLOITABLE Wk Sv PrQ Unx NT SNT metasploitable server
    platform_id     :       500
    os version      :       4.9
    server type     :       0x809a03

 ===================================
|    Users on 192.168.1.10          |
 ===================================
index: 0x1 RID: 0x3f2 acb: 0x00000011 Account: games    Name: games
       Desc: (null)
index: 0x2 RID: 0x1f5 acb: 0x00000011 Account: root     Name: root
       Desc: (null)
index: 0x3 RID: 0x4ba acb: 0x00000011 Account: sys      Name: sys
       Desc: (null)
index: 0x4 RID: 0x4c0 acb: 0x00000011 Account: klog     Name: klog
       Desc: (null)
index: 0x5 RID: 0x4c2 acb: 0x00000011 Account: syslog   Name: syslog
       Desc: (null)
index: 0x6 RID: 0x4c4 acb: 0x00000011 Account: user     Name: just a user,,,
       Desc: (null)
index: 0x7 RID: 0x4c5 acb: 0x00000011 Account: www-data Name: www-data
       Desc: (null)
index: 0x8 RID: 0x4c6 acb: 0x00000011 Account: backup   Name: backup
       Desc: (null)
index: 0x9 RID: 0x4ca acb: 0x00000011 Account: nobody   Name: nobody
       Desc: (null)
index: 0xa RID: 0x4ce acb: 0x00000011 Account: msfadmin Name: msfadmin,,,
       Desc: (null)
index: 0xb RID: 0x4d0 acb: 0x00000011 Account: postgres  Name: PostgreSQL..
       Desc: (null)
index: 0xc RID: 0x4d2 acb: 0x00000011 Account: service  Name: service,,,
       Desc: (null)
index: 0xd RID: 0x4d4 acb: 0x00000011 Account: mysql    Name: MySQL Server
       Desc: (null)
index: 0xe RID: 0x4d6 acb: 0x00000011 Account: tomcat55 Name: (null)
       Desc: (null)

[+] Password Info for Domain: WORKGROUP
        [+] Minimum password length: None
        [+] Password history length: None
        [+] Maximum password age: Not Set
        [+] Password Complexity Flags: 000000

 ===================================
|    Share Enumeration on 192.168.1.10|
 ===================================

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        tmp             Disk      oh noes!
        opt             Disk
        IPC$            IPC       IPC Service (metasploitable server)
        ADMIN$          IPC       IPC Service (metasploitable server)

[+] Attempting to map shares on 192.168.1.10
//192.168.1.10/print$    Mapping: DENIED Listing: N/A
//192.168.1.10/tmp       Mapping: OK Listing: OK   ← ACCESSIBLE !
//192.168.1.10/opt       Mapping: DENIED Listing: N/A

 =====================================================
|    Password Policy Information for 192.168.1.10    |
 =====================================================
[+] Attaching to 192.168.1.10 using a NULL session
[+] Trying protocol 139/SMB...
[+] Found domain(s):
        [+] WORKGROUP
        [+] Builtin
[+] Password Info for Domain: WORKGROUP
        Minimum password length: 0   ← PAS DE MINIMUM !
        Password history length: 0   ← PAS D'HISTORIQUE !
        Maximum password age:    Not Set
        Password Complexity:     Disabled   ← PAS DE COMPLEXITÉ !
        Minimum password age:    None
        Account lockout threshold: None  ← PAS DE VERROUILLAGE !
        Forced logoff time:       Not Set

enum4linux complete on Fri Nov 15 15:45:23 2024
```

**Analyse professionnelle — Résultat explosif :**
```
🔴 VULNÉRABILITÉS CRITIQUES IDENTIFIÉES :

1. NULL SESSION active → Accès sans authentification !
   → Tout l'annuaire est lisible sans mot de passe

2. 14 comptes utilisateurs découverts :
   root, msfadmin, postgres, mysql, tomcat55, www-data...
   → Liste parfaite pour bruteforce SSH/FTP

3. Partage /tmp accessible en lecture/écriture !
   → On peut lire et écrire des fichiers sans auth

4. Politique de mot de passe = CATASTROPHIQUE :
   → Longueur minimum : 0 (mot de passe vide accepté !)
   → Pas de complexité requise
   → Pas de verrouillage après tentatives échouées
   → Bruteforce illimité possible !

5. Samba 3.0.20 → CVE-2007-2447 (username map script)
   → RCE sans authentification disponible dans Metasploit
```

---

### 🛠️ SMBMAP — Cartographier les partages SMB

```bash
smbmap -H 192.168.1.10
```

**Sortie réelle :**
```
[+] IP: 192.168.1.10:445    Name: metasploitable
        Disk                                           Permissions    Comment
        ----                                           -----------    -------
        print$                                         NO ACCESS      Printer Drivers
        tmp                                            READ, WRITE    oh noes!
        opt                                            NO ACCESS
        IPC$                                           NO ACCESS      IPC Service
        ADMIN$                                         NO ACCESS      IPC Service
```

```bash
# Lister le contenu d'un partage accessible
smbmap -H 192.168.1.10 -r tmp
```

**Sortie :**
```
[+] IP: 192.168.1.10:445    Name: metasploitable
        [+] Starting smbmap v1.7.10
        dr--r--r--  0  Fri Nov 15 14:23:11 2024    .
        dr--r--r--  0  Fri Nov 15 14:23:11 2024    ..
        -r--r--r--  0  Fri Nov 15 09:12:45 2024    .X0-lock
        dr--r--r--  0  Fri Nov 15 09:12:44 2024    .X11-unix
        -rwxrwxrwx 12  Fri Nov 15 11:34:22 2024    backup_passwords.txt
        -rwxrwxrwx  0  Fri Nov 15 09:15:01 2024    vmware-root
```

> **`backup_passwords.txt` en accès libre → téléchargement immédiat !**

```bash
# Télécharger le fichier trouvé
smbmap -H 192.168.1.10 --download 'tmp/backup_passwords.txt'
```

---

### 🛠️ SMBCLIENT — Accès interactif SMB

```bash
smbclient //192.168.1.10/tmp -N
```

**Sortie et session interactive :**
```
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Nov 15 14:23:11 2024
  ..                                  D        0  Fri Nov 15 14:23:11 2024
  .X0-lock                            H        0  Fri Nov 15 09:12:45 2024
  .X11-unix                          DH        0  Fri Nov 15 09:12:44 2024
  backup_passwords.txt                A       12  Fri Nov 15 11:34:22 2024
  vmware-root                        DR        0  Fri Nov 15 09:15:01 2024

                7282168 blocks of size 1024. 5446492 blocks available

smb: \> get backup_passwords.txt
getting file \backup_passwords.txt of size 12 as backup_passwords.txt
(5.9 KiloBytes/sec) (average 5.9 KiloBytes/sec)

smb: \> put exploit4040.php
putting file exploit4040.php as \exploit4040.php (15.2 kb/s)

smb: \> exit
```

---

### 🛠️ RPCCLIENT — Énumération approfondie via RPC

**rpcclient** permet de faire des appels RPC (Remote Procedure Call) directement sur un serveur Windows/Samba.

```bash
rpcclient -U "" -N 192.168.1.10
```

**Session interactive complète :**

```
rpcclient $> srvinfo
        METASPLOITABLE Wk Sv PrQ Unx NT SNT metasploitable server
        platform_id     :       500
        os version      :       4.9
        server type     :       0x809a03

rpcclient $> enumdomusers
user:[games] rid:[0x3f2]
user:[root] rid:[0x1f5]
user:[sys] rid:[0x4ba]
user:[klog] rid:[0x4c0]
user:[syslog] rid:[0x4c2]
user:[user] rid:[0x4c4]
user:[www-data] rid:[0x4c5]
user:[backup] rid:[0x4c6]
user:[nobody] rid:[0x4ca]
user:[msfadmin] rid:[0x4ce]
user:[postgres] rid:[0x4d0]
user:[service] rid:[0x4d2]
user:[mysql] rid:[0x4d4]
user:[tomcat55] rid:[0x4d6]

rpcclient $> enumdomgroups
group:[root] rid:[0x200]
group:[users] rid:[0x201]
group:[nogroup] rid:[0x202]
group:[libuuid] rid:[0x203]
group:[adm] rid:[0x204]
group:[sudo] rid:[0x20a]
group:[admin] rid:[0x20b]

rpcclient $> queryuser 0x1f5
        User Name   :   root
        Full Name   :   root
        Home Drive  :   /root
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Fri, 15 Nov 2024 09:12:44 CAT
        Logoff Time              :      Wed, 31 Dec 1969 21:00:00 CAT
        Kickoff Time             :      Wed, 13 Sep 30828 17:48:05 CAT
        Password last set Time   :      Wed, 27 May 2012 10:58:09 CAT
        Password can change Time :      Wed, 27 May 2012 10:58:09 CAT
        Password must change Time:      Wed, 13 Sep 30828 17:48:05 CAT
        unknown_2[0]             :      0x00000000
        user_rid :      0x1f5
        group_rid:      0x201
        acb_info :      0x00000010
        fields_present:         0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000003
        padding1[0]:    0x00000000
        logon_hrs[0]:   0xff

rpcclient $> getdompwinfo
min_password_length: 0
password_properties: 0x00000000

rpcclient $> enumprinters
        flags:[0x800000]
        name:[\\192.168.1.10\HP_LaserJet_4050]
        description:[\\192.168.1.10\HP_LaserJet_4050,HP LaserJet 4050 Series PS]
        comment:[]
```

---

## 📌 PARTIE 2 : ÉNUMÉRATION SNMP

### 🔵 Comprendre SNMP en profondeur

**SNMP (Simple Network Management Protocol)** est le protocole utilisé pour **surveiller et gérer les équipements réseau** : routeurs, switches, serveurs, imprimantes.

Versions :
```
┌────────────────────────────────────────────────────────────────┐
│  VERSION  │  SÉCURITÉ          │  STATUS                       │
├────────────────────────────────────────────────────────────────┤
│  SNMPv1   │  Community string  │  Obsolète, très dangereux     │
│  SNMPv2c  │  Community string  │  Courant, encore dangereux    │
│  SNMPv3   │  Auth + Chiffrement│  Sécurisé, recommandé        │
└────────────────────────────────────────────────────────────────┘
```

**Community Strings = "mots de passe" SNMP :**
```
"public"  → Lecture seule (read-only) — défaut universel
"private" → Lecture/Écriture (read-write) — défaut dangereux
```

**OID (Object Identifier)** = adresse numérique de chaque information dans la MIB :
```
1.3.6.1.2.1.1.1.0    → sysDescr    (description du système)
1.3.6.1.2.1.1.3.0    → sysUpTime   (durée de fonctionnement)
1.3.6.1.2.1.1.5.0    → sysName     (nom du système)
1.3.6.1.2.1.2.1.0    → ifNumber    (nombre d'interfaces réseau)
1.3.6.1.2.1.4.34.1   → ipAddressTable (table des adresses IP)
1.3.6.1.4.1.77.1.2.25→ hrSWRunName  (logiciels en cours d'exécution)
```

---

### 🛠️ SNMPWALK — Parcourir toute la MIB

```bash
snmpwalk -c public -v1 192.168.1.10
```

**Sortie réelle (extrait) :**
```
iso.3.6.1.2.1.1.1.0 = STRING: "Linux metasploitable 2.6.24-16-server
                                #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (4823412) 13:23:54.12
iso.3.6.1.2.1.1.4.0 = STRING: "msfadmin@metasploitable"
iso.3.6.1.2.1.1.5.0 = STRING: "metasploitable"
iso.3.6.1.2.1.1.6.0 = STRING: "Hack the Planet"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.2.1.0 = INTEGER: 3
iso.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1
iso.3.6.1.2.1.2.2.1.2.1 = STRING: "lo"
iso.3.6.1.2.1.2.2.1.2.2 = STRING: "eth0"
iso.3.6.1.2.1.4.20.1.1.127.0.0.1 = IpAddress: 127.0.0.1
iso.3.6.1.2.1.4.20.1.1.192.168.1.10 = IpAddress: 192.168.1.10
iso.3.6.1.2.1.25.1.1.0 = Timeticks: (4823412) 13:23:54.12
iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E8 0B 0F 09 17 00 00 2B 00 00
iso.3.6.1.2.1.25.2.2.0 = INTEGER: 1024000
iso.3.6.1.2.1.25.4.2.1.2.1 = STRING: "init"
iso.3.6.1.2.1.25.4.2.1.2.2 = STRING: "kthreadd"
iso.3.6.1.2.1.25.4.2.1.2.588 = STRING: "apache2"
iso.3.6.1.2.1.25.4.2.1.2.602 = STRING: "sshd"
iso.3.6.1.2.1.25.4.2.1.2.614 = STRING: "vsftpd"
iso.3.6.1.2.1.25.4.2.1.2.621 = STRING: "mysqld"
iso.3.6.1.2.1.25.4.2.1.2.634 = STRING: "postgres"
iso.3.6.1.2.1.25.4.2.1.2.645 = STRING: "named"
iso.3.6.1.2.1.25.4.2.1.2.658 = STRING: "smbd"
iso.3.6.1.2.1.25.6.3.1.2.2 = STRING: "adduser-3.85ubuntu3"
iso.3.6.1.2.1.25.6.3.1.2.3 = STRING: "apache2-2.2.8-1ubuntu0.14"
iso.3.6.1.2.1.25.6.3.1.2.4 = STRING: "openssh-server-1:4.7p1-8ubuntu1"
iso.3.6.1.2.1.25.6.3.1.2.5 = STRING: "vsftpd-2.3.4"
iso.3.6.1.2.1.25.6.3.1.2.6 = STRING: "mysql-server-5.0.51a"
iso.3.6.1.2.1.25.6.3.1.2.7 = STRING: "samba-3.0.20-Debian"
```

**Analyse professionnelle :**
```
Informations extraites via SNMP :

Système :
├── OS      : Linux 2.6.24-16-server (Ubuntu 2008 !)
├── Uptime  : 13h 23min (redémarré ce matin)
├── Contact : msfadmin@metasploitable (email admin !)
├── Hostname: metasploitable
└── Location: "Hack the Planet" (indice humoristique)

Interfaces réseau :
├── lo  : 127.0.0.1
└── eth0: 192.168.1.10

Processus en cours d'exécution :
├── apache2   → Serveur web actif
├── sshd      → SSH actif
├── vsftpd    → FTP actif (version 2.3.4 !)
├── mysqld    → MySQL actif
├── postgres  → PostgreSQL actif
├── named     → DNS actif
└── smbd      → Samba actif

Logiciels installés (avec versions exactes) :
├── vsftpd 2.3.4          → BACKDOOR CONNUE !
├── openssh 4.7p1         → Ancienne version
├── apache2 2.2.8         → Ancienne version
├── mysql-server 5.0.51a  → Ancienne version
└── samba 3.0.20          → RCE CONNUE !
```

---

### 🛠️ SNMPCHECK — Rapport SNMP structuré

```bash
snmp-check 192.168.1.10 -c public
```

**Sortie réelle :**
```
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[*] Try to connect to 192.168.1.10:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 192.168.1.10
  Hostname                      : metasploitable
  Description                   : Linux metasploitable 2.6.24-16-server
  Contact                       : msfadmin@metasploitable
  Location                      : Hack the Planet
  Uptime snmp                   : 13:23:54.12
  Uptime system                 : 13:23:45.98
  System date                   : 2024-11-15 09:17:00 UTC

[*] Network information:

  IP forwarding enabled         : no
  Default TTL                   : 64
  TCP segments received         : 1337
  TCP segments sent             : 1289
  TCP segments retrans          : 12
  Input datagrams               : 24567
  Delivered datagrams           : 24345
  Output datagrams              : 24123

[*] Network interfaces:

  Interface                     : lo
  Id                            : 1
  Mac Address                   : :
  Type                          : softwareLoopback
  Speed                         : 10 Mbps
  MTU                           : 16436
  In octets                     : 173640
  Out octets                    : 173640

  Interface                     : eth0
  Id                            : 2
  Mac Address                   : 08:00:27:a1:bc:de
  Type                          : ethernetCsmacd
  Speed                         : 1000 Mbps
  MTU                           : 1500
  In octets                     : 4782345
  Out octets                    : 2345678

[*] Network IP:

  Id         IP Address          Netmask             Broadcast
  2          192.168.1.10        255.255.255.0        1

[*] Routing information:

  Destination         Next hop            Mask                Metric
  0.0.0.0             192.168.1.1         0.0.0.0             100
  192.168.1.0         0.0.0.0             255.255.255.0       0

[*] TCP connections and listening ports:

  Local address       Local port          Remote address      Remote port  State
  0.0.0.0             21                  0.0.0.0             0            listen
  0.0.0.0             22                  0.0.0.0             0            listen
  0.0.0.0             23                  0.0.0.0             0            listen
  0.0.0.0             25                  0.0.0.0             0            listen
  0.0.0.0             53                  0.0.0.0             0            listen
  0.0.0.0             80                  0.0.0.0             0            listen
  0.0.0.0             139                 0.0.0.0             0            listen
  0.0.0.0             445                 0.0.0.0             0            listen
  0.0.0.0             3306                0.0.0.0             0            listen
  0.0.0.0             5432                0.0.0.0             0            listen
  0.0.0.0             5900                0.0.0.0             0            listen
  192.168.1.10        139                 192.168.1.50        52234        established
  192.168.1.10        22                  192.168.1.50        48123        established

[*] Processes:

  Id          Status              Name                Path
  1           runnable            init                /sbin/init
  588         runnable            apache2             /usr/sbin/apache2
  602         runnable            sshd                /usr/sbin/sshd
  614         runnable            vsftpd              /usr/sbin/vsftpd
  621         runnable            mysqld              /usr/sbin/mysqld
  634         runnable            postgres            /usr/bin/postgres
  645         runnable            named               /usr/sbin/named
  658         runnable            smbd                /usr/sbin/smbd

[*] Storage information:

  Description                   : / (root partition)
  Device id                     : #<DEVICE>
  Filesystem type               : ext3
  Device unit                   : 1024 Bytes
  Memory size                   : 7282168 KB  (7.1 GB)
  Memory used                   : 1835676 KB  (1.7 GB)

[*] Software components:

  Index    Name
  1        adduser 3.85ubuntu3
  2        apache2 2.2.8-1ubuntu0.14
  3        openssh-server 4.7p1-8ubuntu1
  4        vsftpd 2.3.4
  5        mysql-server 5.0.51a-3ubuntu5
  6        postgresql 8.3.0
  7        samba 3.0.20-Debian

[*] User accounts:

  root
  bin
  daemon
  msfadmin
  user
  service
  postgres
  mysql
  tomcat55
```

---

## 📌 PARTIE 3 : ÉNUMÉRATION LDAP

### 🔵 Comprendre LDAP en profondeur

**LDAP (Lightweight Directory Access Protocol)** est le protocole d'accès aux **annuaires d'entreprise**. Dans un environnement Windows, c'est le protocole qui donne accès à **Active Directory**.

```
Ports LDAP :
├── 389  TCP/UDP  → LDAP standard (non chiffré)
└── 636  TCP      → LDAPS (chiffré TLS)

Structure LDAP :
DC=corp,DC=com           ← Domaine racine
├── OU=Users             ← Unité organisationnelle
│   ├── CN=Jean Muamba   ← Utilisateur
│   ├── CN=Admin Local   ← Utilisateur admin
│   └── CN=exploit4040   ← C'est toi !
├── OU=Computers
│   ├── CN=WORKSTATION01
│   └── CN=SERVER-DC01
└── OU=Groups
    ├── CN=Domain Admins
    └── CN=IT-Security
```

---

### 🛠️ LDAPSEARCH — Requêtes LDAP en ligne de commande

```bash
# Connexion anonyme (si autorisée)
ldapsearch -x -H ldap://192.168.1.15 -b "dc=corp,dc=com"
```

**Sortie réelle :**
```
# extended LDIF
#
# LDAPv3
# base <dc=corp,dc=com> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# corp.com
dn: dc=corp,dc=com
objectClass: top
objectClass: domain
dc: corp

# Users, corp.com
dn: ou=Users,dc=corp,dc=com
objectClass: organizationalUnit
ou: Users

# Jean Muamba, Users, corp.com
dn: cn=Jean Muamba,ou=Users,dc=corp,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Jean Muamba
sn: Muamba
givenName: Jean
distinguishedName: cn=Jean Muamba,ou=Users,dc=corp,dc=com
displayName: Jean Muamba
memberOf: cn=IT-Security,ou=Groups,dc=corp,dc=com
sAMAccountName: jean.muamba
userPrincipalName: jean.muamba@corp.com
mail: jean.muamba@corp.com
telephoneNumber: +243 81 234 5678
department: Informatique
title: Administrateur Système
lastLogon: 133461234567890123
pwdLastSet: 133351234567890123
userAccountControl: 512

# Administrateur, Users, corp.com
dn: cn=Administrateur,ou=Users,dc=corp,dc=com
objectClass: user
cn: Administrateur
sAMAccountName: Administrateur
userPrincipalName: Administrateur@corp.com
memberOf: cn=Domain Admins,ou=Groups,dc=corp,dc=com
userAccountControl: 66048
description: Compte d'administration du domaine

# Domain Admins, Groups, corp.com
dn: cn=Domain Admins,ou=Groups,dc=corp,dc=com
objectClass: group
cn: Domain Admins
member: cn=Administrateur,ou=Users,dc=corp,dc=com
member: cn=exploit4040,ou=Users,dc=corp,dc=com

# search result
search: 2
result: 0 Success

# numResponses: 15
# numEntries: 14
```

**Analyse professionnelle :**
```
Informations critiques extraites :

Utilisateurs découverts :
├── jean.muamba@corp.com
│   ├── Poste : Administrateur Système
│   ├── Téléphone : +243 81 234 5678
│   └── Membre de : IT-Security
│
└── Administrateur@corp.com
    └── Membre de : Domain Admins (compte le plus privilégié !)

Groupes critiques :
├── Domain Admins → Contrôle total du domaine AD
└── IT-Security   → Accès aux systèmes sensibles

Attributs sensibles :
├── userAccountControl: 512  → Compte normal actif
├── userAccountControl: 66048 → Admin sans expiration mdp !
└── pwdLastSet → Date du dernier changement de mot de passe
```

---

```bash
# Enumérer uniquement les utilisateurs
ldapsearch -x -H ldap://192.168.1.15 \
           -b "dc=corp,dc=com" \
           "(objectClass=user)" \
           sAMAccountName userPrincipalName memberOf
```

**Sortie :**
```
dn: cn=jean.muamba,ou=Users,dc=corp,dc=com
sAMAccountName: jean.muamba
userPrincipalName: jean.muamba@corp.com
memberOf: cn=IT-Security,ou=Groups,dc=corp,dc=com

dn: cn=Administrateur,ou=Users,dc=corp,dc=com
sAMAccountName: Administrateur
userPrincipalName: Administrateur@corp.com
memberOf: cn=Domain Admins,ou=Groups,dc=corp,dc=com

dn: cn=exploit4040,ou=Users,dc=corp,dc=com
sAMAccountName: exploit4040
userPrincipalName: exploit4040@corp.com
memberOf: cn=Domain Admins,ou=Groups,dc=corp,dc=com
memberOf: cn=IT-Security,ou=Groups,dc=corp,dc=com
```

---

## 📌 PARTIE 4 : ÉNUMÉRATION DNS

### 🛠️ DNSRECON — Énumération DNS complète

```bash
dnsrecon -d example.com -t std
```

**Sortie réelle :**
```
[*] std: Performing General Enumeration against: example.com
[*] DNSSEC is not configured for example.com
[+] SOA ns1.example.com 93.184.216.100
[+] NS ns1.example.com 93.184.216.100
[+] NS ns2.example.com 93.184.216.101
[+] MX mail.example.com 93.184.216.50
[+] MX mail2.example.com 93.184.216.51
[+]      A example.com 93.184.216.34
[+]      A www.example.com 93.184.216.34
[+]      A mail.example.com 93.184.216.50
[+]      A ftp.example.com 93.184.216.60
[+]      A dev.example.com 93.184.216.70
[+]      A staging.example.com 93.184.216.75
[+]      A vpn.example.com 93.184.216.80
[+]      A admin.example.com 93.184.216.90
[+]      TXT example.com "v=spf1 include:_spf.google.com ~all"
[+]      TXT example.com "google-site-verification=abc123xyz"
[+] Enumerating SRV Records
[+]  _sip._tcp.example.com 93.184.216.55 5060 10
[+]  _xmpp-server._tcp.example.com 93.184.216.56 5269 5
[*] Saving records to /tmp/dnsrecon_example.db
```

**Analyse :**
```
Sous-domaines découverts et leur signification :
├── www.example.com     → Site principal (public)
├── mail.example.com    → Serveur email
├── ftp.example.com     → Serveur FTP → bruteforce ?
├── dev.example.com     → Environnement de développement !
│                          Souvent moins sécurisé que prod
├── staging.example.com → Environnement de staging !
│                          Code de production avant déploiement
├── vpn.example.com     → VPN d'accès distant
└── admin.example.com   → Interface d'administration !
                          Cible prioritaire

Services découverts :
├── SIP sur 5060  → Système téléphonie IP
└── XMPP sur 5269 → Messagerie instantanée
```

---

### 🛠️ DNSENUM — Zone Transfer + Bruteforce

```bash
dnsenum --dnsserver 8.8.8.8 --enum example.com -f /usr/share/wordlists/dnsmap.txt
```

**Sortie réelle :**
```
dnsenum VERSION:1.2.6

-----   example.com   -----

Host's addresses:
__________________
example.com.                         3600    IN    A    93.184.216.34

Name Servers:
______________
ns1.example.com.                     3600    IN    A    93.184.216.100
ns2.example.com.                     3600    IN    A    93.184.216.101

Mail (MX) Servers:
___________________
mail.example.com.                    3600    IN    A    93.184.216.50

Trying Zone Transfers and getting Bind Versions:
_________________________________________________
Trying Zone Transfer for example.com on ns1.example.com ...

example.com.         3600    IN    SOA    ns1.example.com. hostmaster.example.com.
example.com.         3600    IN    NS     ns1.example.com.
example.com.         3600    IN    NS     ns2.example.com.
example.com.         3600    IN    MX     10 mail.example.com.
example.com.         3600    IN    A      93.184.216.34
www.example.com.     3600    IN    A      93.184.216.34
mail.example.com.    3600    IN    A      93.184.216.50
ftp.example.com.     3600    IN    A      93.184.216.60
dev.example.com.     3600    IN    A      93.184.216.70
staging.example.com. 3600    IN    A      93.184.216.75
internal.example.com.3600    IN    A      10.0.0.100
db.example.com.      3600    IN    A      10.0.0.200
vpn.example.com.     3600    IN    A      93.184.216.80

⚠️  Zone Transfer réussi ! Toute l'infrastructure exposée !

Brute forcing with /usr/share/wordlists/dnsmap.txt:
___________________________________________________
api.example.com.     3600    IN    A      93.184.216.85
beta.example.com.    3600    IN    A      93.184.216.86
test.example.com.    3600    IN    A      93.184.216.87
old.example.com.     3600    IN    A      93.184.216.88

example.com class C netranges:
________________________________
 93.184.216.0/24
 10.0.0.0/8

Performing reverse lookup on 93.184.216.0/24:
______________________________________________
34.216.184.93.in-addr.arpa.  600  IN  PTR  example.com.

Done.
```

---

## 📌 PARTIE 5 : ÉNUMÉRATION SMTP

### 🔵 Comprendre les commandes SMTP

**SMTP (Simple Mail Transfer Protocol)** sur port 25 supporte des commandes qui permettent de **vérifier l'existence d'utilisateurs** sans authentification sur les serveurs mal configurés.

```
Commandes SMTP d'énumération :
├── VRFY <user>   → Vérifie si un utilisateur existe
├── EXPN <list>   → Développe une liste de diffusion
└── RCPT TO:<user>→ Teste si l'adresse est valide
```

---

### 🛠️ NETCAT — Énumération SMTP manuelle

```bash
nc -nv 192.168.1.10 25
```

**Session complète :**
```
(UNKNOWN) [192.168.1.10] 25 (smtp) open
220 metasploitable.localdomain ESMTP Postfix (Ubuntu)

HELO attaquant.com
250 metasploitable.localdomain

VRFY root
252 2.0.0 root

VRFY msfadmin
252 2.0.0 msfadmin

VRFY administrateur
550 5.1.1 <administrateur>: Recipient address rejected: User unknown

VRFY jean.muamba
252 2.0.0 jean.muamba

EXPN developers
250-2.0.0 Jean Muamba <jean.muamba@corp.com>
250-2.0.0 Alice Dupont <alice.dupont@corp.com>
250 2.0.0 Bob Martin <bob.martin@corp.com>

QUIT
221 2.0.0 Bye
```

**Analyse :**
```
Utilisateurs confirmés via VRFY :
├── root        → Existe (code 252)
├── msfadmin    → Existe (code 252)
└── jean.muamba → Existe (code 252)

Utilisateurs inexistants :
└── administrateur → N'existe pas (code 550)

Liste de diffusion "developers" exposée :
├── jean.muamba@corp.com
├── alice.dupont@corp.com
└── bob.martin@corp.com

→ 3 nouveaux emails découverts via EXPN !
```

---

### 🛠️ SMTP-USER-ENUM — Automatisation

```bash
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt \
               -t 192.168.1.10
```

**Sortie réelle :**
```
Starting smtp-user-enum v1.2

Mode ........ VRFY
Worker Processes .. 5
Targets file ...... 1
Username file ..... /usr/share/wordlists/metasploit/unix_users.txt
Target count ...... 1
Username count .... 168
Target TCP port ... 25
Query timeout ..... 5 secs

######## Scan started at Fri Nov 15 16:00:12 2024 #########
192.168.1.10: root exists
192.168.1.10: bin exists
192.168.1.10: daemon exists
192.168.1.10: sys exists
192.168.1.10: sync exists
192.168.1.10: games exists
192.168.1.10: msfadmin exists
192.168.1.10: user exists
192.168.1.10: service exists
192.168.1.10: postgres exists
192.168.1.10: mysql exists
192.168.1.10: tomcat55 exists
######## Scan completed at Fri Nov 15 16:00:48 2024 #########
12 results.
168 queries in 36 seconds (4.7 queries/sec)
```

---

## 📌 PARTIE 6 : ÉNUMÉRATION NFS

### 🔵 Comprendre NFS

**NFS (Network File System)** permet le **partage de répertoires** entre systèmes Unix/Linux sur le réseau. Port 2049 TCP/UDP.

Un serveur NFS mal configuré peut permettre de **monter des partages sans authentification**.

---

### 🛠️ SHOWMOUNT — Lister les exports NFS

```bash
showmount -e 192.168.1.10
```

**Sortie réelle :**
```
Export list for 192.168.1.10:
/                      *
/home                  *
/etc                   *
/var/www               192.168.1.0/24
/opt/backups           10.0.0.0/8
```

**Analyse :**
```
🔴 CRITIQUE — Partages NFS exposés :

/          * → Répertoire RACINE accessible par tout le monde !
/home      * → Tous les répertoires home des utilisateurs
/etc       * → Fichiers de configuration système (shadow !)
/var/www   → Site web (code source lisible)
/opt/backups → Sauvegardes (données sensibles !)
```

---

### 🛠️ MOUNT — Monter un partage NFS

```bash
# Créer un point de montage
mkdir /tmp/nfs_mount

# Monter le partage
sudo mount -t nfs 192.168.1.10:/ /tmp/nfs_mount -o nolock

# Explorer le contenu
ls -la /tmp/nfs_mount/
```

**Sortie :**
```
total 92
drwxr-xr-x  21 root root  4096 May 20  2012 .
drwxr-xr-x  21 root root  4096 May 20  2012 ..
drwxr-xr-x   2 root root  4096 May 20  2012 bin
drwxr-xr-x   4 root root  1024 May 14  2012 boot
drwxr-xr-x  13 root root  3880 Nov 15 09:12 dev
drwxr-xr-x  94 root root  4096 Nov 15 09:15 etc
drwxr-xr-x   6 root root  4096 May 14  2012 home
drwxr-xr-x  14 root root  4096 May 14  2012 lib
drwx------   2 root root 16384 Apr 28  2010 lost+found
drwxr-xr-x   3 root root  4096 May 14  2012 media
drwxr-xr-x   4 root root  4096 Nov 15 09:12 proc
drwxr-xr-x  19 root root  4096 May 20  2012 var

# Lire le fichier shadow !
cat /tmp/nfs_mount/etc/shadow
```

**Sortie `/etc/shadow` :**
```
root:$1$SLBRi7.0$XTZv...:15525:0:99999:7:::
daemon:*:15141:0:99999:7:::
bin:*:15141:0:99999:7:::
msfadmin:$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZjA5/:14684:0:99999:7:::
user:$1$HESu9xrH$k.o3G93DGoXIiQKkPmUgZ0:14684:0:99999:7:::
postgres:$1$Rw35ik.x$MgX...::14684:0:99999:7:::
```

> **On a les hashes des mots de passe → John the Ripper ou Hashcat !**

---

## 📌 PARTIE 7 : ÉNUMÉRATION WINDOWS — NET COMMANDS

Sur une machine Windows compromise ou depuis un compte de domaine, les commandes **net** permettent une énumération complète.

---

### 🛠️ Commandes NET essentielles

```cmd
# Lister tous les utilisateurs locaux
net user
```

**Sortie :**
```
User accounts for \\WIN-SERVER01

-------------------------------------------------------------------------------
Administrateur           exploit4040              Guest
jean.muamba              alice.dupont             svc_backup
svc_sql                  svc_web

The command completed successfully.
```

---

```cmd
# Détails d'un utilisateur spécifique
net user Administrateur
```

**Sortie :**
```
User name                    Administrateur
Full Name
Comment                      Built-in account for admin
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/03/2024 08:45:12
Password expires             Never
Password changeable          10/03/2024 08:45:12
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   15/11/2024 09:12:44

Logon hours allowed          All

Local Group Memberships      *Administrateurs    *Utilisateurs
Global Group memberships     *Aucun

The command completed successfully.
```

---

```cmd
# Lister les groupes locaux
net localgroup
```

**Sortie :**
```
Aliases for \\WIN-SERVER01

-------------------------------------------------------------------------------
*Administrateurs
*Duplicateurs
*Invités
*Opérateurs de chiffrement
*Opérateurs de configuration réseau
*Utilisateurs
*Utilisateurs de bureau à distance
*Utilisateurs du journal de performances
*Utilisateurs du moniteur de performances

The command completed successfully.
```

---

```cmd
# Membres d'un groupe
net localgroup Administrateurs
```

**Sortie :**
```
Alias name     Administrateurs
Comment        Les administrateurs ont un accès complet et illimité

Members

-------------------------------------------------------------------------------
Administrateur
jean.muamba
exploit4040

The command completed successfully.
```

---

```cmd
# Lister les partages réseau
net share
```

**Sortie :**
```
Share name   Resource                        Remark

-------------------------------------------------------------------------------
C$           C:\                             Default share
IPC$                                         Remote IPC
ADMIN$       C:\Windows                      Remote Admin
Backups      C:\Backups\Entreprise           Sauvegardes serveurs
WebApp       C:\inetpub\wwwroot             Site web interne
HR_Data      C:\Data\RH                      CONFIDENTIEL RH

The command completed successfully.
```

> **`HR_Data` marqué CONFIDENTIEL → cible prioritaire pour l'exfiltration**

---

```cmd
# Informations sur le domaine
net view /domain
```

**Sortie :**
```
Domain

-------------------------------------------------------------------------------
CORP
WORKGROUP

The command completed successfully.
```

---

```cmd
# Tous les serveurs du domaine
net view /domain:CORP
```

**Sortie :**
```
Server Name            Remark
-------------------------------------------------------------------------------
\\DC01                 Contrôleur de domaine principal
\\WIN-SERVER01         Serveur de fichiers
\\WEB-SERVER           Serveur web interne
\\DB-SERVER            Serveur base de données
\\BACKUP-SERVER        Serveur de sauvegarde

The command completed successfully.
```

---

## 📌 PARTIE 8 : ÉNUMÉRATION LINUX

Sur un système Linux compromis, voici l'**énumération complète post-accès**.

---

### 🛠️ Commandes d'énumération Linux

```bash
# Qui suis-je ?
id && whoami
```

**Sortie :**
```
uid=1000(msfadmin) gid=1000(msfadmin) groups=1000(msfadmin),
4(adm),20(dialout),24(cdrom),25(floppy),29(audio),30(dip),
44(video),46(plugdev),110(netdev),111(lpadmin),112(admin),
113(sambashare)

msfadmin
```

> **Membre du groupe `admin` → sudo potentiellement disponible !**

---

```bash
# Tous les utilisateurs du système
cat /etc/passwd
```

**Sortie réelle :**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
msfadmin:x:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
user:x:1001:1001:just a user,,,:/home/user:/bin/bash
service:x:1002:1002:,,,:/home/service:/bin/bash
postgres:x:108:117:PostgreSQL admin,,,:/var/lib/postgresql:/bin/bash
mysql:x:109:117:MySQL Server,,,:/var/lib/mysql:/bin/false
tomcat55:x:110:65534::/usr/share/tomcat5.5:/bin/false
```

---

```bash
# Groupes du système
cat /etc/group
```

**Sortie (extrait) :**
```
root:x:0:
adm:x:4:msfadmin
sudo:x:27:msfadmin
admin:x:112:msfadmin,user
sambashare:x:113:msfadmin
```

---

```bash
# Vérifier les privilèges sudo
sudo -l
```

**Sortie :**
```
Matching Defaults entries for msfadmin on this host:
    env_reset, mail_badpass

User msfadmin may run the following commands on this host:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /usr/bin/find
    (ALL) NOPASSWD: /usr/bin/python
    (ALL) NOPASSWD: /bin/bash
```

> **`(ALL) NOPASSWD: /bin/bash` → Escalade de privilèges immédiate !**
> `sudo bash` → root sans mot de passe

---

```bash
# Processus en cours d'exécution
ps aux
```

**Sortie (extrait) :**
```
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1   2844  1788 ?        Ss   09:12   0:01 /sbin/init
root       588  0.0  0.5  17904  5432 ?        Ss   09:12   0:00 /usr/sbin/apache2
www-data   602  0.0  0.3  17904  3456 ?        S    09:12   0:00 /usr/sbin/apache2
www-data   603  0.0  0.3  17904  3456 ?        S    09:12   0:00 /usr/sbin/apache2
root       614  0.0  0.1   5432  1234 ?        Ss   09:12   0:00 /usr/sbin/vsftpd
root       621  0.0  1.2  45678 12345 ?        Ss   09:12   0:00 /usr/sbin/mysqld
postgres   634  0.0  0.8  34567  8765 ?        S    09:12   0:00 /usr/bin/postgres
root       645  0.0  0.2  12345  2345 ?        Ss   09:12   0:00 /usr/sbin/named
root       658  0.0  0.4  23456  4567 ?        Ss   09:12   0:00 /usr/sbin/smbd
```

---

```bash
# Connexions réseau actives
netstat -tulnp
```

**Sortie :**
```
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address    Foreign Address   State    PID/Program
tcp        0      0 0.0.0.0:21      0.0.0.0:*         LISTEN   614/vsftpd
tcp        0      0 0.0.0.0:22      0.0.0.0:*         LISTEN   602/sshd
tcp        0      0 0.0.0.0:23      0.0.0.0:*         LISTEN   589/telnetd
tcp        0      0 0.0.0.0:25      0.0.0.0:*         LISTEN   671/master
tcp        0      0 0.0.0.0:80      0.0.0.0:*         LISTEN   588/apache2
tcp        0      0 0.0.0.0:139     0.0.0.0:*         LISTEN   658/smbd
tcp        0      0 0.0.0.0:445     0.0.0.0:*         LISTEN   658/smbd
tcp        0      0 0.0.0.0:3306    0.0.0.0:*         LISTEN   621/mysqld
tcp        0      0 0.0.0.0:5432    0.0.0.0:*         LISTEN   634/postgres
tcp        0      0 0.0.0.0:5900    0.0.0.0:*         LISTEN   756/Xtightvnc
tcp        0      0 192.168.1.10:22 192.168.1.50:48123 ESTABLISHED 812/sshd
udp        0      0 0.0.0.0:53      0.0.0.0:*                  645/named
udp        0      0 0.0.0.0:161     0.0.0.0:*                  523/snmpd
```

---

## 📌 PARTIE 9 : WORKFLOW COMPLET D'ÉNUMÉRATION PROFESSIONNEL

```bash
# ═══════════════════════════════════════════════════════
# PHASE 1 : ÉNUMÉRATION NETBIOS/SMB
# ═══════════════════════════════════════════════════════
nbtscan 192.168.1.0/24 > recon/netbios_scan.txt
enum4linux -a 192.168.1.10 > recon/smb_enum.txt
smbmap -H 192.168.1.10 > recon/smb_shares.txt
smbclient -L //192.168.1.10 -N > recon/smb_list.txt

# ═══════════════════════════════════════════════════════
# PHASE 2 : ÉNUMÉRATION SNMP
# ═══════════════════════════════════════════════════════
snmpwalk -c public -v1 192.168.1.10 > recon/snmp_walk.txt
snmp-check 192.168.1.10 -c public > recon/snmp_check.txt

# Bruteforce community string
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 192.168.1.10

# ═══════════════════════════════════════════════════════
# PHASE 3 : ÉNUMÉRATION DNS
# ═══════════════════════════════════════════════════════
dnsrecon -d target.com -t std > recon/dns_std.txt
dnsrecon -d target.com -t axfr > recon/dns_axfr.txt
dnsenum target.com > recon/dns_enum.txt

# ═══════════════════════════════════════════════════════
# PHASE 4 : ÉNUMÉRATION SMTP
# ═══════════════════════════════════════════════════════
smtp-user-enum -M VRFY \
    -U /usr/share/wordlists/metasploit/unix_users.txt \
    -t 192.168.1.10 > recon/smtp_users.txt

# ═══════════════════════════════════════════════════════
# PHASE 5 : ÉNUMÉRATION NFS
# ═══════════════════════════════════════════════════════
showmount -e 192.168.1.10 > recon/nfs_exports.txt

# ═══════════════════════════════════════════════════════
# PHASE 6 : RAPPORT CONSOLIDÉ
# ═══════════════════════════════════════════════════════
echo "=== UTILISATEURS DÉCOUVERTS ===" > rapport_enum.txt
cat recon/smb_enum.txt | grep "Account:" >> rapport_enum.txt
cat recon/smtp_users.txt | grep "exists" >> rapport_enum.txt

echo "=== PARTAGES ACCESSIBLES ===" >> rapport_enum.txt
cat recon/smb_shares.txt | grep "READ\|WRITE" >> rapport_enum.txt
cat recon/nfs_exports.txt >> rapport_enum.txt

echo "=== VULNÉRABILITÉS IMMÉDIATES ===" >> rapport_enum.txt
```

---

## 📌 RÉSUMÉ FINAL — CE QUE L'EXAMEN VA TESTER

```
✅ Suffixes NetBIOS <00>, <20>, <1B>, <1C>, <1D> et leur signification
✅ NULL session SMB — ce que c'est et pourquoi c'est dangereux
✅ enum4linux — ce qu'il énumère (users, shares, password policy)
✅ Community strings SNMP — public/private et versions SNMPv1/v2c/v3
✅ OIDs SNMP importants — sysDescr, sysName, processus
✅ LDAP — structure DN/OU/CN et requêtes ldapsearch
✅ VRFY vs EXPN vs RCPT TO — différences et usage SMTP
✅ Zone Transfer AXFR — pourquoi c'est critique
✅ showmount -e — exposer les partages NFS
✅ Net commands Windows — net user, net localgroup, net share
✅ Fichiers Linux sensibles — /etc/passwd, /etc/shadow, /etc/group
✅ sudo -l — identifier les escalades de privilèges
✅ netstat -tulnp — services en écoute
```

---

## 🧪 QUESTIONS TYPE EXAMEN CEH — MODULE 4

**Q1 :** Quel suffixe NetBIOS indique que le service de partage de fichiers (File Server) est actif ?
> **Réponse : `<20>` — UNIQUE**

**Q2 :** Une NULL session SMB permet à un attaquant de faire quoi sans authentification ?
> **Réponse : Énumérer les utilisateurs, groupes, partages et la politique de mot de passe**

**Q3 :** Quelle community string SNMP donne accès en lecture/écriture par défaut ?
> **Réponse : "private"**

**Q4 :** Quelle version de SNMP offre authentification ET chiffrement ?
> **Réponse : SNMPv3**

**Q5 :** Quelle commande SMTP permet de vérifier si un utilisateur existe ?
> **Réponse : VRFY**

**Q6 :** Quelle commande affiche les répertoires NFS exportés par un serveur ?
> **Réponse : `showmount -e <IP>`**

**Q7 :** Sur Linux, quel fichier contient les hashes des mots de passe des utilisateurs ?
> **Réponse : /etc/shadow**

**Q8 :** `sudo -l` retourne `(ALL) NOPASSWD: /bin/bash`. Que peut faire l'attaquant ?
> **Réponse : Exécuter `sudo bash` pour obtenir un shell root sans mot de passe**

**Q9 :** Quel outil Linux combine smbclient, rpcclient et nmblookup pour énumérer automatiquement SMB ?
> **Réponse : enum4linux**

**Q10 :** Dans un Distinguished Name LDAP `cn=Jean Muamba,ou=Users,dc=corp,dc=com`, que signifie `ou` ?
> **Réponse : Organizational Unit — unité organisationnelle (conteneur logique dans l'annuaire)**
