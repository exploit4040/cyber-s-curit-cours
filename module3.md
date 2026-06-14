# 🛡️ CEH v12 — MODULE 3 : SCANNING DE RÉSEAUX
### Guide pédagogique complet avec sorties d'outils | ML | exploit4040

---

## 📌 INTRODUCTION — POURQUOI LE SCANNING EST UNE SCIENCE

Si la reconnaissance c'est **observer la maison de loin**, le scanning c'est **s'approcher et tester chaque porte et fenêtre** méthodiquement.

Le scanning transforme les informations vagues de la phase 1 en **données concrètes et exploitables** : quels ports sont ouverts, quels services tournent, quel OS est utilisé, quelles vulnérabilités existent.

C'est la phase où tu construis la **carte d'attaque précise** de ta cible.

> **Règle professionnelle :** Un bon scanning discret et méthodique vaut mille fois mieux qu'un scan brutal et rapide qui déclenche toutes les alarmes.

---

## 📌 PARTIE 1 : RÉVISION RÉSEAU ESSENTIELLE

Avant de scanner, tu dois maîtriser les bases réseau. Le CEH les teste directement.

---

### 🔵 Le Modèle OSI — Les 7 Couches

```
┌─────────────────────────────────────────────────────────────┐
│  COUCHE  │  NOM           │  PROTOCOLES / EXEMPLES          │
├─────────────────────────────────────────────────────────────┤
│    7     │  Application   │  HTTP, HTTPS, FTP, SMTP, DNS    │
│    6     │  Présentation  │  SSL/TLS, JPEG, MP4, ASCII      │
│    5     │  Session       │  NetBIOS, RPC, PPTP             │
│    4     │  Transport     │  TCP, UDP                       │
│    3     │  Réseau        │  IP, ICMP, ARP, OSPF, BGP       │
│    2     │  Liaison       │  Ethernet, Wi-Fi, MAC, VLAN     │
│    1     │  Physique      │  Câbles, fibre, signaux radio   │
└─────────────────────────────────────────────────────────────┘

Mnémotechnique : "All People Seem To Need Data Processing"
```

---

### 🔵 TCP vs UDP — La distinction fondamentale

```
TCP (Transmission Control Protocol)
├── Orienté connexion (handshake 3 étapes obligatoire)
├── Fiable (accusés de réception, retransmission)
├── Ordonné (les paquets arrivent dans l'ordre)
├── Plus lent (overhead du contrôle)
└── Utilisé pour : HTTP, HTTPS, FTP, SSH, SMTP

UDP (User Datagram Protocol)
├── Sans connexion (fire and forget)
├── Non fiable (pas d'accusé de réception)
├── Non ordonné
├── Très rapide (pas d'overhead)
└── Utilisé pour : DNS, DHCP, SNMP, VoIP, Gaming
```

---

### 🔵 Le Handshake TCP en 3 étapes — CRITIQUE POUR LE CEH

C'est le fondement de TOUS les types de scans TCP. Tu dois le connaître parfaitement.

```
CLIENT                              SERVEUR
  │                                    │
  │──── SYN (seq=100) ────────────────>│  "Je veux me connecter"
  │                                    │
  │<─── SYN-ACK (seq=200, ack=101) ───│  "D'accord, je suis prêt"
  │                                    │
  │──── ACK (ack=201) ────────────────>│  "Connexion établie"
  │                                    │
  │         [CONNEXION ÉTABLIE]        │
  │                                    │
```

**Les flags TCP :**

```
┌──────────────────────────────────────────────────────┐
│  FLAG  │  NOM          │  RÔLE                       │
├──────────────────────────────────────────────────────┤
│  SYN   │  Synchronize  │  Initier une connexion      │
│  ACK   │  Acknowledge  │  Confirmer réception        │
│  FIN   │  Finish       │  Fermer proprement          │
│  RST   │  Reset        │  Réinitialiser (forcer)     │
│  PSH   │  Push         │  Envoyer immédiatement      │
│  URG   │  Urgent       │  Données prioritaires       │
│  ECE   │  ECN-Echo     │  Congestion réseau          │
│  CWR   │  Congestion   │  Fenêtre réduite            │
└──────────────────────────────────────────────────────┘
```

---

### 🔵 Les États des Ports

```
┌─────────────────────────────────────────────────────────────────┐
│  ÉTAT      │  SIGNIFICATION                                      │
├─────────────────────────────────────────────────────────────────┤
│  OPEN      │  Service actif, accepte les connexions             │
│  CLOSED    │  Port accessible mais aucun service n'écoute       │
│  FILTERED  │  Pare-feu bloque les paquets (pas de réponse)      │
│  UNFILTERED│  Accessible mais état ouvert/fermé inconnu         │
│  OPEN|FILTERED │  Impossible de distinguer (UDP souvent)        │
└─────────────────────────────────────────────────────────────────┘
```

---

### 🔵 Ports Importants à Connaître par Cœur

```
┌──────────────────────────────────────────────────────────────┐
│  PORT  │  PROTOCOLE  │  SERVICE                              │
├──────────────────────────────────────────────────────────────┤
│   20   │    TCP      │  FTP (données)                        │
│   21   │    TCP      │  FTP (contrôle)                       │
│   22   │    TCP      │  SSH                                  │
│   23   │    TCP      │  Telnet (non chiffré, dangereux)      │
│   25   │    TCP      │  SMTP (email sortant)                 │
│   53   │  TCP/UDP    │  DNS                                  │
│   67   │    UDP      │  DHCP Server                         │
│   68   │    UDP      │  DHCP Client                         │
│   80   │    TCP      │  HTTP                                 │
│  110   │    TCP      │  POP3 (email entrant)                │
│  111   │  TCP/UDP    │  RPC (Portmapper)                    │
│  123   │    UDP      │  NTP (synchronisation temps)         │
│  135   │    TCP      │  MSRPC (Windows)                     │
│  137   │    UDP      │  NetBIOS Name Service                │
│  138   │    UDP      │  NetBIOS Datagram                    │
│  139   │    TCP      │  NetBIOS Session (SMB)               │
│  143   │    TCP      │  IMAP (email)                        │
│  161   │    UDP      │  SNMP                                │
│  162   │    UDP      │  SNMP Trap                           │
│  389   │    TCP      │  LDAP                                │
│  443   │    TCP      │  HTTPS                               │
│  445   │    TCP      │  SMB (Windows File Sharing)          │
│  514   │    UDP      │  Syslog                              │
│  636   │    TCP      │  LDAPS (LDAP chiffré)                │
│  873   │    TCP      │  Rsync                               │
│ 1433   │    TCP      │  Microsoft SQL Server                │
│ 1521   │    TCP      │  Oracle Database                     │
│ 2049   │  TCP/UDP    │  NFS                                 │
│ 3306   │    TCP      │  MySQL / MariaDB                     │
│ 3389   │    TCP      │  RDP (Remote Desktop Windows)        │
│ 5432   │    TCP      │  PostgreSQL                          │
│ 5900   │    TCP      │  VNC                                 │
│ 6379   │    TCP      │  Redis                               │
│ 8080   │    TCP      │  HTTP alternatif / Proxy             │
│ 8443   │    TCP      │  HTTPS alternatif                    │
│ 27017  │    TCP      │  MongoDB                             │
└──────────────────────────────────────────────────────────────┘
```

---

## 📌 PARTIE 2 : NMAP — L'OUTIL ROI DU SCANNING

**Nmap (Network Mapper)** est l'outil de scanning le plus utilisé au monde. Il est open source, disponible sur toutes les plateformes, et fait référence dans tous les examens CEH.

**Installation :**
```bash
sudo apt install nmap       # Debian/Ubuntu/Kali
sudo yum install nmap       # CentOS/RHEL
```

---

## 🔴 TYPE 1 : PING SWEEP — Découverte d'hôtes actifs

Avant de scanner les ports, tu dois savoir **quelles machines sont actives** sur le réseau.

**Commande :**
```bash
nmap -sn 192.168.1.0/24
```

**Sortie réelle :**
```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-11-15 14:23 CAT
Nmap scan report for 192.168.1.1
Host is up (0.00042s latency).
MAC Address: C8:D7:19:AB:12:3F (Cisco Systems)

Nmap scan report for 192.168.1.10
Host is up (0.0023s latency).
MAC Address: 08:00:27:A1:BC:DE (Oracle VirtualBox)

Nmap scan report for 192.168.1.15
Host is up (0.0087s latency).
MAC Address: 00:50:56:C0:00:08 (VMware)

Nmap scan report for 192.168.1.20
Host is up (0.0012s latency).
MAC Address: 52:54:00:12:34:56 (QEMU Virtual NIC)

Nmap scan report for 192.168.1.100
Host is up (0.00089s latency).
MAC Address: B8:27:EB:A1:23:45 (Raspberry Pi Foundation)

Nmap done: 256 IP addresses (5 hosts up) scanned in 3.42 seconds
```

**Analyse professionnelle :**
```
Ce qu'on voit :
├── 192.168.1.1   → Routeur Cisco (passerelle)
├── 192.168.1.10  → Machine VirtualBox (VM de test ?)
├── 192.168.1.15  → Machine VMware (serveur virtuel ?)
├── 192.168.1.20  → Machine QEMU/KVM
└── 192.168.1.100 → Raspberry Pi (IoT ? serveur léger ?)

→ 5 cibles identifiées sur 256 adresses possibles
→ Adresses MAC révèlent les fabricants = info précieuse
```

---

## 🔴 TYPE 2 : SYN SCAN (-sS) — Le scan furtif standard

C'est le **scan par défaut de Nmap** quand on a les droits root. Aussi appelé **"Half-Open Scan"** ou **"Stealth Scan"**.

**Principe :**
```
Attaquant          Cible (port OUVERT)
    │──── SYN ────────────>│
    │<─── SYN-ACK ─────────│   Port ouvert détecté !
    │──── RST ────────────>│   On réinitialise sans finir la connexion
    
Attaquant          Cible (port FERMÉ)
    │──── SYN ────────────>│
    │<─── RST-ACK ─────────│   Port fermé détecté !

Attaquant          Cible (port FILTRÉ)
    │──── SYN ────────────>│
    │         [silence]    │   Pare-feu bloque = filtered
```

**Pourquoi "stealth" ?** La connexion TCP n'est jamais complétée → beaucoup de systèmes anciens ne loggent pas les connexions incomplètes.

**Commande :**
```bash
sudo nmap -sS 192.168.1.10
```

**Sortie réelle :**
```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-11-15 14:25 CAT
Nmap scan report for 192.168.1.10
Host is up (0.00089s latency).
Not shown: 977 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
23/tcp   open  telnet
25/tcp   open  smtp
53/tcp   open  domain
80/tcp   open  http
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
512/tcp  open  exec
513/tcp  open  login
514/tcp  open  shell
1099/tcp open  rmiregistry
1524/tcp open  ingreslock
2049/tcp open  nfs
2121/tcp open  ccproxy-ftp
3306/tcp open  mysql
5432/tcp open  postgresql
5900/tcp open  vnc
6000/tcp open  X11
6667/tcp open  irc
8009/tcp open  ajp13
8180/tcp open  unknown
MAC Address: 08:00:27:A1:BC:DE (Oracle VirtualBox)

Nmap done: 1 IP address (1 host up) scanned in 2.89 seconds
```

**Analyse professionnelle :**
```
⚠️  ALERTE HAUTE VALEUR - Machine extrêmement vulnérable !

Ports critiques détectés :
├── 21  (FTP)       → vsftpd potentiel ? Credentials par défaut ?
├── 22  (SSH)       → Bruteforce possible
├── 23  (Telnet)    → ⛔ Cleartext ! Sniffing possible
├── 3306 (MySQL)    → Base de données exposée !
├── 5432 (PostgreSQL)→ Base de données exposée !
├── 5900 (VNC)      → Accès bureau à distance !
├── 445 (SMB)       → EternalBlue ? MS17-010 ?
├── 8180 (Tomcat?)  → Interface admin web ?
└── 1524 (ingreslock)→ Backdoor connue sur Metasploitable !

Verdict : Ceci ressemble à Metasploitable 2 - machine de test délibérément vulnérable
```

---

## 🔴 TYPE 3 : CONNECT SCAN (-sT) — Scan TCP complet

Effectue un **handshake TCP complet**. Utilisable sans droits root mais plus détectable.

**Principe :**
```
Attaquant          Cible (port OUVERT)
    │──── SYN ────────────>│
    │<─── SYN-ACK ─────────│
    │──── ACK ────────────>│   Connexion complète établie
    │──── RST ────────────>│   Puis fermeture immédiate
```

**Commande :**
```bash
nmap -sT 192.168.1.10
```

**Sortie réelle :**
```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-11-15 14:28 CAT
Nmap scan report for 192.168.1.10
Host is up (0.00091s latency).
Not shown: 977 closed tcp ports (conn-refused)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
23/tcp   open  telnet
80/tcp   open  http
3306/tcp open  mysql
5432/tcp open  postgresql
5900/tcp open  vnc
8180/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 1.23 seconds
```

> **Différence clé SYN vs Connect :**
> `-sS` = root requis, plus furtif, plus rapide
> `-sT` = sans root, connexion complète loggée, plus lent

---

## 🔴 TYPE 4 : UDP SCAN (-sU)

Les services UDP ne répondent pas de la même façon que TCP. C'est pourquoi le scan UDP est **lent et délicat**.

**Principe :**
```
Port UDP OUVERT   → Réponse UDP ou pas de réponse
Port UDP FERMÉ    → ICMP "Port Unreachable" reçu
Port UDP FILTRÉ   → Pas de réponse (filtré par pare-feu)
```

**Commande :**
```bash
sudo nmap -sU 192.168.1.10
```

**Sortie réelle :**
```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-11-15 14:31 CAT
Nmap scan report for 192.168.1.10
Host is up (0.00089s latency).
Not shown: 957 closed udp ports (port-unreach)
PORT      STATE         SERVICE
53/udp    open          domain
67/udp    open|filtered dhcps
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
111/udp   open          rpcbind
123/udp   open          ntp
137/udp   open          netbios-ns
138/udp   open|filtered netbios-dgm
161/udp   open          snmp
2049/udp  open          nfs

Nmap done: 1 IP address (1 host up) scanned in 1083.47 seconds
```

**Analyse :**
```
Observations importantes :
├── 53/udp  (DNS)  → Serveur DNS actif, zone transfer possible
├── 161/udp (SNMP) → Community string "public" ? Enumération !
├── 137/udp (NetBIOS) → Enumération NetBIOS possible
└── 2049/udp (NFS) → Partages NFS montables ?

⚠️ Le scan a pris 1083 secondes (18 minutes) 
   → UDP scanning = LENT par nature
```

---

## 🔴 TYPE 5 : FIN SCAN (-sF)

Envoie un paquet avec **uniquement le flag FIN** activé. Aucun flag SYN.

**Principe (basé sur RFC 793) :**
```
Port FERMÉ  → Répond RST (comportement normal RFC)
Port OUVERT → Ignore le paquet (pas de réponse)
Port FILTRÉ → Pas de réponse (pare-feu)
```

**Commande :**
```bash
sudo nmap -sF 192.168.1.10
```

**Sortie réelle :**
```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-11-15 14:52 CAT
Nmap scan report for 192.168.1.10
Host is up (0.00041s latency).
Not shown: 977 closed tcp ports (reset)
PORT     STATE         SERVICE
21/tcp   open|filtered ftp
22/tcp   open|filtered ssh
23/tcp   open|filtered telnet
80/tcp   open|filtered http
3306/tcp open|filtered mysql

Nmap done: 1 IP address (1 host up) scanned in 1.73 seconds
```

> **Limitation :** Windows répond RST sur tous les ports (ouverts et fermés) → FIN scan inefficace contre Windows. Très efficace contre Linux/Unix.

---

## 🔴 TYPE 6 : XMAS SCAN (-sX)

Envoie un paquet avec **FIN + PSH + URG** activés simultanément. Appelé "Christmas" car le paquet est "illuminé comme un sapin de Noël".

**Commande :**
```bash
sudo nmap -sX 192.168.1.10
```

**Sortie réelle :**
```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-11-15 14:55 CAT
Nmap scan report for 192.168.1.10
Host is up (0.00043s latency).
Not shown: 977 closed tcp ports (reset)
PORT     STATE         SERVICE
21/tcp   open|filtered ftp
22/tcp   open|filtered ssh
23/tcp   open|filtered telnet
25/tcp   open|filtered smtp
80/tcp   open|filtered http
3306/tcp open|filtered mysql
5432/tcp open|filtered postgresql
5900/tcp open|filtered vnc

Nmap done: 1 IP address (1 host up) scanned in 1.81 seconds
```

---

## 🔴 TYPE 7 : NULL SCAN (-sN)

Envoie un paquet avec **aucun flag TCP** activé.

**Commande :**
```bash
sudo nmap -sN 192.168.1.10
```

**Sortie réelle :**
```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-11-15 14:57 CAT
Nmap scan report for 192.168.1.10
Host is up (0.00044s latency).
Not shown: 977 closed tcp ports (reset)
PORT     STATE         SERVICE
21/tcp   open|filtered ftp
22/tcp   open|filtered ssh
23/tcp   open|filtered telnet
80/tcp   open|filtered http
3306/tcp open|filtered mysql

Nmap done: 1 IP address (1 host up) scanned in 1.69 seconds
```

---

## 🔴 TYPE 8 : ACK SCAN (-sA) — Cartographier le pare-feu

Ce scan n'est **pas conçu pour trouver des ports ouverts**. Il sert à **cartographier les règles du pare-feu** et identifier les ports filtrés vs non-filtrés.

**Principe :**
```
Attaquant               Cible
    │──── ACK ─────────────>│
    │                       │
    │<─── RST ──────────────│  → Port UNFILTERED (pas de firewall ici)
    │         [silence]     │  → Port FILTERED (firewall bloque)
```

**Commande :**
```bash
sudo nmap -sA 192.168.1.10
```

**Sortie réelle :**
```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-11-15 15:01 CAT
Nmap scan report for 192.168.1.10
Host is up (0.00041s latency).
Not shown: 987 unfiltered tcp ports (reset)
PORT     STATE    SERVICE
22/tcp   filtered ssh
80/tcp   filtered http
443/tcp  filtered https
3306/tcp filtered mysql
8080/tcp filtered http-proxy

Nmap done: 1 IP address (1 host up) scanned in 2.14 seconds
```

**Analyse :**
```
Les ports "filtered" = pare-feu actif sur ces ports
Les ports "unfiltered" = pas de pare-feu sur ces ports

→ Utile pour comprendre la configuration du pare-feu
→ Guide le choix des techniques d'évasion
```

---

## 🔴 TYPE 9 : VERSION DETECTION (-sV) — Identifier les services

Ce scan tente de déterminer la **version exacte** du service qui tourne sur chaque port ouvert.

**Commande :**
```bash
nmap -sV 192.168.1.10
```

**Sortie réelle :**
```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-11-15 15:05 CAT
Nmap scan report for 192.168.1.10
Host is up (0.00089s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet      Linux telnetd
25/tcp   open  smtp        Postfix smtpd
53/tcp   open  domain      ISC BIND 9.4.2
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
5900/tcp open  vnc         VNC (protocol 3.3)
8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1

Service Info: Host: metasploitable; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 13.47 seconds
```

**Analyse professionnelle — C'est de l'or pur :**
```
Vulnérabilités immédiates identifiées :

🔴 vsftpd 2.3.4        → CVE-2011-2523 : BACKDOOR ! 
                          Port 6200 s'ouvre après smiley :) dans username
                          
🔴 OpenSSH 4.7p1       → Version très ancienne, multiples CVEs
                          Debian 2008 → Système non patché depuis 2008 !
                          
🔴 Apache 2.2.8         → Multiple CVEs critiques disponibles
                          
🔴 Samba 3.0.20         → CVE-2007-2447 : username map script RCE !
                          
🔴 MySQL 5.0.51a        → Authentification bypass possible
                          
🔴 VNC Protocol 3.3     → Pas d'auth ou auth faible ?
                          
🔴 Tomcat 1.1           → Interface admin /manager sur port 8180 ?

→ Rapport de version = liste de courses pour l'exploitation
```

---

## 🔴 TYPE 10 : OS FINGERPRINTING (-O) — Identifier l'OS

Nmap envoie des paquets spécialement forgés et analyse les réponses pour **deviner le système d'exploitation**.

**Commande :**
```bash
sudo nmap -O 192.168.1.10
```

**Sortie réelle :**
```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-11-15 15:10 CAT
Nmap scan report for 192.168.1.10
Host is up (0.00090s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.33
Network Distance: 1 hop

OS detection performed. Please report any incorrect results.
Nmap done: 1 IP address (1 host up) scanned in 4.58 seconds
```

---

## 🔴 SCAN COMPLET PROFESSIONNEL (-A) — Le scan tout-en-un

Le flag `-A` combine : OS detection + Version detection + Script scanning + Traceroute.

**Commande :**
```bash
sudo nmap -A -T4 192.168.1.10
```

**Sortie réelle (extrait) :**
```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-11-15 15:15 CAT
Nmap scan report for 192.168.1.10
Host is up (0.00089s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 192.168.1.5
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|_End of status

22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)

23/tcp   open  telnet      Linux telnetd

80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
| http-methods:
|   Supported Methods: GET HEAD POST OPTIONS
|   Potentially risky methods: TRACE
|_  See: https://nmap.org/nsedoc/scripts/http-methods.html
|_http-server-header: Apache/2.2.8 (Ubuntu) DAV/2
|_http-title: Metasploitable2 - Linux

3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
| mysql-info:
|   Protocol: 10
|   Version: 5.0.51a-3ubuntu5
|   Thread ID: 8
|   Capabilities flags: 43564
|   Some Capabilities: Support41Auth, SupportsTransactions
|   Status: Autocommit
|_  Salt: {mK_&r!Ae7Vy,9JXa5^3

5900/tcp open  vnc         VNC (protocol 3.3)
| vnc-info:
|   Protocol version: 3.3
|   Security types:
|_    VNC Authentication (2)

OS details: Linux 2.6.9 - 2.6.33

TRACEROUTE
HOP RTT     ADDRESS
1   0.90 ms 192.168.1.10

Nmap done: 1 IP address (1 host up) scanned in 43.27 seconds
```

---

## 📌 PARTIE 3 : NSE — NMAP SCRIPTING ENGINE

Le **NSE** est l'un des aspects les plus puissants de Nmap. Il permet d'exécuter des **scripts automatisés** pour des tâches spécifiques.

Les scripts sont classés en catégories :

```
┌────────────────────────────────────────────────────────────┐
│  CATÉGORIE   │  UTILISATION                                │
├────────────────────────────────────────────────────────────┤
│  auth        │  Tester des credentials par défaut         │
│  broadcast   │  Découverte réseau broadcast               │
│  brute       │  Bruteforce de services                    │
│  default     │  Scripts standards (-sC)                   │
│  discovery   │  Collecte d'informations                   │
│  dos         │  Tests de déni de service (prudence !)     │
│  exploit     │  Exploitation de vulnérabilités            │
│  external    │  Requêtes vers services externes           │
│  fuzzer      │  Fuzzing de protocoles                     │
│  intrusive   │  Scripts intrusifs (bruyants)              │
│  malware     │  Détecter des backdoors/malwares           │
│  safe        │  Scripts non dangereux                     │
│  version     │  Détection de version                      │
│  vuln        │  Scan de vulnérabilités                    │
└────────────────────────────────────────────────────────────┘
```

---

### 🛠️ SCRIPTS NSE ESSENTIELS AVEC SORTIES

#### Script de détection SMB (MS17-010 / EternalBlue)
```bash
nmap --script smb-vuln-ms17-010 -p 445 192.168.1.10
```

**Sortie :**
```
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.1.10

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists
|       in Microsoft SMBv1 server (ms17-010)
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

Nmap done: 1 IP address (1 host up) scanned in 4.32 seconds
```

---

#### Script de détection backdoor vsftpd
```bash
nmap --script ftp-vsftpd-backdoor -p 21 192.168.1.10
```

**Sortie :**
```
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.1.10

PORT   STATE SERVICE
21/tcp open  ftp

Host script results:
| ftp-vsftpd-backdoor:
|   VULNERABLE:
|   vsFTPd version 2.3.4 backdoor
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2011-2523
|     Risk factor: HIGH
|       vsFTPd version 2.3.4 backdoor, this was
|       reported on 2011-07-04.
|     Exploit results:
|       Shell command: id
|       Results: uid=0(root) gid=0(root)
|     Disclosure date: 2011-07-03
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523
|_      https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb

Nmap done: 1 IP address (1 host up) scanned in 6.78 seconds
```

---

#### Scan complet de vulnérabilités
```bash
nmap --script vuln 192.168.1.10
```

**Sortie (extrait) :**
```
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.1.10

PORT     STATE SERVICE
21/tcp   open  ftp
| ftp-vsftpd-backdoor:
|   VULNERABLE: CVE-2011-2523 (CRITICAL)

80/tcp   open  http
| http-csrf:
|   Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.1.10
|   Found the following possible CSRF vulnerabilities:
|     Path: http://192.168.1.10/phpMyAdmin/
|     Form id: login_form
|     Form action: index.php
| http-sql-injection:
|   Possible sqli for queries:
|     http://192.168.1.10/dvwa/vulnerabilities/sqli/?id=1%27&Submit=Submit
| http-stored-xss:
|   VULNERABLE to Stored XSS:
|     http://192.168.1.10/dvwa/vulnerabilities/xss_s/

445/tcp  open  microsoft-ds
| smb-vuln-ms17-010:
|   VULNERABLE: MS17-010 EternalBlue (CRITICAL)

3306/tcp open  mysql
| mysql-empty-password:
|   VULNERABLE:
|   MySQL is accessible with empty password for user 'root'
|     Risk: HIGH

Nmap done: 1 IP address (1 host up) scanned in 128.43 seconds
```

---

#### Scripts HTTP utiles
```bash
# Enumérer les méthodes HTTP
nmap --script http-methods -p 80,443 192.168.1.10

# Trouver des répertoires cachés
nmap --script http-enum -p 80 192.168.1.10
```

**Sortie http-enum :**
```
PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /phpMyAdmin/: phpMyAdmin
|   /dvwa/: DVWA v1.0.7
|   /admin/: Possible admin folder
|   /backup/: Possible backup folder
|   /test/: Test page
|   /robots.txt: Robots file
|   /cgi-bin/: Potentially interesting directory w/ listing
|   /icons/: Potentially interesting folder w/ directory listing
|_  /index.php: Drupal possible admin page
```

---

## 📌 PARTIE 4 : MASSCAN — SCANNING ULTRA-RAPIDE

**Masscan** peut scanner **l'internet entier en 6 minutes**. Il est beaucoup plus rapide que Nmap mais moins précis. Utilisé pour des scans de grande envergure.

**Commande :**
```bash
sudo masscan 192.168.1.0/24 -p1-65535 --rate=1000
```

**Sortie réelle :**
```
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2024-11-15 15:30:00 GMT
Initiating SYN Stealth Scan
Scanning 256 hosts [65535 ports/host]

Discovered open port 22/tcp on 192.168.1.10
Discovered open port 80/tcp on 192.168.1.10
Discovered open port 21/tcp on 192.168.1.10
Discovered open port 3306/tcp on 192.168.1.10
Discovered open port 445/tcp on 192.168.1.10
Discovered open port 5432/tcp on 192.168.1.10
Discovered open port 5900/tcp on 192.168.1.10
Discovered open port 8180/tcp on 192.168.1.10
Discovered open port 80/tcp on 192.168.1.1
Discovered open port 443/tcp on 192.168.1.1

Rate: 998.23 kpps
```

**Workflow professionnel Masscan + Nmap :**
```bash
# Étape 1 : Scan rapide avec Masscan
sudo masscan 192.168.1.0/24 -p1-65535 --rate=1000 -oG masscan_results.txt

# Étape 2 : Extraire les IPs actives
grep "open" masscan_results.txt | cut -d " " -f4 | sort -u > live_hosts.txt

# Étape 3 : Scan approfondi Nmap sur les cibles trouvées
nmap -sV -sC -O -iL live_hosts.txt -oA rapport_final
```

---

## 📌 PARTIE 5 : HPING3 — FORGEUR DE PAQUETS

**Hping3** est un outil de **forge de paquets** qui permet de créer des paquets TCP/UDP/ICMP personnalisés. Très utilisé pour tester les pare-feux et effectuer des DoS.

---

### Ping ICMP classique
```bash
hping3 -1 192.168.1.10
```

**Sortie :**
```
HPING 192.168.1.10 (eth0 192.168.1.10): icmp mode set, 28 headers + 0 data bytes
len=28 ip=192.168.1.10 ttl=64 id=42341 icmp_seq=0 rtt=0.7 ms
len=28 ip=192.168.1.10 ttl=64 id=42342 icmp_seq=1 rtt=0.5 ms
len=28 ip=192.168.1.10 ttl=64 id=42343 icmp_seq=2 rtt=0.6 ms

--- 192.168.1.10 hping statistic ---
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 0.5/0.6/0.7 ms
```

---

### SYN scan manuel sur port 80
```bash
hping3 -S -p 80 192.168.1.10
```

**Sortie :**
```
HPING 192.168.1.10 (eth0 192.168.1.10): S set, 40 headers + 0 data bytes
len=46 ip=192.168.1.10 ttl=64 id=0 sport=80 flags=SA seq=0 win=5840 rtt=0.9 ms
len=46 ip=192.168.1.10 ttl=64 id=0 sport=80 flags=SA seq=1 win=5840 rtt=0.8 ms

--- 192.168.1.10 hping statistic ---
2 packets transmitted, 2 packets received, 0% packet loss
```

> **flags=SA** = SYN-ACK reçu → Port **80 ouvert** confirmé

---

### Firewall walking (ACK scan)
```bash
hping3 -A -p 80 192.168.1.10 --count 3
```

**Sortie :**
```
HPING 192.168.1.10 (eth0 192.168.1.10): A set, 40 headers + 0 data bytes
len=46 ip=192.168.1.10 ttl=64 id=0 sport=80 flags=R seq=0 win=0 rtt=1.1 ms
len=46 ip=192.168.1.10 ttl=64 id=0 sport=80 flags=R seq=1 win=0 rtt=0.9 ms

--- 192.168.1.10 hping statistic ---
3 packets transmitted, 3 packets received, 0% packet loss
```

> **flags=R** = RST reçu → Port non filtré par pare-feu

---

### SYN Flood (simulation DoS — TEST LAB UNIQUEMENT)
```bash
sudo hping3 --flood -S -p 80 192.168.1.10
```

**Sortie :**
```
HPING 192.168.1.10 (eth0 192.168.1.10): S set, 40 headers + 0 data bytes
hping in flood mode, no replies will be shown

--- 192.168.1.10 hping statistic ---
128473 packets transmitted, 0 packets received, 100% packet loss
round-trip min/avg/max = 0.0/0.0/0.0 ms
```

---

## 📌 PARTIE 6 : NETCAT — LE COUTEAU SUISSE DU RÉSEAU

**Netcat** (nc) est appelé "le couteau suisse du réseau". Il peut créer des connexions TCP/UDP, écouter sur des ports, transférer des fichiers, créer des backdoors simples.

---

### Banner Grabbing — Identifier un service manuellement
```bash
nc -nv 192.168.1.10 21
```

**Sortie :**
```
(UNKNOWN) [192.168.1.10] 21 (ftp) open
220 (vsFTPd 2.3.4)
```

> La bannière révèle immédiatement **vsftpd 2.3.4** → backdoor connue !

---

```bash
nc -nv 192.168.1.10 22
```

**Sortie :**
```
(UNKNOWN) [192.168.1.10] 22 (ssh) open
SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
```

---

```bash
nc -nv 192.168.1.10 80
# Puis taper manuellement :
HEAD / HTTP/1.0
[Entrée deux fois]
```

**Sortie :**
```
(UNKNOWN) [192.168.1.10] 80 (http) open
HTTP/1.1 200 OK
Date: Fri, 15 Nov 2024 14:00:00 GMT
Server: Apache/2.2.8 (Ubuntu) DAV/2
X-Powered-By: PHP/5.2.4-2ubuntu5.10
Content-Type: text/html
```

> **Server: Apache/2.2.8** + **PHP/5.2.4** → Deux versions obsolètes avec des CVEs critiques

---

### Netcat en mode écoute (listener)
```bash
# Machine A (attaquant) - écoute sur port 4444
nc -lvnp 4444

# Machine B (cible) - se connecte
nc 192.168.1.5 4444
```

**Sortie sur l'attaquant :**
```
listening on [any] 4444 ...
connect to [192.168.1.5] from (UNKNOWN) [192.168.1.10] 52341
```

---

## 📌 PARTIE 7 : LES OPTIONS NMAP AVANCÉES

---

### Spécifier les ports à scanner
```bash
# Ports spécifiques
nmap -p 22,80,443,3306 192.168.1.10

# Plage de ports
nmap -p 1-1024 192.168.1.10

# Tous les ports (1-65535)
nmap -p- 192.168.1.10

# Top 100 ports les plus courants
nmap --top-ports 100 192.168.1.10

# Top 1000 ports (défaut Nmap)
nmap 192.168.1.10
```

**Sortie `-p 22,80,443,3306 192.168.1.10` :**
```
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
443/tcp  closed https
3306/tcp open   mysql
```

---

### Contrôle du timing (-T)

```
┌──────────────────────────────────────────────────────┐
│  NIVEAU  │  NOM       │  VITESSE   │  USAGE          │
├──────────────────────────────────────────────────────┤
│   -T0    │  Paranoid  │  Très lent │  IDS ultra-furtif│
│   -T1    │  Sneaky    │  Lent      │  Évasion IDS     │
│   -T2    │  Polite    │  Modéré    │  Peu de bande    │
│   -T3    │  Normal    │  Normal    │  Par défaut      │
│   -T4    │  Aggressive│  Rapide    │  Réseau rapide   │
│   -T5    │  Insane    │  Très rapide│ Peu fiable      │
└──────────────────────────────────────────────────────┘
```

```bash
# Scan furtif pour éviter IDS
nmap -T1 -sS 192.168.1.10

# Scan rapide (réseau local)
nmap -T4 -sS 192.168.1.10
```

---

### Sauvegarde des résultats
```bash
# Format normal (lisible humain)
nmap -sV 192.168.1.10 -oN rapport.txt

# Format XML (parseable par outils)
nmap -sV 192.168.1.10 -oX rapport.xml

# Format Grepable
nmap -sV 192.168.1.10 -oG rapport.gnmap

# Tous les formats à la fois
nmap -sV 192.168.1.10 -oA rapport_complet
```

---

## 📌 PARTIE 8 : TECHNIQUES D'ÉVASION NMAP

Quand une cible a un IDS/IPS, tu dois **masquer tes scans**. Voici les techniques officielles du CEH.

---

### Fragmentation des paquets (-f)
```bash
sudo nmap -sS -f 192.168.1.10
sudo nmap -sS -ff 192.168.1.10   # Fragments de 16 octets
```

Les paquets fragmentés peuvent **contourner certains IDS** qui ne reassemblent pas les fragments avant inspection.

---

### Decoy Scan (-D) — Fausse identité

Tu envoies des paquets qui semblent venir de **plusieurs IPs simultanément**. L'IDS voit une attaque depuis 10 adresses → impossible d'isoler la vraie.

```bash
sudo nmap -sS -D 10.0.0.1,10.0.0.2,10.0.0.3,ME 192.168.1.10
```

**Ce que voit la cible :**
```
SYN depuis 10.0.0.1  → Port 80
SYN depuis 10.0.0.2  → Port 80
SYN depuis 10.0.0.3  → Port 80
SYN depuis TON_IP    → Port 80 (réel)

→ Impossible de savoir lequel est l'attaquant réel
```

---

### IP Spoofing (-S) + Interface (-e)
```bash
sudo nmap -sS -S 10.0.0.100 -e eth0 192.168.1.10
```

---

### Source Port Manipulation (--source-port)

Certains pare-feux autorisent le trafic venant du **port DNS (53)** par défaut.

```bash
sudo nmap -sS --source-port 53 192.168.1.10
```

---

### Délais aléatoires entre paquets
```bash
sudo nmap -sS --scan-delay 1s 192.168.1.10
sudo nmap -sS --max-rate 10 192.168.1.10
```

---

### Commande d'évasion complète professionnelle
```bash
sudo nmap -sS -T1 -f --data-length 25 -D RND:10 --source-port 53 \
          -sV --version-intensity 1 -O \
          --randomize-hosts -oA rapport_furtif \
          192.168.1.10
```

---

## 📌 PARTIE 9 : TRACEROUTE — CARTOGRAPHIER LE CHEMIN RÉSEAU

**Traceroute** permet de voir **tous les routeurs traversés** entre toi et la cible. Essentiel pour comprendre l'architecture réseau.

```bash
traceroute 192.168.1.10
```

**Sortie :**
```
traceroute to 192.168.1.10 (192.168.1.10), 30 hops max, 60 byte packets
 1  192.168.1.1 (192.168.1.1)    0.412 ms  0.389 ms  0.371 ms
 2  10.0.0.1 (10.0.0.1)          2.413 ms  2.391 ms  2.371 ms
 3  172.16.0.1 (172.16.0.1)      5.234 ms  5.198 ms  5.187 ms
 4  * * *
 5  203.0.113.1 (203.0.113.1)   15.678 ms 15.654 ms 15.640 ms
 6  192.168.1.10 (192.168.1.10)  16.234 ms 16.198 ms 16.187 ms
```

**Analyse :**
```
Hop 1 : 192.168.1.1     → Routeur local (LAN)
Hop 2 : 10.0.0.1        → Routeur interne (plage privée)
Hop 3 : 172.16.0.1      → Autre segment interne
Hop 4 : * * *           → Routeur qui ne répond pas (filtré)
Hop 5 : 203.0.113.1     → IP publique (sortie vers internet)
Hop 6 : 192.168.1.10    → Cible atteinte

→ Architecture : LAN → réseau interne → DMZ → Internet → Cible
→ Hop 4 suspect : probablement un pare-feu
```

---

## 📌 PARTIE 10 : WORKFLOW COMPLET DE SCANNING PROFESSIONNEL

Voici la **méthodologie complète** qu'un ethical hacker suit pendant la phase de scanning :

```bash
# ═══════════════════════════════════════════════════════
# ÉTAPE 1 : DÉCOUVERTE D'HÔTES ACTIFS
# ═══════════════════════════════════════════════════════
sudo nmap -sn 192.168.1.0/24 -oG hosts_actifs.txt

# Extraire les IPs actives
grep "Up" hosts_actifs.txt | cut -d " " -f2 > live.txt

# ═══════════════════════════════════════════════════════
# ÉTAPE 2 : SCAN DE PORTS RAPIDE
# ═══════════════════════════════════════════════════════
sudo nmap -sS -T4 --top-ports 1000 -iL live.txt -oA scan_rapide

# ═══════════════════════════════════════════════════════
# ÉTAPE 3 : SCAN COMPLET DE TOUS LES PORTS
# ═══════════════════════════════════════════════════════
sudo nmap -sS -p- -T4 -iL live.txt -oA scan_complet

# ═══════════════════════════════════════════════════════
# ÉTAPE 4 : VERSION + OS SUR PORTS OUVERTS
# ═══════════════════════════════════════════════════════
sudo nmap -sV -O -sC -iL live.txt -oA scan_versions

# ═══════════════════════════════════════════════════════
# ÉTAPE 5 : SCAN DE VULNÉRABILITÉS
# ═══════════════════════════════════════════════════════
sudo nmap --script vuln -iL live.txt -oA scan_vulns

# ═══════════════════════════════════════════════════════
# ÉTAPE 6 : UDP SUR PORTS CRITIQUES
# ═══════════════════════════════════════════════════════
sudo nmap -sU -p 53,67,68,69,111,123,137,138,161,162,2049 \
          -iL live.txt -oA scan_udp

# ═══════════════════════════════════════════════════════
# ÉTAPE 7 : GÉNÉRATION DU RAPPORT
# ═══════════════════════════════════════════════════════
# Convertir XML en HTML
xsltproc scan_versions.xml -o rapport_final.html
```

---

## 📌 RÉSUMÉ COMPARATIF DE TOUS LES TYPES DE SCANS

```
┌──────────────────────────────────────────────────────────────────────────┐
│  SCAN    │  FLAG  │  MÉCANISME         │  AVANTAGE       │  LIMITE       │
├──────────────────────────────────────────────────────────────────────────┤
│  SYN     │  -sS   │  SYN / RST         │  Furtif, rapide │  Root requis  │
│  Connect │  -sT   │  Handshake complet │  Sans root      │  Loggé        │
│  UDP     │  -sU   │  UDP paquets       │  Services UDP   │  Très lent    │
│  FIN     │  -sF   │  FIN flag seul     │  Évasion IDS    │  Pas Windows  │
│  Xmas    │  -sX   │  FIN+PSH+URG       │  Évasion IDS    │  Pas Windows  │
│  Null    │  -sN   │  Aucun flag        │  Évasion IDS    │  Pas Windows  │
│  ACK     │  -sA   │  ACK flag          │  Mapping FW     │  Pas ports    │
│  Window  │  -sW   │  ACK + window      │  Firewall info  │  Rare usage   │
│  Maimon  │  -sM   │  FIN+ACK           │  Évasion BSD    │  Très rare    │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 📌 RÉSUMÉ FINAL — CE QUE L'EXAMEN VA TESTER

```
✅ TCP handshake en 3 étapes et tous les flags TCP
✅ Différence TCP vs UDP et leurs usages
✅ États des ports : open, closed, filtered
✅ SYN scan vs Connect scan — différences et usages
✅ FIN/Xmas/Null scan — pourquoi ils évitent les IDS
✅ ACK scan — sert à cartographier le pare-feu
✅ UDP scan — lent, services UDP importants
✅ -sV (version) et -O (OS) — ce qu'ils révèlent
✅ NSE — catégories de scripts et usage --script vuln
✅ Timing -T0 à -T5 — quand utiliser chaque niveau
✅ Techniques d'évasion : -f, -D, --source-port
✅ Ports critiques et leurs services par cœur
✅ Différence Nmap vs Masscan (vitesse vs précision)
✅ Netcat pour banner grabbing
✅ Hping3 — forge de paquets personnalisés
✅ Traceroute — cartographier l'architecture réseau
```

---

## 🧪 QUESTIONS TYPE EXAMEN CEH — MODULE 3

**Q1 :** Quel type de scan Nmap effectue un demi-handshake TCP et n'établit jamais une connexion complète ?
> **Réponse : SYN Scan (-sS) — Half-Open Scan**

**Q2 :** Un scan renvoie `open|filtered` sur un port UDP. Que signifie cet état ?
> **Réponse : Nmap ne peut pas distinguer si le port est ouvert ou filtré — pas de réponse reçue**

**Q3 :** Quel flag Nmap permet de masquer l'attaquant en générant du trafic depuis plusieurs IPs leurres ?
> **Réponse : -D (Decoy Scan)**

**Q4 :** Un pentester utilise `nmap -sA`. Quel est l'objectif principal ?
> **Réponse : Cartographier les règles du pare-feu (identifier les ports filtrés vs non-filtrés)**

**Q5 :** Pourquoi les scans FIN, Xmas et Null sont-ils inefficaces contre Windows ?
> **Réponse : Windows répond RST sur tous les ports (ouverts et fermés), rendant impossible la distinction**

**Q6 :** Quelle commande Nmap détecte les services ET leurs versions sur les ports ouverts ?
> **Réponse : nmap -sV**

**Q7 :** Un scan Nmap révèle `vsftpd 2.3.4` sur le port 21. Quel est le risque immédiat ?
> **Réponse : Backdoor connue CVE-2011-2523 — accès root possible**

**Q8 :** Quel outil est capable de scanner tous les ports de l'internet entier en minutes grâce à sa vitesse extrême ?
> **Réponse : Masscan**

**Q9 :** Quel niveau de timing Nmap (-T) est recommandé pour éviter la détection par IDS ?
> **Réponse : -T0 (Paranoid) ou -T1 (Sneaky)**

**Q10 :** Un hacker envoie des paquets TCP avec les flags FIN, PSH et URG simultanément. Quel type de scan effectue-t-il ?
> **Réponse : Xmas Scan (-sX)**

---
