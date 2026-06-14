# 🛡️ CEH v12 — MODULE 2 : FOOTPRINTING & RECONNAISSANCE
### Guide pédagogique complet | SPCTRA Mz | exploit4040

---

## 📌 INTRODUCTION — POURQUOI LA RECONNAISSANCE EST LA PHASE LA PLUS IMPORTANTE

Il existe une règle d'or dans le monde du hacking professionnel :

> **"Give me 6 hours to chop down a tree and I will spend the first 4 sharpening the axe."**
> — Abraham Lincoln

Traduit en cybersécurité : **donne-moi 10 heures pour pirater un système, j'en passerai 7 à collecter des informations.**

La majorité des hackers amateurs échouent parce qu'ils attaquent trop vite, sans préparation. Un professionnel — éthique ou non — sait que **la qualité de l'attaque dépend entièrement de la qualité de la reconnaissance.**

Le **Footprinting** (ou Reconnaissance) c'est la **Phase 1** du pentest. Son objectif est de construire une **carte complète** de la cible : son infrastructure, ses employés, ses technologies, ses relations, ses failles potentielles — tout ça **sans déclencher d'alarme**.

---

## 📌 PARTIE 1 : FOOTPRINTING VS RECONNAISSANCE — LA DISTINCTION

Ces deux termes sont souvent utilisés comme synonymes, mais le CEH fait une distinction précise.

---

### 🔍 Reconnaissance
Terme **large et général**. Désigne toute activité de collecte d'informations sur une cible, qu'elle soit active ou passive, physique ou numérique.

---

### 🔍 Footprinting
Terme **spécifique au CEH**. C'est la méthodologie structurée de collecte d'informations sur une organisation cible — son réseau, ses systèmes, et ses employés — dans le but de **cartographier son périmètre d'attaque**.

Le résultat du footprinting c'est un **dossier de renseignement complet** sur la cible avant toute tentative d'intrusion.

---

## 📌 PARTIE 2 : LES DEUX TYPES DE RECONNAISSANCE

```
RECONNAISSANCE
├── PASSIVE  → Pas de contact direct avec la cible
└── ACTIVE   → Contact direct avec la cible (légèrement détectable)
```

---

## 🔵 RECONNAISSANCE PASSIVE

Tu collectes des informations sur la cible **sans jamais interagir directement** avec ses systèmes. La cible ne peut pas détecter ton activité car tu utilises des sources publiques ou tierces.

**Règle d'or :** La cible ne sait pas que tu existes.

**Sources utilisées :**
- Moteurs de recherche
- Réseaux sociaux
- Bases de données publiques (WHOIS, DNS public)
- Sites d'archivage web
- Offres d'emploi
- Documents publics (métadonnées)

---

## 🔵 RECONNAISSANCE ACTIVE

Tu interagis **directement** avec les systèmes de la cible pour obtenir des informations. C'est légèrement détectable si l'organisation a un monitoring en place.

**Exemples :**
- Envoyer un ping ou un scan réseau vers les serveurs de la cible
- Faire une requête DNS directement vers leur serveur
- Tenter un transfert de zone DNS
- Faire du social engineering téléphonique

---

## 📌 PARTIE 3 : OSINT — OPEN SOURCE INTELLIGENCE

L'**OSINT** est le pilier de la reconnaissance passive. C'est l'art de collecter des informations à partir de **sources ouvertes et publiques**.

Tout ce qui est accessible publiquement sans autorisation spéciale est une source OSINT :

```
Internet public → Sites web, réseaux sociaux, forums
Registres publics → WHOIS, registres d'entreprises
Presse et médias → Articles, communiqués de presse
Documents publics → PDF, présentations, rapports annuels
Offres d'emploi → Révèlent les technologies utilisées
```

---

### 🛠️ OSINT FRAMEWORK

Le site **osintframework.com** est une carte interactive de **tous les outils OSINT disponibles** classés par catégorie. C'est la référence ultime pour tout investigateur.

Catégories principales :
- Username tracking
- Email addresses
- Domain names
- IP addresses / Netblocks
- Social networks
- Documents / Files

---

## 📌 PARTIE 4 : GOOGLE HACKING / GOOGLE DORKS

Les **Google Dorks** sont des opérateurs de recherche avancés de Google utilisés pour trouver des **informations sensibles indexées accidentellement** sur internet.

C'est une technique de reconnaissance passive très puissante. Aucune interaction avec la cible — tu passes simplement par Google.

---

### 📋 LES OPÉRATEURS ESSENTIELS

| Opérateur | Fonction | Exemple |
|---|---|---|
| `site:` | Limiter au domaine | `site:entreprise.com` |
| `intitle:` | Mot dans le titre | `intitle:"index of"` |
| `inurl:` | Mot dans l'URL | `inurl:admin` |
| `intext:` | Mot dans le contenu | `intext:"mot de passe"` |
| `filetype:` | Type de fichier | `filetype:pdf` |
| `cache:` | Version en cache | `cache:site.com` |
| `link:` | Sites qui pointent vers | `link:site.com` |
| `"..."` | Phrase exacte | `"rapport financier 2024"` |
| `-` | Exclure un mot | `site:gov -www` |

---

### 🎯 DORKS UTILISÉS EN PENTEST PROFESSIONNEL

**Trouver des pages d'administration exposées :**
```
site:entreprise.com inurl:admin
site:entreprise.com inurl:login
site:entreprise.com intitle:"admin panel"
```

**Trouver des fichiers sensibles exposés :**
```
site:entreprise.com filetype:pdf "confidentiel"
site:entreprise.com filetype:xls "password"
site:entreprise.com filetype:sql
```

**Trouver des caméras exposées :**
```
intitle:"webcamXP 5" inurl:8080
intitle:"Live View / - AXIS"
```

**Trouver des pages de login vulnérables :**
```
inurl:"/phpMyAdmin/index.php"
inurl:"/wp-admin/wp-login.php"
```

**Trouver des index de répertoires ouverts :**
```
intitle:"index of" "parent directory"
intitle:"index of" passwd
intitle:"index of" ".htpasswd"
```

---

### 📚 GOOGLE HACKING DATABASE (GHDB)

Le site **exploit-db.com/google-hacking-database** recense des **milliers de dorks** classés par catégorie :
- Footholds (points d'entrée)
- Files containing usernames
- Sensitive directories
- Vulnerable servers
- Error messages
- Files containing passwords

> **Note CEH :** Le GHDB est maintenu par Offensive Security, la même organisation qui maintient Kali Linux et l'Exploit-DB.

---

## 📌 PARTIE 5 : WHOIS LOOKUP

**WHOIS** est un protocole et une base de données qui contient les **informations d'enregistrement** des noms de domaine et des blocs d'adresses IP.

---

### 🔍 Ce que WHOIS révèle :

```
┌─────────────────────────────────────────────┐
│  WHOIS : example.com                        │
├─────────────────────────────────────────────┤
│  Registrant Name    : John Smith            │
│  Registrant Email   : admin@example.com     │
│  Registrant Phone   : +1-555-0100           │
│  Registrant Address : 123 Main St, NY       │
│  Name Servers       : ns1.example.com       │
│                       ns2.example.com       │
│  Creation Date      : 2010-03-15            │
│  Expiration Date    : 2025-03-15            │
│  Registrar          : GoDaddy.com           │
└─────────────────────────────────────────────┘
```

Ces informations sont **de l'or** pour un hacker :
- Adresse email du propriétaire → cible pour phishing
- Numéro de téléphone → cible pour vishing
- Serveurs de noms → base pour l'énumération DNS
- Dates d'expiration → domaines qui vont expirer (domain hijacking)

---

### 🛠️ Outils WHOIS

**En ligne :**
- whois.domaintools.com
- whois.arin.net (pour les IP en Amérique du Nord)
- whois.ripe.net (pour les IP en Europe)
- whois.apnic.net (pour les IP en Asie-Pacifique)
- whois.afrinic.net (pour les IP en Afrique 🌍)

**En ligne de commande :**
```bash
whois example.com
whois 192.168.1.1
```

---

### 🌍 LES RIRs (Regional Internet Registries)

Les RIRs gèrent l'attribution des adresses IP dans leurs régions :

| RIR | Région |
|---|---|
| **ARIN** | Amérique du Nord |
| **RIPE NCC** | Europe, Moyen-Orient |
| **APNIC** | Asie-Pacifique |
| **AFRINIC** | Afrique 🌍 |
| **LACNIC** | Amérique Latine |

> **Pertinent pour toi :** En tant qu'étudiant basé à Kinshasa, les IPs africaines sont gérées par **AFRINIC**. Dans un pentest sur une organisation congolaise, tu iras sur whois.afrinic.net.

---

## 📌 PARTIE 6 : DNS ENUMERATION

Le **DNS (Domain Name System)** est l'annuaire de l'internet. Il traduit les noms de domaine en adresses IP.

Pour un hacker, le DNS est une **mine d'informations** sur l'infrastructure d'une organisation.

---

### 🔍 Les types d'enregistrements DNS

| Type | Fonction | Exemple |
|---|---|---|
| **A** | Domaine → IPv4 | example.com → 93.184.216.34 |
| **AAAA** | Domaine → IPv6 | example.com → 2606::... |
| **MX** | Serveurs mail | mail.example.com |
| **NS** | Serveurs DNS | ns1.example.com |
| **CNAME** | Alias | www → example.com |
| **TXT** | Infos texte | SPF, DKIM, vérification |
| **SOA** | Infos zone DNS | Serveur principal, contact admin |
| **PTR** | IP → Domaine (reverse) | 34.216.184.93 → example.com |
| **SRV** | Services spécifiques | _sip._tcp.example.com |

---

### 🛠️ OUTILS DNS EN LIGNE DE COMMANDE

#### nslookup
```bash
# Requête simple
nslookup example.com

# Spécifier un type d'enregistrement
nslookup -type=MX example.com
nslookup -type=NS example.com
nslookup -type=TXT example.com
nslookup -type=SOA example.com

# Utiliser un serveur DNS spécifique
nslookup example.com 8.8.8.8

# Reverse lookup (IP → domaine)
nslookup 93.184.216.34
```

#### dig (plus puissant que nslookup)
```bash
# Requête de base
dig example.com

# Type spécifique
dig example.com MX
dig example.com NS
dig example.com TXT
dig example.com ANY    # Tous les enregistrements

# Reverse lookup
dig -x 93.184.216.34

# Sortie courte (réponse seulement)
dig example.com +short

# Tracer le chemin DNS complet
dig example.com +trace

# Zone transfer (technique d'attaque DNS)
dig axfr @ns1.example.com example.com
```

#### host
```bash
host example.com
host -t MX example.com
host -t NS example.com
host 93.184.216.34    # Reverse lookup
```

---

### 🚨 ZONE TRANSFER (AXFR) — ATTAQUE DNS CRITIQUE

Le **Zone Transfer** est une technique qui permet à un serveur DNS secondaire de **télécharger toute la zone DNS** d'un domaine depuis le serveur primaire.

Si mal configuré, n'importe qui peut demander ce transfert et obtenir **la liste complète des sous-domaines et adresses IP** d'une organisation.

```bash
# Tenter un zone transfer
dig axfr @ns1.example.com example.com

# Si vulnérable, tu obtiens quelque chose comme :
# mail.example.com      A    10.0.0.1
# ftp.example.com       A    10.0.0.2
# dev.example.com       A    10.0.0.3
# vpn.example.com       A    10.0.0.4
# staging.example.com   A    10.0.0.5
# internal.example.com  A    192.168.1.100
```

> C'est comme si quelqu'un te donnait le plan complet d'un immeuble avant que tu y entres.

---

### 🛠️ OUTILS DE DNS ENUMERATION AUTOMATISÉS

#### DNSenum
```bash
dnsenum example.com
dnsenum --dnsserver 8.8.8.8 example.com
dnsenum --enum example.com
```
Effectue automatiquement : lookup, zone transfer, bruteforce de sous-domaines.

#### Fierce
```bash
fierce --domain example.com
fierce --domain example.com --wordlist /usr/share/wordlists/fierce.txt
```

#### Dnsrecon
```bash
dnsrecon -d example.com
dnsrecon -d example.com -t axfr    # Zone transfer
dnsrecon -d example.com -t brt     # Bruteforce
dnsrecon -d example.com -t std     # Standard enumeration
```

#### Sublist3r (bruteforce de sous-domaines)
```bash
sublist3r -d example.com
sublist3r -d example.com -b -p 80,443    # + bruteforce
```

---

## 📌 PARTIE 7 : REVERSE IP LOOKUP

Quand tu as l'adresse IP d'un serveur, le **Reverse IP Lookup** te dit **quels autres domaines sont hébergés sur cette même IP**.

C'est crucial car si 10 domaines partagent le même serveur, une vulnérabilité sur l'un peut affecter les autres.

**Outils en ligne :**
- viewdns.info/reverseip/
- yougetsignal.com/tools/web-sites-on-web-server/
- hackertarget.com/reverse-ip-lookup/

**En ligne de commande :**
```bash
# Reverse DNS lookup
dig -x 93.184.216.34
nslookup 93.184.216.34
```

---

## 📌 PARTIE 8 : EMAIL TRACKING ET ENUMERATION

Les emails sont une **source d'informations critique**. Ils révèlent :
- Le format des adresses email de l'entreprise (prenom.nom@corp.com)
- Les noms des employés
- Les technologies utilisées (headers email)
- L'infrastructure mail (serveurs MX)

---

### 🛠️ Trouver des emails

#### theHarvester
C'est l'outil de référence pour collecter des emails, sous-domaines, IPs et URLs associés à un domaine.

```bash
# Recherche via Google
theHarvester -d example.com -b google

# Recherche via Bing
theHarvester -d example.com -b bing

# Toutes les sources disponibles
theHarvester -d example.com -b all

# Avec limitation et sortie HTML
theHarvester -d example.com -b google -l 100 -f rapport.html
```

Sources supportées : Google, Bing, LinkedIn, Twitter, GitHub, Shodan, CertSpotter, Hunter, etc.

---

#### Hunter.io
Site web qui agrège les adresses email publiquement associées à un domaine.

```
https://hunter.io/search/example.com
```

Révèle :
- Le format d'email de l'entreprise (ex: {firstname}.{lastname}@company.com)
- Les emails trouvés avec leurs sources
- Le score de confiance de chaque email

---

### 🔍 Analyser les headers d'un email

Un email reçu contient des **headers** (en-têtes) qui révèlent le chemin exact qu'il a parcouru : serveur de départ, serveur de relais, IPs traversées, logiciels utilisés.

```
Received: from mail.example.com (mail.example.com [203.0.113.1])
Received: from webapp01.internal.example.com ([192.168.1.50])
X-Mailer: Microsoft Outlook 16.0
X-Originating-IP: 10.0.0.5
```

Informations extraites :
- **203.0.113.1** → IP publique du serveur mail
- **192.168.1.50** → IP interne révélée accidentellement
- **Microsoft Outlook 16.0** → version du logiciel email
- **10.0.0.5** → adresse IP interne de la machine expéditrice

> Un simple email de phishing peut révéler toute l'architecture interne d'une entreprise.

---

## 📌 PARTIE 9 : SHODAN ET CENSYS

Ces deux outils sont appelés les **"moteurs de recherche des hackers"**. Au lieu d'indexer des pages web comme Google, ils **scannent et indexent tous les appareils connectés à internet** : serveurs, routeurs, caméras, imprimantes, systèmes SCADA, IoT...

---

### 🔴 Shodan.io

Shodan scanne en permanence l'intégralité de l'espace d'adressage IPv4 et stocke les **bannières de services** (les réponses des ports ouverts).

**Filtres Shodan essentiels :**

```
# Trouver tous les appareils d'une organisation
org:"Orange DRC"
org:"Vodacom Congo"

# Trouver les serveurs d'un pays
country:"CD"    # Congo RDC
country:"ZA"    # Afrique du Sud

# Trouver par technologie
product:"Apache httpd"
product:"Microsoft IIS"
product:"OpenSSH"

# Trouver des appareils sur un port spécifique
port:22         # SSH
port:3389       # RDP (Remote Desktop Windows)
port:23         # Telnet (très dangereux si ouvert)
port:5900       # VNC

# Trouver les versions vulnérables connues
product:"vsftpd" version:"2.3.4"    # Backdoor connue !
product:"Apache" version:"2.4.49"   # CVE-2021-41773

# Trouver des caméras spécifiques
product:"Hikvision IP Camera"
product:"AXIS"

# Combinaisons
country:"CD" port:22 product:"OpenSSH"
org:"entreprise.com" port:443
```

**Shodan Dorks populaires :**
```
"default password" country:CD
"Authorization: Basic" port:80
"Server: Apache" country:CD port:8080
title:"PhpMyAdmin" country:CD
```

---

### 🔵 Censys.io

Similaire à Shodan mais avec une approche plus orientée **recherche de sécurité**. Il offre une vue plus détaillée des certificats SSL/TLS, ce qui permet de trouver des sous-domaines cachés.

```
# Chercher un domaine
parsed.names: example.com

# Chercher par organisation
autonomous_system.organization: "Example Corp"

# Trouver des certificats SSL
parsed.subject.organization: "Example Corp"
```

> **Astuce professionnelle :** Les certificats SSL/TLS sont publics. Censys et crt.sh te permettent de trouver **tous les sous-domaines** d'une organisation en cherchant leurs certificats.

```
# Sur crt.sh
https://crt.sh/?q=%.example.com
```

---

## 📌 PARTIE 10 : WAYBACK MACHINE

La **Wayback Machine** (archive.org) archive des copies de pages web depuis 1996. C'est une source d'information passive extrêmement puissante.

**Ce qu'on peut y trouver :**
- Anciennes versions d'un site web (peut contenir des vulnérabilités corrigées depuis)
- Fichiers supprimés mais encore archivés
- Anciennes technologies utilisées
- Anciens employés listés sur le site
- Anciens sous-domaines

```bash
# Utiliser waybackurls pour extraire toutes les URLs archivées
waybackurls example.com | grep "\.php"
waybackurls example.com | grep "admin"
waybackurls example.com | grep "\.zip\|\.sql\|\.bak"
```

---

## 📌 PARTIE 11 : RECON-NG

**Recon-ng** est un framework de reconnaissance modulaire, similaire à Metasploit mais dédié à la phase de collecte d'informations.

```bash
# Lancer Recon-ng
recon-ng

# Créer un workspace pour ton engagement
[recon-ng] > workspaces create pentest_clientA

# Voir les modules disponibles
[recon-ng] > modules search whois
[recon-ng] > modules search dns
[recon-ng] > modules search shodan

# Charger un module
[recon-ng] > modules load recon/domains-hosts/hackertarget

# Configurer et lancer
[recon-ng][pentest_clientA][hackertarget] > options set SOURCE example.com
[recon-ng][pentest_clientA][hackertarget] > run

# Voir les résultats
[recon-ng] > show hosts
[recon-ng] > show contacts
[recon-ng] > show credentials
```

Recon-ng stocke tous les résultats dans une **base de données SQLite locale** ce qui facilite les investigations longues.

---

## 📌 PARTIE 12 : MALTEGO

**Maltego** est un outil de visualisation OSINT qui crée des **graphes relationnels** entre différentes entités : domaines, IPs, emails, personnes, organisations, comptes réseaux sociaux.

Il utilise des **transforms** (requêtes automatisées vers des sources de données) pour découvrir automatiquement des liens entre entités.

**Exemple de graphe Maltego :**
```
example.com
├── 93.184.216.34 (IP)
│   └── Héberge aussi: example2.com, example3.com
├── mail.example.com
│   └── 93.184.216.50 (MX)
├── John Smith (PDG, via LinkedIn)
│   ├── john.smith@example.com
│   ├── Twitter: @johnsmith_ceo
│   └── Téléphone: +1-555-0100
└── ns1.example.com (DNS)
    └── Géré par: GoDaddy
```

Version gratuite : **Maltego Community Edition** (transformations limitées mais suffisante pour la pratique CEH)

---

## 📌 PARTIE 13 : NETCRAFT

**Netcraft** (netcraft.com) est une source d'information passive qui révèle :

- Le **système d'exploitation** du serveur web
- Le **serveur web** utilisé (Apache, Nginx, IIS) et sa version
- L'**hébergeur** du domaine
- L'**historique** des technologies utilisées
- Les **sous-domaines** connus

**Comment l'utiliser :**
```
https://sitereport.netcraft.com/?url=example.com
```

> **Pourquoi c'est puissant ?** Si Netcraft me dit que le serveur tourne sur Apache 2.4.49, je sais immédiatement qu'il est vulnérable à CVE-2021-41773 (Path Traversal/RCE critique). Et la cible ne sait pas que j'ai regardé.

---

## 📌 PARTIE 14 : SOCIAL MEDIA FOOTPRINTING

Les réseaux sociaux sont une **mine d'or OSINT**. Les employés publient sans réaliser les informations qu'ils révèlent.

---

### LinkedIn — Source numéro 1 en OSINT professionnel

Ce qu'on peut extraire :
```
✅ Liste de tous les employés
✅ Postes et hiérarchie (qui est admin système, qui est RSSI)
✅ Technologies utilisées (dans les descriptions de poste)
✅ Offres d'emploi → révèlent les technologies cherchées
✅ Anciens employés → potentiellement mécontents
✅ Adresses email (souvent listées)
✅ Numéros de téléphone directs
```

**Exemple d'exploitation d'une offre d'emploi :**
```
Offre: "Cherche Administrateur Système Windows Server 2019 
        maîtrisant VMware vSphere 7.0, Cisco ASA, 
        et Microsoft Azure AD"

Information extraite:
→ OS: Windows Server 2019
→ Virtualisation: VMware vSphere 7.0
→ Firewall: Cisco ASA
→ Cloud: Microsoft Azure AD
→ Direction d'attaque probable: Azure AD misconfiguration
```

---

### Twitter / X, Facebook, Instagram

- Publications géolocalisées → emplacement des bureaux, salles serveurs
- Photos de badges d'accès publiées accidentellement
- Photos de tableaux blancs avec schémas d'architecture
- Discussions sur des projets internes
- Horaires d'équipe (utile pour le social engineering)

---

### Outils d'automatisation réseaux sociaux :

```bash
# Sherlock - Trouver un username sur 300+ plateformes
sherlock exploit4040

# Social-Analyzer
social-analyzer --username "john.smith" --platforms "linkedin,twitter"

# Twint (Twitter OSINT sans API)
twint -u johndoe --since 2024-01-01
```

---

## 📌 PARTIE 15 : FOCA — ANALYSE DES MÉTADONNÉES

**FOCA** (Fingerprinting Organizations with Collected Archives) est un outil Windows qui analyse les **métadonnées des documents publics** d'une organisation.

Quand une entreprise publie des PDFs, Word, Excel, PowerPoint sur son site web, ces fichiers contiennent souvent des **métadonnées cachées** :

```
Métadonnées extraites d'un PDF:
├── Auteur : Jean-Baptiste Muamba
├── Créé avec : Microsoft Word 2016
├── Imprimante : HP LaserJet P4015 (\\serveur-print01\HP4015)
├── Chemin original : C:\Users\jb.muamba\Documents\confidentiel\rapport_q3.docx
├── Serveur : serveur-print01
└── Domaine Windows : CORP\jb.muamba
```

> En un seul document PDF publié innocemment, on a : un nom d'utilisateur Windows, un serveur interne, un chemin de fichier, et la version exacte de Word utilisée.

**Alternative open source :**
```bash
# exiftool - extraction de métadonnées
exiftool document.pdf
exiftool *.docx
exiftool -r /dossier/   # Récursif

# Extraction en masse depuis un domaine
metagoofil -d example.com -t pdf,doc,xls,ppt -l 100 -n 50 -o /tmp/results
```

---

## 📌 PARTIE 16 : EMAIL TRACKING

**EmailTrackerPro** et d'autres outils permettent de tracer des emails envoyés pour collecter des informations sur le destinataire : localisation approximative, client email utilisé, système d'exploitation, heure d'ouverture.

Principe : On intègre un **pixel de tracking invisible** (1x1 pixel) dans l'email HTML. Quand la victime l'ouvre, le pixel charge depuis notre serveur et on enregistre :
- Adresse IP du destinataire
- User-Agent (OS + navigateur/client mail)
- Heure d'ouverture
- Localisation géographique approximative

```html
<!-- Pixel de tracking (exemple éducatif) -->
<img src="https://tracker.exemple.com/pixel.gif?id=123" 
     width="1" height="1" style="display:none">
```

---

## 📌 PARTIE 17 : MÉTHODOLOGIE PROFESSIONNELLE DE FOOTPRINTING

Voici la **méthodologie complète** qu'un ethical hacker professionnel suit pendant la phase de reconnaissance :

---

```
ÉTAPE 1 : COLLECTE D'INFORMATIONS SUR L'ORGANISATION
├── Nom légal exact, filiales, partenaires
├── Localisation des bureaux, datacenters
├── Plages d'adresses IP (WHOIS/RIR)
├── Noms de domaine principaux et secondaires
└── Technologies mentionnées dans la presse

ÉTAPE 2 : COLLECTE SUR LE RÉSEAU
├── WHOIS du domaine et des IPs
├── Enumeration DNS complète (A, MX, NS, TXT, SOA)
├── Tentative de zone transfer (AXFR)
├── Bruteforce de sous-domaines (sublist3r, amass)
├── Reverse IP lookup
└── Traceroute (cartographie réseau)

ÉTAPE 3 : COLLECTE SUR LES PERSONNES
├── theHarvester (emails, noms)
├── LinkedIn (employés, postes, technologies)
├── Hunter.io (format email)
├── Réseaux sociaux
└── Offres d'emploi

ÉTAPE 4 : COLLECTE TECHNIQUE
├── Shodan/Censys (services exposés)
├── Netcraft (OS, serveur web, historique)
├── crt.sh (certificats SSL → sous-domaines)
├── Wayback Machine (anciennes versions)
└── FOCA/exiftool (métadonnées de documents)

ÉTAPE 5 : COMPILATION DU RAPPORT
├── Cartographie de l'infrastructure
├── Liste des employés clés
├── Technologies identifiées
├── Vecteurs d'attaque probables
└── Recommandations de scan (Phase 2)
```

---

## 📌 PARTIE 18 : CONTRE-MESURES AU FOOTPRINTING

En tant qu'ethical hacker, tu dois aussi savoir **comment se défendre** contre la reconnaissance. Le CEH teste ça aussi.

---

| Vecteur | Contre-mesure |
|---|---|
| **WHOIS** | Utiliser un service de confidentialité WHOIS (privacy protect) |
| **Google Dorks** | Google Search Console, fichier robots.txt, retirer des pages de l'index |
| **Zone Transfer** | Restreindre AXFR aux serveurs DNS autorisés uniquement |
| **Shodan** | Fermer les ports inutiles, pare-feu, bannières minimales |
| **Métadonnées** | Nettoyer les documents avant publication (exiftool -all= doc.pdf) |
| **Email tracking** | Bloquer le chargement d'images externes dans le client mail |
| **LinkedIn/Social** | Formation des employés, politique OPSEC |
| **Offres d'emploi** | Ne pas mentionner les technologies spécifiques dans les offres |
| **DNS reconnaissance** | Minimiser les enregistrements DNS publics |
| **Footprinting général** | Surveillance continue (Google Alerts, Brand24) |

---

## 📌 OUTILS RÉSUMÉ — MODULE 2

```
┌──────────────────────────────────────────────────────────────┐
│  CATÉGORIE          │  OUTIL                                 │
├──────────────────────────────────────────────────────────────┤
│  OSINT global       │  OSINT Framework, Maltego, Recon-ng    │
│  Google Hacking     │  Google Dorks, GHDB (exploit-db)       │
│  WHOIS/Registres    │  whois, ARIN, RIPE, AFRINIC, APNIC     │
│  DNS                │  nslookup, dig, host, DNSenum, Fierce  │
│                     │  Dnsrecon, Sublist3r, amass            │
│  Emails             │  theHarvester, Hunter.io, EmailTrackerPro│
│  IP/Services        │  Shodan, Censys, Reverse IP lookup     │
│  Technologies       │  Netcraft, SpyOnWeb, BuiltWith         │
│  Métadonnées        │  FOCA, exiftool, metagoofil            │
│  Archives web       │  Wayback Machine, waybackurls          │
│  Social Media       │  Sherlock, Twint, LinkedIn manual      │
│  Certificats SSL    │  crt.sh, Censys                        │
└──────────────────────────────────────────────────────────────┘
```

---

## 📌 RÉSUMÉ FINAL — CE QUE L'EXAMEN VA TESTER

```
✅ Différence Footprinting passif vs actif
✅ Définition OSINT et ses sources
✅ Google Dorks — opérateurs clés (site:, filetype:, intitle:)
✅ WHOIS — ce qu'il révèle et les RIRs par région
✅ DNS — tous les types d'enregistrements et leur rôle
✅ Zone Transfer AXFR — comment ça marche et pourquoi c'est dangereux
✅ theHarvester — usage et sources
✅ Shodan/Censys — utilité et filtres
✅ Maltego — visualisation de liens entre entités
✅ Recon-ng — framework modulaire de reconnaissance
✅ FOCA — extraction de métadonnées
✅ Contre-mesures pour chaque vecteur
✅ Connaître l'ordre de la méthodologie professionnelle
```

---

## 🧪 QUESTIONS TYPE EXAMEN CEH — MODULE 2

**Q1 :** Un ethical hacker consulte archive.org pour voir les anciennes versions du site d'une cible. Quel type de reconnaissance effectue-t-il ?
> **Réponse : Passive (Wayback Machine)**

**Q2 :** Quelle commande DNS permet de tenter un transfert de zone ?
> **Réponse : `dig axfr @ns1.example.com example.com`**

**Q3 :** Quel outil permet de chercher des appareils connectés à internet par technologie ou par pays ?
> **Réponse : Shodan.io**

**Q4 :** Un pentester utilise `theHarvester -d example.com -b google`. Que collecte-t-il ?
> **Réponse : Emails, sous-domaines, IPs et URLs associés au domaine example.com via Google**

**Q5 :** Quelle organisation gère les adresses IP en Afrique ?
> **Réponse : AFRINIC**

**Q6 :** Un document Word publié sur le site web d'une entreprise contient le chemin `C:\Users\admin\Documents\confidentiel.docx`. Quelle technique a permis de découvrir ça ?
> **Réponse : Analyse des métadonnées (FOCA / exiftool)**

**Q7 :** Un attaquant utilise `site:corp.com filetype:xls`. Quel outil utilise-t-il ?
> **Réponse : Google Hacking / Google Dorks**

**Q8 :** Quel enregistrement DNS révèle les serveurs de messagerie d'une organisation ?
> **Réponse : Enregistrement MX**

**Q9 :** Quelle contre-mesure empêche le zone transfer DNS non autorisé ?
> **Réponse : Restreindre les requêtes AXFR aux serveurs DNS autorisés uniquement**

**Q10 :** Quel framework de reconnaissance stocke ses résultats dans une base SQLite et fonctionne de manière modulaire similaire à Metasploit ?
> **Réponse : Recon-ng**

---
