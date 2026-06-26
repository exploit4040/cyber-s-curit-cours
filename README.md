# PLAN DE COURS DÉTAILLÉ - CEH v12
## Certified Ethical Hacker (EC-Council)
### 20 Modules Officiels

---

## MODULE 1 : INTRODUCTION À L'ETHICAL HACKING

**Objectifs :**
- Comprendre les concepts fondamentaux de la cybersécurité
- Distinguer les types de hackers (White hat, Black hat, Grey hat, Script kiddie, Hacktivist)
- Maîtriser les 5 phases d'un test d'intrusion
- Connaître les cadres légaux (ISO 27001, PCI DSS, HIPAA, GDPR, SOX)
- Comprendre les Rules of Engagement (RoE)

**Concepts clés :**
- CIA Triad (Confidentialité, Intégrité, Disponibilité)
- AAA (Authentification, Autorisation, Comptabilité)
- Non-répudiation
- Analyse de risque et gestion des vulnérabilités
- Types de contrôles (préventif, détective, correctif, dissuasif, compensatoire)

**Termes importants :**
- CVE (Common Vulnerabilities and Exposures)
- CVSS (Common Vulnerability Scoring System) - version 3.1
- CWE (Common Weakness Enumeration)
- APT (Advanced Persistent Threat)
- Zero-day vulnerability

---

## MODULE 2 : FOOTPRINTING ET RECONNAISSANCE

**Footprinting passif :**
- OSINT (Open Source Intelligence)
- Recherches Google avancées / Google Dorks
- Whois lookup (whois.domaintools.com, whois.arin.net)
- DNS enumeration (nslookup, dig, host)
- Reverse IP lookup (viewdns.info, yougetsignal.com)
- Email tracking (EmailTrackerPro)

**Footprinting actif :**
- theHarvester
- Recon-ng
- Maltego (version community gratuite)
- Shodan.io, Censys.io
- Wayback Machine (archive.org)
- Netcraft, SpyOnWeb
- Social media footprinting (LinkedIn, Facebook, Twitter)
- Google Hacking Database (GHDB)

**Outils essentiels :**
- theHarvester, Recon-ng, Maltego, Shodan, Censys
- DMitry, FOCA (métadonnées)
- OSINT Framework (osintframework.com)

---

## MODULE 3 : SCANNING RÉSEAUX

**Concepts réseau :**
- Modèle OSI (7 couches)
- TCP/IP : protocoles, ports, flags TCP (SYN, ACK, FIN, RST, PSH, URG)
- Handshake TCP en 3 étapes
- Types de ports : ouverts, fermés, filtrés

**Nmap :**
- SYN scan (-sS), Connect scan (-sT), UDP scan (-sU)
- FIN scan (-sF), Xmas scan (-sX), Null scan (-sN)
- ACK scan (-sA), Window scan (-sW), Maimon scan (-sM)
- Ping sweep (-sn), OS fingerprinting (-O)
- Version detection (-sV), Script scanning (-sC)
- NSE (Nmap Scripting Engine) : découverte, vulnérabilité, exploitation
- Évasion : fragmentation (-f), decoy (-D), spoof (-S), timing (-T0 à -T5)

**Autres outils :**
- Masscan, Hping3, Unicornscan
- Netcat / Ncat
- Angry IP Scanner, Advanced Port Scanner

**Évasion de pare-feu :**
- Fragmentation des paquets
- IP spoofing
- MAC address spoofing
- Timing entre les paquets

---

## MODULE 4 : ÉNUMÉRATION

**Enumeration NetBIOS/SMB :**
- nbtstat, nbtscan, net view, enum4linux
- Null sessions
- SMBMap, Smbclient, Smbget

**Enumeration SNMP :**
- SNMPwalk, SNMPcheck, SolarWinds, MIB Browser
- Community strings (public, private)

**Enumeration LDAP :**
- LDAPsearch, JXplorer, Softerra LDAP Browser

**Enumeration DNS :**
- Zone transfer, DNSenum, Fierce, Dnsrecon

**Enumeration NFS :**
- Showmount, mount

**Enumeration SMTP :**
- VRFY, EXPN, RCPT TO, SMTP-user-enum

**Enumeration Windows :**
- Net commands (net user, net localgroup, net share)
- PsExec, WMI, PowerShell Remoting

**Enumeration Linux :**
- /etc/passwd, /etc/shadow, /etc/group
- Id, whoami, groups, users, finger

---

## MODULE 5 : ANALYSE DE VULNÉRABILITÉS

**Concepts :**
- CVE (Common Vulnerabilities and Exposures)
- CWE (Common Weakness Enumeration)
- CVSS v3.1 (score 0-10)
- Types de vulnérabilités : configuration, logicielle, réseau, humaine

**Scanners :**
- Nessus (Tenable)
- OpenVAS (Greenbone) - gratuit
- QualysGuard
- Nexpose (Rapid7)
- GFI LanGuard, Retina CS

**Processus :**
- Identification des actifs
- Scan des vulnérabilités
- Analyse et priorisation (faux positifs, faux négatifs)
- Reporting et remédiation
- Rescan et validation

**Métriques :**
- CVSS Vector : AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
- Exploitability metrics et Impact metrics

---

## MODULE 6 : HACKING DE SYSTÈMES

**Authentification Windows :**
- NTLM, NTLMv2, Kerberos
- LAN Manager hash, LM hash
- SAM database, NTDS.dit

**Password cracking :**
- John the Ripper (mode wordlist, single, incremental, external)
- Hashcat (cracking GPU, modes : 0=MD5, 1000=NTLM, 100=SHA1, 1400=SHA256)
- Rainbow tables (Ophcrack, RainbowCrack)
- Hydra, Medusa, Ncrack (bruteforce en ligne)

**Privilege escalation Linux :**
- SUID/SGID binaries (find / -perm -4000)
- Cron jobs (crontab -l, /etc/crontab)
- Sudo (sudo -l, sudo misconfiguration)
- Kernel exploits (CVE-2021-4034 - PwnKit, Dirty Cow)
- PATH hijacking
- NFS no_root_squash

**Privilege escalation Windows :**
- AlwaysInstallElevated
- Unquoted service paths
- Service permissions (sc, accesschk)
- DLL hijacking / DLL injection
- Token stealing (SeImpersonatePrivilege, Potato exploits)
- UAC bypass
- Kernel exploits (MS16-135, MS17-017)

**Autres techniques :**
- Keylogging (Strokes, Keylog, Refog)
- Stéganographie (QuickStego, OpenStego, Snow)
- Rootkits (kernel-level, user-level)
- Hidding files (NTFS streams, attrib)

**Contre-mesures :**
- GPO (Group Policy Object)
- LAPS (Local Administrator Password Solution)
- UAC, BitLocker, EFS
- Windows Defender, EMET, AppLocker

---

## MODULE 7 : MALWARES

**Types de malwares :**
- Virus (file infector, boot sector, macro, multipartite, polymorphic)
- Worms (CodeRed, Slammer, Blaster, Conficker)
- Trojans (RAT : Remote Access Trojan)
- Ransomware (Crypto, Locker, WannaCry, NotPetya)
- Rootkits (kernel, user, bootkit, firmware)
- Spyware, Adware, Botnets, Logic bombs
- Fileless malware

**Analyse statique :**
- Hachage (MD5, SHA1, SHA256)
- Strings, PE Studio, DIE (Detect It Easy)
- VirusTotal, Hybrid Analysis
- PE headers (Portable Executable)

**Analyse dynamique :**
- Sandbox (Cuckoo, Joe Sandbox, Any.Run)
- Debuggers (x64dbg, OllyDbg, WinDbg)
- Process Monitor (Procmon), Process Explorer
- Wireshark, Fiddler, TCPView
- Regshot, Autoruns, API Monitor

**Obfuscation et anti-analyse :**
- Packing (UPX, Themida, VMProtect)
- Crypting, encoding (Base64, XOR)
- Anti-VM, Anti-debug, Anti-sandbox
- Dead code insertion, instruction substitution
- Code reordering

---

## MODULE 8 : SNIFFING

**Concepts :**
- Promiscuous mode vs non-promiscuous mode
- Protocoles vulnérables : HTTP, FTP, Telnet, POP3, SMTP (non chiffrés)
- Protocoles sécurisés : HTTPS, SFTP, SSH, IMAPS

**ARP Spoofing / ARP Poisoning :**
- Principe : corruption de la table ARP
- Outils : Arpspoof, Bettercap, Cain & Abel
- MITM (Man-in-the-Middle)

**MAC Flooding :**
- Inondation de la table CAM du switch (Ettercap, Macof)

**DHCP Starvation / Rogue DHCP :**
- Attaque par épuisement des baux DHCP
- Yersinia, DHCPstarv

**DNS Poisoning / Spoofing :**
- Modification du cache DNS
- DNSSpoof, Ettercap

**Outils :**
- Wireshark (filtres : http, tcp.port==80, ip.addr==X.X.X.X)
- tcpdump (commandes : -i, -n, -v, -X, -w, -r)
- Bettercap (sniffing, ARP spoofing, HTTPS stripping)
- Ettercap, Cain & Abel, Dsniff, Responder

**SSL/TLS attacks :**
- SSL stripping (sslstrip, Bettercap)
- SSL/TLS MITM (mitmproxy, Burp Suite)
- Downgrade attack (POODLE, FREAK, Logjam)

**Contre-mesures :**
- Dynamic ARP Inspection (DAI)
- Port Security (MAC sticky, limit)
- DHCP Snooping
- 802.1X (dot1x)
- HTTPS everywhere, HSTS
- VPN (IPSec, OpenVPN, WireGuard)

---

## MODULE 9 : INGÉNIERIE SOCIALE

**Types d'attaques :**
- Phishing (email massif)
- Spear-phishing (ciblé)
- Whaling (cadres dirigeants)
- Vishing (voice phishing)
- SMiShing (SMS phishing)
- Pharming (redirection DNS)
- Clone phishing

**Techniques :**
- Pretexting (création d'un scénario crédible)
- Baiting (physique : clé USB piégée)
- Tailgating / Piggybacking (suivi physique)
- Quid pro quo (échange d'information)
- Impersonation (usurpation d'identité)
- Dumpster diving (fouille des poubelles)
- Shoulder surfing (observation par-dessus l'épaule)
- Watering hole (compromission d'un site visité fréquemment)

**Outils :**
- SET (Social Engineering Toolkit) - Kali Linux
- GoPhish (open source)
- PhishTester, SendPhish, King Phisher
- Evilginx (reverse proxy phishing)

**Contre-mesures :**
- Sensibilisation et formation
- MFA (Multi-Factor Authentication)
- SPF, DKIM, DMARC (sécurité email)
- Email filtering (Proofpoint, Mimecast)
- Politiques de sécurité
- Signalement des tentatives

---

## MODULE 10 : DÉNI DE SERVICE (DoS/DDoS)

**Types d'attaques :**
- Volume-based : ICMP flood, UDP flood, SYN flood, Ping of Death
- Protocol-based : SYN flood, Smurf attack, Fraggle attack
- Application-layer : HTTP flood, Slowloris, Slow read attack
- Amplification : NTP (monlist), DNS (ANY), SSDP, CharGEN
- Reflection (spoofing de l'IP source)

**Botnets :**
- Mirai, Zeus, Emotet, Trickbot
- C2 (Command and Control) : IRC, HTTP, DNS tunneling
- Structure client-serveur, P2P

**Outils :**
- LOIC (Low Orbit Ion Cannon), HOIC
- Hping3, Metasploit (auxiliary/dos)
- Slowloris, GoldenEye, RUDY
- MHDDoS, DDoSIM, Tor's Hammer

**Contre-mesures :**
- Rate limiting (iptables, nginx limit_req)
- Load balancers, CDN (Cloudflare, Akamai)
- SYN cookies, TCP backlog
- Blackhole routing, null routing
- IDS/IPS (Snort, Suricata)
- WAF (ModSecurity, AWS WAF)
- Reverse proxies (Nginx, HAProxy)
- ISP-level filtering

**Détection :**
- Netstat, netflow, bandwidth monitoring
- Nagios, Zabbix, PRTG
- MRTG, Cacti

---

## MODULE 11 : VOL DE SESSION

**Concepts :**
- Session ID, cookies, tokens JWT, SAML
- Session fixation, session hijacking
- Man-in-the-Browser (MITB)

**Attaques :**
- Cookie stealing (XSS + vol de cookie)
- Session prediction (cookies prévisibles)
- Session fixation (forcer un cookie connu)
- CRLF injection
- CSRF / XSRF (Cross-Site Request Forgery)
- Sniffing de session (HTTP non chiffré)
- MITB (Man-in-the-Browser) via Trojan bancaire

**Outils :**
- Burp Suite (Repeater, Sequencer, Intruder)
- OWASP ZAP
- Cookie Manager, EditThisCookie
- Firesheep (sessions HTTP non chiffrées)
- Bettercap (HTTP/HTTPS proxy)

**Contre-mesures :**
- HttpOnly flag (cookies inaccessibles au JS)
- Secure flag (cookies HTTPS uniquement)
- SameSite flag (Strict, Lax, None)
- Token rotation, expiration des sessions
- CSRF tokens
- Re-validation des sessions
- Chiffrement TLS

---

## MODULE 12 : ÉVASION IDS/PARE-FEU/HONEYPOTS

**IDS/IPS :**
- Network-based (NIDS) : Snort, Suricata, Bro/Zeek
- Host-based (HIDS) : OSSEC, Wazuh, Tripwire
- Détection par signature vs anomalie vs heuristique
- False positive, false negative

**Types de pare-feu :**
- Packet filter (stateless)
- Stateful inspection
- Application-level (proxy)
- Next-Generation (NGFW) : Palo Alto, Fortinet
- WAF (Web Application Firewall) : ModSecurity, Cloudflare
- UTM (Unified Threat Management)

**Évasion :**
- Fragmentation des paquets (-f dans Nmap)
- IP spoofing, MAC spoofing
- Source routing
- Tunneling (ICMP, DNS, HTTP, SSH)
- Encodage/encryption du payload
- Timing delays
- Polymorphism, metamorphism
- Outils : Nmap evasions, Fragroute, Traffic IQ Professional

**Honeypots :**
- Low-interaction (Honeyd, Dionaea)
- High-interaction (Argos, Sebek)
- Honeynet, Honeytokens
- T-Pot (suite complète honeypot)
- Indicateurs de compromission (IOC)

---

## MODULE 13 : HACKING DE SERVEURS WEB

**Serveurs ciblés :**
- Apache, Nginx, IIS (Internet Information Services)
- Tomcat, WebLogic, WebSphere
- Lighttpd, Caddy

**Attaques :**
- Directory traversal / Path traversal (../../../etc/passwd)
- HTTP methods abuse (PUT, DELETE, TRACE, CONNECT)
- Default credentials (Tomcat admin, PHPMyAdmin)
- Missing security headers (X-Frame-Options, CSP, HSTS)
- Server-Side Template Injection (SSTI)
- HTTP parameter pollution (HPP)
- WebDAV exploitation (davtest, cadaver)

**Contre-mesures :**
- Durcissement (hardening) des serveurs
- Désactiver les méthodes inutiles (TRACE, PUT, DELETE)
- Vhost configuration correcte
- Permissions minimales
- Patch management régulier
- WAF

---

## MODULE 14 : HACKING D'APPLICATIONS WEB

**OWASP Top 10 (2021) :**
1. A01 - Broken Access Control
2. A02 - Cryptographic Failures
3. A03 - Injection
4. A04 - Insecure Design
5. A05 - Security Misconfiguration
6. A06 - Vulnerable and Outdated Components
7. A07 - Identification and Authentication Failures
8. A08 - Software and Data Integrity Failures
9. A09 - Security Logging and Monitoring Failures
10. A10 - Server-Side Request Forgery (SSRF)

**SQL Injection :**
- In-band (erreur, union-based)
- Blind (boolean-based, time-based)
- Out-of-band (DNS, HTTP)
- Second-order SQLi
- Outils : SQLMap (automatisation), jSQL

**XSS (Cross-Site Scripting) :**
- Reflected XSS, Stored XSS, DOM-based XSS
- Self-XSS, blind XSS
- XSS payloads (alerte, cookie stealing, redirection)
- Contre-mesures : CSP (Content Security Policy), input sanitization, output encoding

**Autres attaques :**
- CSRF (Cross-Site Request Forgery)
- SSRF (Server-Side Request Forgery)
- LFI/RFI (File Inclusion)
- XXE (XML External Entity)
- IDOR (Insecure Direct Object Reference)
- Unvalidated redirects/forwards

**Outils :**
- Burp Suite Community (Proxy, Repeater, Intruder, Scanner)
- OWASP ZAP
- SQLMap, jSQL
- Dirb, Dirbuster, Gobuster, FFUF
- Nikto, Wapiti, Arachni

---

## MODULE 15 : HACKING DE BASES DE DONNÉES

**Bases de données :**
- MySQL, MariaDB, MSSQL, Oracle, PostgreSQL
- MongoDB, Redis, Cassandra (NoSQL)

**Attaques spécifiques :**
- SQL injection (voir Module 14)
- Authentification bypass (='or'1'='1)
- Extraction de mot de passe (mysql.user, sys.dm_exec_connections)
- XP_CMDSHELL (MSSQL : exécution de commandes système)
- UDF (User Defined Functions)
- NoSQL injection (MongoDB, JSON injection)

**Outils :**
- SQLMap, jSQL, NoSQLMap
- DBMS tools : MySQL Workbench, SSMS, PgAdmin
- Hash cracking spécifique (MSSQL : hash 0x0100 = MD5)

**Contre-mesures :**
- Prepared statements (requêtes paramétrées)
- Stored procedures (avec droits minimaux)
- WAF (Web Application Firewall)
- Least privilege principle (DROP USER, REVOKE)
- Encryption at rest (TDE, BitLocker)
- Auditing et logging

---

## MODULE 16 : HACKING SANS FIL

**Cryptographie Wi-Fi :**
- WEP (RC4 - 64/128 bits : cassé en minutes)
- WPA (TKIP/RC4 - vulnérable)
- WPA2 (AES/CCMP - vulnérable via KRACK)
- WPA3 (SAE/Opportunistic Wireless Encryption - plus sécurisé)
- 802.1X / RADIUS (Enterprise)
- PSK (Pre-Shared Key) vs Enterprise

**Attaques :**
- WEP cracking (Aircrack-ng, 5-10 min de paquets)
- WPA/WPA2 cracking (4-way handshake capture + dictionnaire)
- PMKID attack (sans client)
- KRACK attack (CVE-2017-13077 à 13088)
- Evil Twin (AP rogue avec SSID identique)
- Rogue AP (AP non autorisé)
- Deauthentication attack (aireplay-ng -0)
- Beacon flood, Probe request flood

**Bluetooth :**
- Bluejacking (messages non sollicités)
- Bluesnarfing (vol de données)
- Bluebugging (contrôle du téléphone)
- Blueborne (CVE-2017-0781)
- Outils : BlueZ, Bluesnarfer, Bluelog

**RFID/NFC :**
- Cloning, skimming
- Mifare Classic (cassable avec Proxmark3)
- Outils : Proxmark3, MFCUK, MFOC

**Outils :**
- Aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng)
- Aircrack-ng, Reaver (WPS), PixieWPS
- Wifite, Kismet, Wireshark
- Bettercap (capture, évil twin)
- MDK3, MDK4
- Fern Wi-Fi Cracker, Fern WPS

**Contre-mesures :**
- WPA3/AES
- 802.1X / RADIUS
- WIPS (Wireless Intrusion Prevention System)
- Switch to Enterprise mode
- Désactiver WPS
- MAC filtering (peu efficace, facile à contourner)
- VPN obligatoire sur Wi-Fi

---

## MODULE 17 : HACKING MOBILE

**Plateformes :**
- Android (Linux kernel, APK, ART/Dalvik)
- iOS (XNU kernel, Mach-O, IPA, Objective-C/Swift)

**Android :**
- Rooting (Magisk, SuperSU)
- APK reverse engineering (APKTool, jadx-gui, dex2jar, JD-GUI)
- MobSF (Mobile Security Framework)
- Drozer (framework d'attaque Android)
- Analyse de permissions Android
- ADB (Android Debug Bridge)
- Attaques : malwares, phishing SMS, interception, repackaging

**iOS :**
- Jailbreak (checkra1n, unc0ver, Taurine)
- IPA reverse (class-dump, hopper, Ghidra)
- Objection (dynamic instrumentation)
- iOS security : sandbox, code signing, ASLR, data protection
- Attaques : phishing iOS, malicious profiles, sideloading via Cydia Impactor

**Sécurité mobile :**
- OWASP Mobile Top 10
- MSTG (Mobile Security Testing Guide)
- Android Keystore, iOS Keychain
- SSL Pinning, certificate transparency
- Root/jailbreak detection
- Data storage security (SharedPreferences, NSUserDefaults)

---

## MODULE 18 : IOT ET OT HACKING

**IoT (Internet of Things) :**
- Architectures IoT (device-gateway-cloud)
- Protocoles : MQTT, CoAP, ZigBee, Z-Wave, BLE, 6LoWPAN
- Attaques : firmware analysis, hardware exploitation (UART, JTAG), side-channel
- Outils : Firmwalker, Binwalk, Shodan, Thingful

**Firmware analysis :**
- Firmware extraction (binwalk -Me)
- Filesystem analysis (SquashFS, JFFS2, YAFFS, UBIFS)
- Hardcoded credentials
- Backdoors, debug interfaces (UART, JTAG, SWD)

**OT/SCADA (Operational Technology) :**
- Protocoles : Modbus, DNP3, IEC 60870-5-104, IEC 61850, PROFINET
- Attaques : Modbus injection, DNP3 manipulation, Man-in-the-Middle SCADA
- Cibles : PLC (Programmable Logic Controller), RTU, HMI
- Outils : ModbusPal, Modscan, ScadaBR, OpenPLC
- Exemples : Stuxnet, TRITON, Industroyer

**Contre-mesures IoT/OT :**
- Segmentation réseau (Purdue Model for ICS)
- OPC UA security
- Firmware signing
- Secure boot
- Hardware security modules (HSM / TPM)
- NIST SP 800-82 (Guide to ICS Security)

---

## MODULE 19 : CLOUD COMPUTING

**Fournisseurs :**
- Amazon Web Services (AWS)
- Microsoft Azure
- Google Cloud Platform (GCP)

**Attaques AWS :**
- S3 bucket misconfiguration (public read/write)
- IAM privilege escalation (PassRole, CreatePolicyVersion)
- EC2 metadata service abuse (169.254.169.254)
- Lambda injection
- CloudTrail evasion
- Outils : Pacu, ScoutSuite, CloudSploit

**Attaques Azure :**
- Azure AD misconfiguration
- Key Vault secrets extraction
- Managed identity abuse
- Storage account exposure
- Outils : Stormspotter, MicroBurst, AzureHound

**Attaques GCP :**
- GCS bucket misconfiguration
- IAM roles abuse
- Cloud Functions injection
- Outils : GCPBucketBrute, GCP-IAM-Exploiter

**Container security :**
- Docker : image vulnerability, privilege escalation (--privileged), host mount
- Kubernetes : etcd exposure, RBAC misconfiguration, dashboard exposure, kubelet API
- Outils : Trivy, Kube-hunter, Kube-bench, Falco

**Serverless :**
- AWS Lambda, Azure Functions, Google Cloud Functions
- Event injection, dependency poisoning (supply chain)
- Logging et monitoring gaps

**OWASP Cloud Top 10 :**
1. IAM misconfiguration
2. Insecure interfaces/APIs
3. Misconfiguration
4. Data exposure
5. Limited visibility
6. Denial of Service
7. Shared technology vulnerabilities
8. Supply chain vulnerabilities
9. Cloud provider lock-in
10. Compliance risks

---

## MODULE 20 : CRYPTOGRAPHIE

**Chiffrement symétrique :**
- DES (56 bits - obsolète)
- 3DES (112 bits - déprécié)
- AES (128, 192, 256 bits - standard actuel)
- Blowfish, Twofish, RC4 (obsolète pour données modernes)
- Modes : ECB (faible), CBC, CFB, OFB, CTR, GCM (authentifié)

**Chiffrement asymétrique :**
- RSA (1024 bits obsolète, 2048/4096 recommandé)
- Diffie-Hellman (échange de clés)
- ECC (Elliptic Curve Cryptography) - 256 bits = ~RSA 3072
- DSA, ElGamal

**Fonctions de hachage :**
- MD5 (128 bits - cassé)
- SHA-1 (160 bits - cassé, collisions possibles)
- SHA-2 (SHA-256, SHA-384, SHA-512 - standard actuel)
- SHA-3 (standard le plus récent)
- RIPEMD-160 (utilisé dans Bitcoin)

**Attaques cryptographiques :**
- Brute force
- Rainbow tables (compromis temps-mémoire)
- Chosen plaintext / ciphertext attacks
- Padding Oracle attack (ex: CVE-2013-4790)
- Collision attack (SHA-1, MD5)
- Birthday attack (anniversaire paradoxe)
