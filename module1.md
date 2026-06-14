# 🛡️ CEH v12 — MODULE 1 : INTRODUCTION À L'ETHICAL HACKING
### Guide pédagogique complet | ML | exploit4040

---

## 📌 PARTIE 1 : QU'EST-CE QUE LA CYBERSÉCURITÉ ?

Avant de parler d'ethical hacking, il faut poser les bases.

La **cybersécurité** c'est l'ensemble des pratiques, technologies et processus conçus pour **protéger les systèmes informatiques, les réseaux et les données** contre les attaques, les dommages ou les accès non autorisés.

Imagine une banque. Elle a des coffres, des gardiens, des caméras, des codes secrets. La cybersécurité c'est exactement pareil, mais dans le monde numérique. Ton système informatique est la banque, et toi l'ethical hacker tu es le **testeur de sécurité** engagé pour trouver les failles avant que les vrais voleurs ne le fassent.

---

## 📌 PARTIE 2 : LES TYPES DE HACKERS

Le mot "hacker" est souvent mal compris. Il ne veut pas dire criminel. Il désigne quelqu'un qui a une **maîtrise technique profonde** des systèmes. Ce qui différencie les hackers c'est leur **intention** et leur **autorisation**.

---

### 🎩 White Hat (Chapeau Blanc)
C'est le **hacker éthique légal**. Il travaille avec la permission de l'organisation cible. Son but : trouver les vulnérabilités pour les corriger.

> Exemple : Tu es embauché par une entreprise pour tester leur système. Tu as un contrat, une autorisation écrite. Tu es un White Hat.

C'est le rôle du **CEH**. C'est ce que tu prépares.

---

### 🎩 Black Hat (Chapeau Noir)
C'est le **cybercriminel**. Il attaque sans autorisation, pour voler des données, extorquer de l'argent, ou causer des dommages. Il viole la loi.

> Exemple : WannaCry en 2017 — des hackers Black Hat ont infecté des centaines de milliers d'ordinateurs dans 150 pays avec un ransomware.

---

### 🎩 Grey Hat (Chapeau Gris)
Entre les deux. Il peut pirater **sans autorisation** mais sans mauvaise intention. Parfois il signale la faille après l'avoir exploitée, parfois il demande une compensation.

> Exemple : Un Grey Hat découvre une faille dans le site d'une grande entreprise, l'exploite pour prouver qu'elle existe, puis contacte l'entreprise pour la vendre ou la signaler.

Légalement : toujours **illégal**, même sans mauvaise intention.

---

### 🎩 Script Kiddie
C'est quelqu'un qui utilise des **outils créés par d'autres** sans comprendre comment ils fonctionnent. Pas de vraie compétence technique. C'est le niveau 0.

> Exemple : Télécharger un outil de DDoS trouvé sur YouTube et l'utiliser sur un serveur de jeu. Aucune compréhension. Juste copier-coller.

---

### 🎩 Hacktivist
Hacker motivé par une **idéologie politique ou sociale**. Il utilise ses compétences pour défendre une cause.

> Exemple : Anonymous — groupe hacktivist connu pour attaquer des gouvernements, des corporations, et des organisations qu'ils considèrent injustes.

---

### 🎩 State-Sponsored Hacker
Hacker financé et dirigé par un **gouvernement**. Les attaques sont très sophistiquées, avec des ressources énormes.

> Exemple : Le groupe Lazarus (Corée du Nord), APT28 / Fancy Bear (Russie), APT41 (Chine).

---

### 🎩 Insider Threat
La menace **de l'intérieur**. Un employé malveillant, ou quelqu'un dont les accès ont été compromis. Très dangereux car il connaît déjà le système.

> Exemple : Un administrateur système mécontent qui supprime des bases de données avant de partir.

---

## 📌 PARTIE 3 : LES 5 PHASES D'UN TEST D'INTRUSION

C'est **le cœur du Module 1**. Le CEH te demande de connaître ce processus par cœur. Chaque attaque — qu'elle soit éthique ou criminelle — suit ces 5 phases.

---

```
PHASE 1 → PHASE 2 → PHASE 3 → PHASE 4 → PHASE 5
Reconnaissance → Scanning → Gaining Access → Maintaining Access → Covering Tracks
```

---

### 🔍 PHASE 1 : Reconnaissance (Footprinting)

C'est la phase de **collecte d'informations**. Tu n'attaques rien encore. Tu observes, tu étudies ta cible.

Deux types :

**Passive** : Tu collectes des informations **sans interagir directement** avec la cible. La cible ne sait pas que tu existes.
- Google Dorks
- WHOIS lookup
- Réseaux sociaux (LinkedIn, Facebook)
- Shodan.io

**Active** : Tu interagis **directement** avec la cible (ping, scan DNS). Légèrement détectable.
- Nmap ping sweep
- DNS zone transfer

> Analogie : Avant de cambrioler une maison, le voleur observe le quartier, note les heures de départ/arrivée, repère les caméras. Il ne touche rien encore. C'est la reconnaissance.

---

### 🔍 PHASE 2 : Scanning

Maintenant tu interagis avec la cible pour trouver des **portes ouvertes** (ports ouverts, services actifs, OS utilisé, vulnérabilités).

Outils : **Nmap, Masscan, Nessus, OpenVAS**

Types de scanning :
- **Port scanning** → quels ports sont ouverts ?
- **Vulnerability scanning** → quelles vulnérabilités existent ?
- **Network scanning** → quels appareils sont sur le réseau ?

> Analogie : Le cambrioleur s'approche maintenant de la maison. Il teste chaque fenêtre, chaque porte. Il cherche ce qui est mal fermé.

---

### 🔍 PHASE 3 : Gaining Access (Exploitation)

Tu exploites une vulnérabilité trouvée pour **entrer dans le système**. C'est ici que tu utilises Metasploit, des exploits, des attaques par dictionnaire, des injections SQL...

> Analogie : Le cambrioleur a trouvé une fenêtre ouverte. Il entre.

C'est la phase la plus "spectaculaire" mais elle repose entièrement sur la qualité des phases 1 et 2. **Sans bonne reconnaissance, pas de bonne exploitation.**

---

### 🔍 PHASE 4 : Maintaining Access (Persistance)

Une fois entré, tu t'assures de **rester** dans le système même après un redémarrage. Tu installes une backdoor, un rootkit, un RAT (Remote Access Trojan).

Pourquoi ? Dans un vrai test d'intrusion, tu veux démontrer qu'un attaquant peut revenir. Dans une vraie attaque criminelle, le hacker veut garder le contrôle pour exfiltrer des données progressivement.

> Analogie : Le cambrioleur copie les clés de la maison pour pouvoir revenir quand il veut.

---

### 🔍 PHASE 5 : Covering Tracks (Effacement des traces)

Tu **supprimes toutes les preuves** de ton passage. Logs système, historique bash, événements Windows, fichiers temporaires.

Commandes courantes :
```bash
history -c          # Efface l'historique bash
echo "" > /var/log/auth.log   # Vide le log d'authentification
```

> Analogie : Le cambrioleur nettoie ses empreintes digitales, remet tout en place.

**Note importante CEH :** Dans un pentest éthique, tu ne couvres PAS tes traces. Tu documentes tout au contraire pour le rapport final.

---

## 📌 PARTIE 4 : LA TRIADE CIA

C'est le **fondement de toute la cybersécurité**. Trois principes. Tu dois les connaître dans le sang.

---

### 🔒 C — Confidentialité (Confidentiality)

L'information ne doit être accessible qu'aux **personnes autorisées**.

> Violation : Un hacker vole la base de données des clients d'une banque. Les données étaient confidentielles, elles ne l'ont plus été.

Mécanismes : Chiffrement, contrôle d'accès, VPN, authentification.

---

### 🔒 I — Intégrité (Integrity)

L'information ne doit pas être **modifiée** sans autorisation. Elle doit être exacte et complète.

> Violation : Un hacker modifie le montant d'un virement bancaire en transit. L'intégrité a été compromise.

Mécanismes : Hash (MD5, SHA-256), signatures numériques, checksums.

---

### 🔒 A — Disponibilité (Availability)

Les systèmes et données doivent être **accessibles quand on en a besoin**.

> Violation : Une attaque DDoS met hors ligne le site d'une entreprise pendant 24h. La disponibilité a été compromise.

Mécanismes : Load balancers, sauvegardes, plans de continuité (BCP/DRP).

---

### 📊 Le triangle CIA en pratique

| Attaque | CIA violée |
|---|---|
| Vol de données | Confidentialité |
| Modification de fichiers | Intégrité |
| DDoS | Disponibilité |
| Ransomware | Intégrité + Disponibilité |
| Phishing | Confidentialité |

---

## 📌 PARTIE 5 : AAA — AUTHENTIFICATION, AUTORISATION, COMPTABILITÉ

---

### 🔑 Authentication (Authentification)
**"Qui es-tu ?"**

Vérifier l'identité d'un utilisateur. Trois facteurs :
- **Ce que tu sais** → mot de passe, PIN, question secrète
- **Ce que tu as** → carte, téléphone (OTP), token physique
- **Ce que tu es** → empreinte digitale, reconnaissance faciale (biométrie)

Le **MFA (Multi-Factor Authentication)** combine au moins 2 de ces facteurs.

---

### 🔑 Authorization (Autorisation)
**"Qu'as-tu le droit de faire ?"**

Après authentification, on vérifie tes **permissions**. Exemple : tu t'es connecté (authentification), mais tu n'as pas le droit d'accéder au dossier RH (autorisation refusée).

Modèles courants :
- **RBAC** (Role-Based Access Control) → accès par rôle
- **DAC** (Discretionary Access Control) → le propriétaire décide
- **MAC** (Mandatory Access Control) → politique centrale imposée

---

### 🔑 Accounting (Comptabilité / Audit)
**"Qu'as-tu fait ?"**

Traçabilité complète des actions. Qui s'est connecté, quand, depuis où, qu'a-t-il fait. C'est ce qui permet les investigations forensiques après un incident.

> Outils : Syslog, Windows Event Viewer, SIEM (Splunk, ELK Stack)

---

## 📌 PARTIE 6 : NON-RÉPUDIATION

La **non-répudiation** garantit qu'une personne **ne peut pas nier** avoir effectué une action.

> Exemple : Tu envoies un email signé numériquement. Si quelqu'un le reçoit, tu ne peux pas dire "ce n'est pas moi". Ta signature cryptographique prouve que c'est toi.

Mécanismes : Signatures numériques (RSA, DSA, ECDSA), journaux d'audit signés, PKI (Public Key Infrastructure).

---

## 📌 PARTIE 7 : LES TYPES DE CONTRÔLES DE SÉCURITÉ

---

| Type | Définition | Exemple |
|---|---|---|
| **Préventif** | Empêche l'attaque | Pare-feu, chiffrement, contrôle d'accès |
| **Détective** | Détecte l'attaque en cours | IDS, antivirus, logs |
| **Correctif** | Répare après l'attaque | Backup/restore, patch |
| **Dissuasif** | Décourage l'attaquant | Caméras, panneaux d'avertissement |
| **Compensatoire** | Compense une faiblesse | Double validation si MFA impossible |
| **Directif** | Impose une règle | Politiques de sécurité, procédures |

---

## 📌 PARTIE 8 : LES CADRES LÉGAUX ET RÉGLEMENTAIRES

Le CEH insiste sur le fait qu'un ethical hacker travaille **toujours dans un cadre légal**. Voici les principaux frameworks.

---

### 📜 ISO/IEC 27001
Standard international de **gestion de la sécurité de l'information** (ISMS). Il définit les bonnes pratiques pour protéger les données d'une organisation.

---

### 📜 PCI DSS
(Payment Card Industry Data Security Standard)
Obligatoire pour toute organisation qui **traite des données de cartes bancaires**. 12 exigences principales.

---

### 📜 HIPAA
(Health Insurance Portability and Accountability Act)
Loi américaine protégeant les **données médicales des patients**. Applicable aux hôpitaux, assurances, prestataires de santé.

---

### 📜 GDPR
(General Data Protection Regulation)
Règlement européen sur la **protection des données personnelles**. Applicable à toute organisation traitant des données de citoyens européens. Amendes jusqu'à 4% du chiffre d'affaires mondial.

---

### 📜 SOX
(Sarbanes-Oxley Act)
Loi américaine sur la **transparence financière** des entreprises cotées en bourse. Impose des contrôles stricts sur les systèmes financiers.

---

## 📌 PARTIE 9 : RULES OF ENGAGEMENT (RoE)

Avant tout pentest, l'ethical hacker et le client signent les **Rules of Engagement**. C'est le document le plus important.

Il définit :
- ✅ **Scope** : quels systèmes sont autorisés à tester
- ✅ **Période** : quand le test peut être effectué
- ✅ **Méthodes** : quelles techniques sont autorisées
- ✅ **Contacts d'urgence** : qui appeler si quelque chose tourne mal
- ✅ **Limitations** : ce qui est strictement interdit

> Sans RoE signé, tu es un criminel. Avec RoE signé, tu es un professionnel.

**Types de pentests selon le niveau de connaissance :**

| Type | Connaissance préalable |
|---|---|
| **Black Box** | Aucune information. Tu attaques comme un hacker externe. |
| **White Box** | Accès total (code source, schémas réseau, credentials). |
| **Grey Box** | Informations partielles. Le plus réaliste. |

---

## 📌 PARTIE 10 : LES TERMES FONDAMENTAUX CEH

---

### 🔵 CVE — Common Vulnerabilities and Exposures
Identifiant unique pour chaque vulnérabilité connue publiquement.

Format : **CVE-ANNÉE-NUMÉRO**

> Exemple : CVE-2021-44228 = Log4Shell (vulnérabilité critique dans Apache Log4j)

Base de données : **nvd.nist.gov**

---

### 🔵 CVSS — Common Vulnerability Scoring System (v3.1)
Système de **notation des vulnérabilités** de 0 à 10.

| Score | Criticité |
|---|---|
| 0.0 | Aucune |
| 0.1 – 3.9 | Faible |
| 4.0 – 6.9 | Moyenne |
| 7.0 – 8.9 | Haute |
| 9.0 – 10.0 | Critique |

Le vecteur CVSS ressemble à ça :
```
AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
```

Décryptage :
- **AV:N** → Attack Vector: Network (exploitable à distance)
- **AC:L** → Attack Complexity: Low (facile)
- **PR:N** → Privileges Required: None (pas besoin d'être connecté)
- **UI:N** → User Interaction: None (pas besoin que la victime clique)
- **C:H / I:H / A:H** → Impact sur Confidentialité/Intégrité/Disponibilité : High

---

### 🔵 CWE — Common Weakness Enumeration
Catalogue des **types de faiblesses** dans le code et l'architecture.

> Différence CVE vs CWE :
> - **CWE** = le type de faiblesse (ex: CWE-79 = XSS en général)
> - **CVE** = l'instance spécifique (ex: CVE-2023-XXXX = cette faille XSS précise dans ce logiciel)

---

### 🔵 APT — Advanced Persistent Threat
Attaque **longue durée, très sophistiquée**, souvent étatique. L'attaquant entre discrètement et reste des mois voire des années à exfiltrer des données sans être détecté.

Caractéristiques :
- Ciblée (pas aléatoire)
- Persistante (longue durée)
- Furtive (évite la détection)
- Ressources importantes (État ou crime organisé)

> Exemples : APT28 (Russie), APT41 (Chine), Lazarus Group (Corée du Nord)

---

### 🔵 Zero-Day Vulnerability
Vulnérabilité **inconnue du fabricant** et donc sans patch disponible. Le terme "zero-day" signifie que le fabricant a eu **zéro jour** pour réagir.

> Très précieuse sur le marché noir. Peut valoir des millions de dollars.

Timeline :
```
Découverte par hacker → Exploitation active → Fabricant informé → Patch publié
     (zero-day)                                (N-day)
```

---

## 📌 PARTIE 11 : ANALYSE DE RISQUE

La gestion des risques c'est le **pilier stratégique** de toute organisation sécurisée.

**Formule fondamentale :**
```
RISQUE = MENACE × VULNÉRABILITÉ × IMPACT
```

---

### Concepts clés :

**Actif (Asset)** : Ce qu'on protège. Données clients, serveurs, réputation.

**Menace (Threat)** : Ce qui peut causer un dommage. Hacker, incendie, erreur humaine.

**Vulnérabilité (Vulnerability)** : La faiblesse exploitable. Port ouvert, mot de passe faible.

**Exploit** : Le moyen d'exploiter la vulnérabilité. Code, technique, outil.

**Impact** : Les conséquences si l'attaque réussit. Perte financière, réputation, données.

---

### Les 4 réponses au risque :

| Réponse | Définition | Exemple |
|---|---|---|
| **Éviter** | Supprimer l'activité risquée | Ne pas connecter un système critique à internet |
| **Réduire** | Mettre en place des contrôles | Installer un pare-feu, faire des patchs |
| **Transférer** | Partager le risque | Souscrire une cyber-assurance |
| **Accepter** | Vivre avec le risque résiduel | Risque faible dont le coût de correction > impact |

---

## 📌 PARTIE 12 : LES VECTEURS D'ATTAQUE COURANTS

Pour le CEH, tu dois reconnaître rapidement le vecteur d'attaque utilisé.

| Vecteur | Description |
|---|---|
| **Phishing** | Email frauduleux pour voler des credentials |
| **Malware** | Logiciel malveillant (virus, trojan, ransomware) |
| **Exploitation de vulnérabilité** | Exploiter un bug non patché |
| **Ingénierie sociale** | Manipuler psychologiquement un humain |
| **Insider threat** | Attaque depuis l'intérieur |
| **Physical access** | Accès physique au matériel |
| **Supply chain** | Compromettre un fournisseur de confiance |
| **Credential stuffing** | Utiliser des mots de passe volés ailleurs |

---

## 📌 RÉSUMÉ FINAL — CE QUE L'EXAMEN VA TESTER

```
✅ Les 7 types de hackers et leurs motivations
✅ Les 5 phases du pentest dans l'ordre
✅ CIA Triad — définition et exemples d'attaques pour chaque pilier
✅ AAA — distinction claire entre les 3 concepts
✅ CVE vs CVSS vs CWE — ne pas les confondre
✅ Score CVSS — lire un vecteur et identifier la criticité
✅ APT — caractéristiques distinctives
✅ Zero-day — définition et timeline
✅ Black/White/Grey box — différences
✅ RoE — pourquoi c'est indispensable
✅ Les 5 types de contrôles
✅ Les cadres légaux (ISO 27001, PCI DSS, GDPR, HIPAA, SOX)
```

---

## 🧪 QUESTIONS TYPE EXAMEN CEH — MODULE 1

**Q1 :** Un consultant en sécurité est engagé sans aucune information préalable sur le réseau cible. Quel type de pentest effectue-t-il ?
> **Réponse : Black Box**

**Q2 :** Une vulnérabilité a un score CVSS de 9.8. Quelle est sa criticité ?
> **Réponse : Critique**

**Q3 :** Quelle phase du pentest consiste à supprimer les logs système ?
> **Réponse : Phase 5 — Covering Tracks**

**Q4 :** Un attaquant reste discrètement dans un réseau pendant 8 mois pour exfiltrer des données. Ce type d'attaque s'appelle :
> **Réponse : APT (Advanced Persistent Threat)**

**Q5 :** Lequel des éléments suivants garantit qu'un utilisateur ne peut pas nier avoir effectué une action ?
> **Réponse : Non-répudiation**

**Q6 :** Une attaque DDoS affecte quel pilier de la CIA Triad ?
> **Réponse : Disponibilité (Availability)**

**Q7 :** Quel framework légal concerne spécifiquement les données de cartes bancaires ?
> **Réponse : PCI DSS**

---
