# 🔐 CryptoLab Pro — Laboratoire de Cryptographie Appliquée

> **6 TPs complets • 28+ algorithmes • Interface web premium • Applications réseau interactives**

Projet académique complet couvrant l'ensemble de la cryptographie moderne : du chiffrement de César au vote électronique homomorphe, avec une interface graphique web professionnelle et des applications réseau testables sur machines réelles.

---

## 📋 Table des matières

- [Installation rapide](#-installation-rapide)
- [Interface graphique](#-interface-graphique-web)
- [Structure du projet](#-structure-du-projet)
- [TP1 — Chiffres classiques](#tp1--chiffres-classiques)
- [TP2 — Chiffrement symétrique](#tp2--chiffrement-symétrique)
- [TP3 — Chiffrement asymétrique](#tp3--chiffrement-asymétrique)
- [TP4 — Fonctions de hachage](#tp4--fonctions-de-hachage)
- [TP5 — Signatures numériques](#tp5--signatures-numériques)
- [TP6 — Applications réseau](#tp6--applications-réseau)
- [Tests unitaires](#-tests-unitaires)
- [Guides détaillés TP6](#-guides-détaillés-tp6)
- [Dépendances](#-dépendances)
- [FAQ & Résolution de problèmes](#-faq--résolution-de-problèmes)

---

## 🚀 Installation rapide

### Prérequis

- **Python 3.10+**
- **pip** (gestionnaire de paquets)
- **Windows 10/11** ou Linux/macOS

### 3 étapes

```powershell
# 1. Se placer dans le dossier du projet
cd chemin\vers\Crypto_Project

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Lancer l'interface graphique
python app.py
# → Ouvrir http://localhost:5000 dans le navigateur
```

### Commande unique (PowerShell)

```powershell
pip install -r requirements.txt; $env:PYTHONIOENCODING='utf-8'; python app.py
```

---

## 🖥️ Interface graphique web

CryptoLab inclut une **interface web professionnelle** (Flask + HTML/CSS/JS) avec un thème dark premium.

```powershell
python app.py
# → http://localhost:5000
```

### Pages disponibles (20 pages interactives)

| TP | Pages | Fonctionnalités |
|:---|:------|:----------------|
| **TP1** | César, Vigenère, Hill, OTP | Chiffrer/déchiffrer/cryptanalyser en temps réel |
| **TP2** | RC4, DES/3DES, AES, NIST Finalists | Modes ECB/CBC/CTR, benchmark, 4 finalistes NIST |
| **TP3** | RSA, Diffie-Hellman, ElGamal, ECC, Hybride | Génération de clés, MITM, ECDH, RSA+AES-GCM |
| **TP4** | Hash/Avalanche, MD5 Collision | Effet avalanche, SHA-256 from scratch, collision réelle |
| **TP5** | RSA-PSS, ECDSA, ElGamal Sign, DSA | Signer, vérifier, détecter la falsification |
| **TP6** | WiFi Chat, Bluetooth Chat, TCP/TLS Chat, Vote Paillier | Chat chiffré temps réel PC↔Android + vote homomorphe |

> **Chaque bouton exécute le vrai code Python du TP** — pas de simulation JavaScript.

---

## 📁 Structure du projet

```
Crypto_Project/
│
├── app.py                          🖥️  Backend Flask (API REST pour tous les TPs)
├── templates/index.html            📄  Interface web (20 pages SPA)
├── static/
│   ├── style.css                   🎨  Thème dark premium
│   └── app.js                      ⚡  Logique frontend
│
├── tp1_classique/                  📚 TP1 : Chiffres classiques
│   ├── cesar.py                    → César + IC + force brute
│   ├── vigenere.py                 → Vigenère + Kasiski + cryptanalyse automatique
│   ├── hill.py                     → Hill 2×2/3×3 + attaque à clair connu
│   ├── otp.py                      → One-Time Pad + vulnérabilité réutilisation
│   └── attacks/                    → Brute force, analyse fréquentielle, Kasiski
│
├── tp2_symetrique/                 🔒 TP2 : Chiffrement symétrique
│   ├── rc4.py                      → RC4 : KSA/PRGA + biais statistique
│   ├── des_modes.py                → DES/3DES : ECB vs CBC (faiblesse visuelle)
│   ├── aes_modes.py                → AES-128/192/256 : ECB/CBC/CTR + benchmark
│   └── nist_finalists/             → Twofish, Serpent, RC6, MARS
│
├── tp3_asymetrique/                🗝️ TP3 : Chiffrement asymétrique
│   ├── diffie_hellman.py           → DH + dérivation AES
│   ├── mitm_attack.py              → Attaque Man-in-the-Middle complète
│   ├── rsa.py                      → RSA-OAEP 1024/2048/4096
│   ├── hybrid_rsa_aes.py           → RSA + AES-256-GCM (mode production)
│   ├── elgamal.py                  → ElGamal + non-déterminisme
│   └── ecc.py                      → ECDH P-256 + ECIES
│
├── tp4_hachage/                    #️⃣ TP4 : Hachage
│   ├── md5_demo.py                 → MD5 cassé + collision Wang & Yu (2004)
│   ├── sha256_impl.py              → SHA-256 FROM SCRATCH (validé)
│   ├── sha512_demo.py              → SHA-512 + HMAC-SHA256/512
│   └── benchmark.py                → Benchmark MD5/SHA-256/SHA-512
│
├── tp5_signatures/                 ✍️ TP5 : Signatures numériques
│   ├── rsa_pss.py                  → RSA-PSS (probabiliste)
│   ├── elgamal_sign.py             → ElGamal Sign + vuln nonce (hack PS3)
│   └── dsa_ecdsa.py                → DSA-2048 + ECDSA P-256/P-384
│
├── tp6_application/                🌐 TP6 : Applications réseau INTERACTIVES
│   ├── tcp/server.py + client.py   → Chat TCP/TLS sécurisé (TLSv1.3)
│   ├── bluetooth/bt_server.py      → Bluetooth AES-GCM (Windows compatible)
│   │           + bt_client.py
│   ├── wifi_chat/udp_server.py     → Chat UDP chiffré (broadcast WiFi)
│   │            + udp_client.py
│   └── vote_electronique/          → Vote Paillier homomorphe (serveur + clients)
│
├── docs/                           📖 Guides détaillés TP6
│   ├── TP6_1_TCP_TLS.md
│   ├── TP6_2_Bluetooth.md
│   ├── TP6_3_WiFi_Chat.md
│   └── TP6_4_Vote_Paillier.md
│
├── tests/                          🧪 39 tests unitaires pytest
├── utils/                          🔧 Helpers, benchmark, logger
├── outputs/                        📊 Graphiques générés
└── requirements.txt
```

---

## TP1 — Chiffres classiques

**Objectif** : Bases de la cryptographie et cryptanalyse.

| # | Exercice | Fichier | Apprentissage |
|---|----------|---------|---------------|
| 1.1 | César | `cesar.py` | Décalage, IC ≈ 0.065 (français), force brute 26 clés |
| 1.2 | Vigenère | `vigenere.py` | Poly-alphabétique, Kasiski → longueur de clé, IC par sous-séquences |
| 1.3 | Hill | `hill.py` | Matrices mod 26, inversibilité, attaque à clair connu |
| 1.4 | OTP | `otp.py` | Sécurité parfaite, danger mortel de la réutilisation |

```powershell
python tp1_classique/cesar.py          # Chiffrement + cryptanalyse automatique
python tp1_classique/vigenere.py       # Vigenère + Kasiski
python tp1_classique/hill.py           # Matrices + attaque
python tp1_classique/otp.py            # XOR + démo vulnérabilité
```

---

## TP2 — Chiffrement symétrique

**Objectif** : Chiffrements par flot et par blocs, modes opératoires, compétition NIST.

| # | Exercice | Fichier | Apprentissage |
|---|----------|---------|---------------|
| 2.1 | RC4 | `rc4.py` | KSA/PRGA, biais octet 2, vulnérabilité WEP |
| 2.2 | DES/3DES | `des_modes.py` | Feistel 16 tours, ECB vs CBC (patterns visibles) |
| 2.3 | AES | `aes_modes.py` | AES-128/192/256, ECB/CBC/CTR, nonce-reuse |
| 2.4 | NIST | `nist_finalists/` | Twofish, Serpent, RC6, MARS — pourquoi Rijndael a gagné |

```powershell
python tp2_symetrique/rc4.py
python tp2_symetrique/des_modes.py
python tp2_symetrique/aes_modes.py
python tp2_symetrique/nist_finalists/twofish_demo.py
```

> ⚠️ **Ne JAMAIS utiliser ECB** en production — les motifs du clair restent visibles dans le chiffré.

---

## TP3 — Chiffrement asymétrique

**Objectif** : Échange de clés, chiffrement à clé publique, attaques, mode hybride.

| # | Exercice | Fichier | Apprentissage |
|---|----------|---------|---------------|
| 3.1 | Diffie-Hellman | `diffie_hellman.py` | Échange de clés, dérivation AES |
| 3.1b | MITM | `mitm_attack.py` | Mallory intercepte et remplace les clés publiques |
| 3.2 | RSA | `rsa.py` | RSA-OAEP, benchmark multi-tailles, export PEM |
| 3.2b | Hybride | `hybrid_rsa_aes.py` | RSA chiffre la clé AES, AES chiffre les données |
| 3.3 | ElGamal | `elgamal.py` | Non-déterministe : `E(M)₁ ≠ E(M)₂` |
| 3.4 | ECC | `ecc.py` | Courbes elliptiques, ECDH P-256, ECIES |

```powershell
python tp3_asymetrique/diffie_hellman.py
python tp3_asymetrique/rsa.py
python tp3_asymetrique/elgamal.py
python tp3_asymetrique/ecc.py
```

---

## TP4 — Fonctions de hachage

**Objectif** : Propriétés des fonctions de hachage, implémentation SHA-256, collisions.

| # | Exercice | Fichier | Apprentissage |
|---|----------|---------|---------------|
| 4.1 | MD5 | `md5_demo.py` | **MD5 est cassé !** Collision Wang & Yu (2004) démontrée |
| 4.2 | SHA-256 | `sha256_impl.py` | Implémentation from scratch, validée contre `hashlib` |
| 4.3 | SHA-512 | `sha512_demo.py` | SHA-512 + HMAC-SHA256/512 |
| 4.4 | Benchmark | `benchmark.py` | Comparaison performances MD5 vs SHA-256 vs SHA-512 |

```powershell
python tp4_hachage/md5_demo.py         # Collision MD5 réelle
python tp4_hachage/sha256_impl.py      # SHA-256 from scratch
python tp4_hachage/benchmark.py        # Graphiques de performance
```

> **Effet avalanche** : changer 1 bit d'entrée → ~50% des bits de sortie changent.

---

## TP5 — Signatures numériques

**Objectif** : Signer, vérifier, détecter la falsification, comprendre les vulnérabilités.

| # | Exercice | Fichier | Apprentissage |
|---|----------|---------|---------------|
| 5.1 | RSA-PSS | `rsa_pss.py` | Non-déterministe : `Sign(M)₁ ≠ Sign(M)₂` |
| 5.2 | ElGamal | `elgamal_sign.py` | Nonce réutilisé → clé privée compromise (hack PS3, 2010) |
| 5.3 | DSA/ECDSA | `dsa_ecdsa.py` | DSA-2048, ECDSA P-256, comparaison taille/vitesse |

```powershell
python tp5_signatures/rsa_pss.py
python tp5_signatures/elgamal_sign.py
python tp5_signatures/dsa_ecdsa.py
```

---

## TP6 — Applications réseau

**Objectif** : Utiliser la cryptographie dans des applications réseau **réelles et interactives** — accessible depuis l'interface web, testable entre un PC et un Android sur le même réseau local.

> **NOUVEAU** : Toutes les applications TP6 sont désormais intégrées dans le site web. Aucun terminal requis — ouvrez simplement `http://localhost:5000` et naviguez vers TP6.

---

### 🌐 Accès Web (recommandé)

```powershell
python app.py
# → http://localhost:5000  →  sidebar TP6
```

**4 applications dans la sidebar TP6 :**

| # | Application | Room SocketIO | Chiffrement | PIN/Mot de passe |
|---|-------------|--------------|-------------|-----------------|
| 📡 | **WiFi Chat** | `tp6-wifi` | AES-256-GCM | `CryptoLab2024` (défaut) |
| 🔵 | **Bluetooth Chat** | `tp6-bluetooth` | AES-256-GCM | `1234` (PIN défaut) |
| 🔒 | **TCP/TLS Chat** | `tp6-tcp` | AES-256-GCM | `TLS-Secret-2024` (défaut) |
| 🗳️ | **Vote Paillier** | — | Paillier homomorphe | — |

---

### 📡 TP6.1 — WiFi Chat (Interface Web)

Chat UDP chiffré, simulé via WebSockets sur le réseau local.

#### Étape par étape — PC (Ethernet) + Android (WiFi)

**1. Lancer le serveur sur le PC**
```powershell
cd Crypto_Project
python app.py
```
Le serveur affiche votre **IP LAN** :
```
[>] Reseau : http://192.168.100.49:5000   ← à noter
[>] Android: ouvrir http://192.168.100.49:5000 dans Chrome
```

**2. Ouvrir le pare-feu Windows** (si l'Android ne peut pas se connecter)
```powershell
netsh advfirewall firewall add rule name="CryptoLab" dir=in action=allow protocol=TCP localport=5000
```

**3. Sur le PC — rejoindre le chat**
- Ouvrir `http://127.0.0.1:5000` dans Chrome
- Sidebar → **WiFi Chat**
- Nom : `PC-Desktop` | Mot de passe : `CryptoLab2024`
- Cliquer **📡 Rejoindre WiFi Chat** → statut passe à 🟢 Connecté

**4. Sur l'Android — rejoindre le même chat**
- Connecter l'Android au **même routeur WiFi**
- Ouvrir Chrome Android → `http://192.168.100.49:5000`
- Sidebar → **WiFi Chat**
- Nom : `Android` | Mot de passe : `CryptoLab2024` (**identique**)
- Cliquer **📡 Rejoindre WiFi Chat**
- Les deux appareils apparaissent dans **Membres connectés**

**5. Chatter**
- Taper un message sur le PC → apparaît sur l'Android en temps réel
- Taper un message sur l'Android → apparaît sur le PC
- Chaque bulle affiche le badge **🔒 AES-256-GCM**
- Le panneau **Détails cryptographiques** montre le Nonce, Ciphertext et Tag pour chaque message

#### Architecture technique

```
PC Chrome                  Flask Server (app.py)         Android Chrome
   |                              |                              |
   |-- join_chat(tp6-wifi) ------>|                              |
   |                              |<--- join_chat(tp6-wifi) -----|
   |                              |                              |
   | [PBKDF2 → clé AES-256]       |                    [PBKDF2 → clé AES-256]
   | [AES-GCM encrypt(msg)]       |                              |
   |-- send_message(blob) ------->|                              |
   |                              |--- message_received(blob) -->|
   |                              |              [AES-GCM decrypt → texte clair]
```

> **Confidentialité** : Le serveur Flask **ne voit jamais le texte clair**. Il relaye uniquement le blob chiffré opaque. La clé AES est dérivée côté client (navigateur) et n'est jamais envoyée au serveur.

---

### 🔵 TP6.2 — Bluetooth Chat (Interface Web)

Simulation du protocole Bluetooth RFCOMM avec appairage par PIN, chiffrement AES-256-GCM.

**Différence par rapport au WiFi Chat :**
- Le **PIN d'appairage** remplace le mot de passe (simule le pairing Bluetooth)
- Le salt PBKDF2 est différent (`BluetoothPairingSalt`) → clé AES différente
- Les deux appareils doivent entrer le **même PIN** (ex: `1234`)

**Utilisation :**
- Sidebar → **Bluetooth Chat**
- Nom : `Mon-PC` | PIN : `1234`
- Sur Android : Nom : `Galaxy-S24` | PIN : `1234`
- Cliquer **🔵 Appairer et Rejoindre**

**Comportement cryptographique :**
```
PIN "1234"  →  PBKDF2-SHA256 (100 000 itérations)  →  Clé AES-256
Message     →  AES-256-GCM(Nonce 96-bit)            →  Ciphertext + Tag 128-bit
```

---

### 🔒 TP6.3 — TCP/TLS Chat (Interface Web)

Simulation d'un canal TCP/TLS avec clé pré-partagée et chiffrement end-to-end AES-256-GCM.

**Différence :**
- Utilise le salt `TLSSalt2024` pour la dérivation PBKDF2
- Simule un échange de clé TLS pré-négociée
- Le serveur affiche explicitement qu'il ne peut pas lire les messages

**Utilisation :**
- Sidebar → **TCP/TLS Chat**
- Identifiant : `Client-PC` | Clé TLS : `TLS-Secret-2024`
- Sur Android : Identifiant : `Client-Android` | **même clé TLS**
- Cliquer **🔒 Connexion TLS**

---

### 🗳️ TP6.4 — Vote Paillier (Interface Web)

Vote électronique homomorphe : le serveur additionne les votes chiffrés **sans jamais voir les votes individuels**.

**Utilisation :**
- Sidebar → **Vote Paillier**
- Cliquer sur les boutons OUI/NON pour configurer les votes
- Cliquer **🗳️ Dépouiller (Paillier)**
- Le résultat est calculé sur des données chiffrées et révèle uniquement le total

---

### 🖥️ Mode terminal (scripts standalone)

Les scripts Python originaux restent disponibles pour une utilisation en ligne de commande :

```powershell
# TCP/TLS (port 9443)
python tp6_application/tcp/server.py
python tp6_application/tcp/client.py 127.0.0.1

# Bluetooth simulé (port 9800)
python tp6_application/bluetooth/bt_server.py
python tp6_application/bluetooth/bt_client.py 127.0.0.1
python tp6_application/bluetooth/bt_server.py --simulate   # sans réseau

# WiFi UDP chiffré (port 9999)
python tp6_application/wifi_chat/udp_server.py
python tp6_application/wifi_chat/udp_client.py 127.0.0.1

# Vote Paillier (port 9500)
python tp6_application/vote_electronique/vote_server.py
python tp6_application/vote_electronique/vote_client.py 127.0.0.1
```

> 📖 **Guides détaillés** : voir le dossier `docs/` pour les schémas réseau et instructions pas à pas.

---

## 🧪 Tests unitaires

```powershell
# Tous les tests (39)
python -m pytest tests/ -v

# Un TP spécifique
python -m pytest tests/test_tp1.py -v
python -m pytest tests/test_tp3.py -v
```

**Résultat attendu :** `39 passed` ✅

---

## 📖 Guides détaillés TP6

Chaque exercice réseau dispose d'un guide complet dans le dossier `docs/` :

| Guide | Contenu |
|-------|---------|
| [`TP6_1_TCP_TLS.md`](docs/TP6_1_TCP_TLS.md) | Configuration réseau, pare-feu, VM bridge, certificats |
| [`TP6_2_Bluetooth.md`](docs/TP6_2_Bluetooth.md) | 3 modes : simulation, 2 PC Windows, PC+smartphone |
| [`TP6_3_WiFi_Chat.md`](docs/TP6_3_WiFi_Chat.md) | Broadcast UDP, Wireshark, chat bidirectionnel |
| [`TP6_4_Vote_Paillier.md`](docs/TP6_4_Vote_Paillier.md) | Homomorphie additive, mode local et réseau |

---

## 📦 Dépendances

| Paquet | Usage |
|--------|-------|
| `cryptography` | RSA, ECDSA, ECDH, TLS, certificats X.509 |
| `pycryptodome` | AES, DES, 3DES, RC4, GCM |
| `sympy` | Arithmétique symbolique (primalité, factorisation) |
| `matplotlib` | Graphiques (benchmark, biais RC4, ECB vs CBC) |
| `numpy` | Manipulation d'images |
| `phe` | Chiffrement homomorphe Paillier |
| `flask` | Interface graphique web |
| `flask-socketio` | WebSockets temps réel (TP6 Chat) |
| `eventlet` | Serveur async pour Flask-SocketIO |
| `pytest` | Tests unitaires |

> **Node-forge** (librairie JS) est chargé automatiquement depuis CDN — elle remplace WebCrypto API pour fonctionner sur HTTP (pas de HTTPS requis).

Tout installer :
```powershell
pip install -r requirements.txt
```

---

## ❓ FAQ & Résolution de problèmes

### Caractères spéciaux illisibles (Windows)

```powershell
$env:PYTHONIOENCODING='utf-8'
```

### `pybluez` ne s'installe pas sur Windows

C'est normal — `pybluez` ne supporte que Linux. Le module Bluetooth de CryptoLab utilise des **sockets TCP** sur Windows avec le même chiffrement AES-GCM. Utilisez `--simulate` pour tester sans réseau.

### RSA refuse les clés 512 bits

La bibliothèque `cryptography` exige un minimum de **1024 bits** pour RSA. Les démos utilisent 2048 bits par défaut.

### Erreur `Cannot read properties of undefined (reading 'importKey')` sur Android

Cette erreur apparaît quand l'Android accède au chat via **HTTP** (pas HTTPS). La WebCrypto API du navigateur est bloquée sur HTTP pour des raisons de sécurité.

**Solution appliquée dans ce projet :** la bibliothèque `node-forge` (JavaScript pur) remplace WebCrypto. Elle implémente PBKDF2 et AES-256-GCM sans requérir HTTPS.

Si vous voyez encore cette erreur, videz le cache du navigateur Android :
- Chrome Android → `...` → Paramètres → Confidentialité → Effacer les données de navigation

### `Connection refused` sur le chat web TP6

1. Vérifiez que `python app.py` tourne sur le PC
2. PC et Android doivent être sur le **même routeur** (Ethernet PC + WiFi Android = OK)
3. Ouvrez le port Flask dans le pare-feu Windows :
```powershell
netsh advfirewall firewall add rule name="CryptoLab" dir=in action=allow protocol=TCP localport=5000
```
4. Sur l'Android, tapez l'IP LAN du PC (ex: `http://192.168.100.49:5000`), **pas** `localhost`

### Les deux appareils se voient dans Membres mais les messages ne s'affichent pas

Cause : le **mot de passe / PIN est différent** entre les deux appareils. La clé AES dérivée est alors différente → le déchiffrement échoue silencieusement.

Solution : vérifier que le même mot de passe est saisi des deux côtés avant de rejoindre.

### `Connection refused` sur TP6 (scripts terminal)

1. Vérifiez que le **serveur est lancé** dans un autre terminal
2. Vérifiez que les deux machines sont sur le **même sous-réseau**
3. Ouvrez le port dans le pare-feu Windows :

```powershell
# TLS (port 9443)
netsh advfirewall firewall add rule name="CryptoLab-TLS" dir=in action=allow protocol=TCP localport=9443

# UDP Chat (port 9999)
netsh advfirewall firewall add rule name="CryptoLab-UDP" dir=in action=allow protocol=UDP localport=9999

# Vote (port 9500)
netsh advfirewall firewall add rule name="CryptoLab-Vote" dir=in action=allow protocol=TCP localport=9500
```

### Les graphiques ne s'affichent pas

Les graphiques sont sauvegardés dans `outputs/`. Vérifiez que `matplotlib` et `numpy` sont installés.

---

## 👤 Auteur

Projet de Cryptographie Appliquée — 2026
