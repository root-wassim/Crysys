# 📡 TP6.3 — Chat WiFi UDP Chiffré (AES-256-GCM)

## 🎯 Objectif

Créer un chat en temps réel entre 2 machines via **UDP**, où chaque paquet est chiffré indépendamment avec **AES-256-GCM**. L'utilisateur tape ses messages et voit le nonce, tag, et chiffré de chaque paquet.

---

## 📋 Ce que vous allez apprendre

| Concept | Explication |
|---------|-------------|
| **UDP** | Protocole sans connexion, rapide, pas de handshake |
| **Broadcast** | `255.255.255.255` → tous les appareils du réseau reçoivent |
| **AES-256-GCM** | Chiffrement authentifié par paquet (nonce unique) |
| **Nonce unique** | 12 octets aléatoires différents par message |
| **Tag GCM** | 16 octets — détecte toute modification du message |
| **Clé pré-partagée** | `SHA-256("CryptoLab_WiFi_Chat_2024")` |

---

## 🔧 Prérequis

| Élément | Détail |
|---------|--------|
| **Python** | 3.10+ |
| **Paquets** | `pip install pycryptodome` |
| **Réseau** | 2 appareils sur le même WiFi |

---

## 📐 Architecture

### Mode unicast (1 → 1)
```
┌──────────────────────┐     UDP (port 9999)     ┌──────────────────────┐
│    MACHINE A         │◄═══════════════════════►│    MACHINE B         │
│  udp_server.py       │  AES-256-GCM par paquet │  udp_client.py       │
│  (écoute + envoie)   │  nonce unique/message   │  (envoie)            │
└──────────────────────┘                        └──────────────────────┘
```

### Mode broadcast (1 → tous)
```
┌──────────────────────┐     255.255.255.255      ┌──────────────────────┐
│    ÉMETTEUR          │══════════════════════════►│    TOUS les appareils│
│  udp_client.py       │                          │    du réseau WiFi    │
│  255.255.255.255     │                          │    reçoivent         │
└──────────────────────┘                          └──────────────────────┘
```

---

## ▶️ Mode 1 — Test sur la même machine (localhost)

### Étape 1 — Ouvrir 2 terminaux PowerShell

### Étape 2 — Terminal 1 : Serveur (écoute + envoie)

```powershell
cd Crypto_Project
python tp6_application/wifi_chat/udp_server.py
```

**Sortie :**
```
============================================================
  TP6 — Chat WiFi UDP Chiffré (AES-256-GCM)
============================================================

  📡 Chat UDP chiffré AES-256-GCM
  🔑 Clé partagée : a5c8f3b2d1e4...
  📡 Écoute sur le port 9999
  📤 Envoi vers : 127.0.0.1 (localhost)

  📤 Vous >
```

### Étape 3 — Terminal 2 : Client (envoie)

```powershell
cd Crypto_Project
python tp6_application/wifi_chat/udp_client.py 127.0.0.1
```

### Étape 4 — Taper des messages

**Côté client** — tapez un message :
```
  📤 Vous > Bonjour WiFi sécurisé !
     [23:50:12] ✅ Envoyé (118 octets)
     Clair   : "Bonjour WiFi sécurisé !"
     Chiffré : 8f2a1bc4d5e6f7a8b9c0d1e2f3...
     Nonce   : a1b2c3d4e5f6a7b8c9d0e1f2
     Tag GCM : f3a2b1c4d5e6f7a8b9c0d1e2f3a4b5c6
```

**Côté serveur** — le message apparaît déchiffré :
```
  📩 [23:50:12] 127.0.0.1 → Bonjour WiFi sécurisé !
     Nonce: a1b2c3d4e5f6... | Tag: f3a2b1c4d5e6... | ✅ GCM OK
```

> Chaque message a un **nonce différent** — vérifiez-le en envoyant 2 fois le même texte !

---

## ▶️ Mode 2 — Chat entre 2 machines (même WiFi)

### Étape 1 — Trouver les IPs

```powershell
# Sur chaque machine :
ipconfig
# Machine A : 192.168.1.10
# Machine B : 192.168.1.11
```

### Étape 2 — Machine A : écoute bidirectionnelle

```powershell
python tp6_application/wifi_chat/udp_server.py 192.168.1.11
```
> Le serveur écoute ET peut envoyer vers Machine B.

### Étape 3 — Machine B : envoie vers Machine A

```powershell
python tp6_application/wifi_chat/udp_client.py 192.168.1.10
```

### Pour un chat bidirectionnel complet

Lancez le serveur **sur les deux machines** :

```powershell
# Machine A :
python tp6_application/wifi_chat/udp_server.py 192.168.1.11

# Machine B :
python tp6_application/wifi_chat/udp_server.py 192.168.1.10
```

Chaque machine écoute ET envoie — c'est un vrai chat !

---

## ▶️ Mode 3 — Broadcast (tous les appareils du réseau)

```powershell
python tp6_application/wifi_chat/udp_client.py 255.255.255.255
```

Tous les appareils du réseau WiFi qui ont le serveur UDP ouvert recevront le message.

---

## 🔍 Observer avec Wireshark (optionnel)

1. Installer [Wireshark](https://www.wireshark.org/)
2. Capturer sur l'interface WiFi
3. Filtrer : `udp.port == 9999`
4. **Observer** : les données des paquets UDP sont un JSON chiffré (illisible)
5. Comparer avec un envoi en clair pour voir la différence

---

## 🔬 Détail d'un paquet UDP chiffré

```
Paquet UDP brut capturé par Wireshark :
───────────────────────────────────────────
{"n":"a1b2c3d4e5f6a7b8c9d0e1f2",
 "t":"f3a2b1c4d5e6f7a8b9c0d1e2f3a4b5c6",
 "c":"8f2a1bc4d5e6f7a8b9c0d1e2f3a4b5"}
───────────────────────────────────────────
  n = nonce (12 octets, unique par message)
  t = tag GCM (16 octets, intégrité)
  c = ciphertext (message chiffré)

Sans la clé AES-256, impossible de lire le message !
```

---

## ⚠️ Résolution de problèmes

| Problème | Solution |
|----------|----------|
| Broadcast non reçu | Vérifier que les 2 appareils sont sur le même sous-réseau |
| `Address already in use` | Fermer l'ancien processus ou `taskkill /F /PID <pid>` |
| Pare-feu bloque | `netsh advfirewall firewall add rule name="CryptoLab-UDP" dir=in action=allow protocol=UDP localport=9999` |
| Messages non reçus | Le serveur doit être lancé AVANT le client |
