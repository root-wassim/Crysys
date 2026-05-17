# 📶 TP6.2 — Communication Bluetooth Sécurisée (Windows)

## 🎯 Objectif

Établir une communication Bluetooth chiffrée **AES-256-GCM** entre deux appareils. L'utilisateur tape ses messages manuellement — chaque message est chiffré avec un nonce unique.

---

## 📋 Ce que vous allez apprendre

| Concept | Explication |
|---------|-------------|
| **AES-256-GCM** | Chiffrement authentifié : confidentialité + intégrité en un seul algo |
| **Nonce (12 octets)** | Valeur aléatoire unique par message — JAMAIS réutilisé |
| **Tag GCM (16 octets)** | Prouve que le message n'a pas été modifié en transit |
| **Clé pré-partagée** | Clé dérivée d'un PIN d'appairage via SHA-256 |
| **RFCOMM simulé** | Transport TCP simulant le protocole Bluetooth RFCOMM |

---

## 🔧 Prérequis

| Élément | Détail |
|---------|--------|
| **Python** | 3.10+ |
| **Paquets** | `pip install pycryptodome` |
| **Réseau** | 2 PC Windows, OU mode simulation (1 seul PC) |

> `pybluez` n'est pas nécessaire — le module utilise des sockets TCP natifs Windows.

---

## 📐 Architecture

```
┌──────────────────────┐                        ┌──────────────────────┐
│    PC SERVEUR        │   TCP (port 9800)       │    PC CLIENT         │
│                      │◄═══════════════════════►│                      │
│  bt_server.py        │   AES-256-GCM           │  bt_client.py        │
│                      │   Nonce unique/message   │                      │
│  Clé = SHA256(PIN)   │                         │  Clé = SHA256(PIN)   │
└──────────────────────┘                        └──────────────────────┘
```

---

## ▶️ Option A — Mode simulation (1 seul PC, sans réseau)

Le mode simulation démontre **toute la cryptographie** sans avoir besoin de réseau :

```powershell
cd Crypto_Project
python tp6_application/bluetooth/bt_server.py --simulate
```

**Sortie :**
```
============================================================
  TP6 - Serveur Bluetooth Chiffré (Windows)
============================================================

  === Bluetooth AES-GCM — Mode Simulation ===
  🔑 Clé partagée (pré-échangée) : 59c3b0079cda2137f0bb638d2b130dab...

  📤 Message clair  : Bonjour depuis Bluetooth !
  🔒 Chiffré (hex)  : 53106a6d8830c38da2e4e2a815a4f9...
  🏷️  Tag GCM       : c676cc03bcaaf118e3f0a798392d1eea
  📥 Déchiffré      : Bonjour depuis Bluetooth !
  ✅ Intégrité OK   : True

  📤 Message clair  : Message confidentiel via BT
  🔒 Chiffré (hex)  : 848163c5ed3224f1f00de8d8ab136f...
  🏷️  Tag GCM       : d830cb4fdb2f9ee0a505bf371196e82d
  📥 Déchiffré      : Message confidentiel via BT
  ✅ Intégrité OK   : True

  --- Test de falsification ---
  ✅ Falsification DÉTECTÉE — GCM refuse le message modifié !
```

> La simulation montre : chiffrement, déchiffrement, vérification d'intégrité, ET détection de falsification.

---

## ▶️ Option B — Mode réseau (2 PC Windows)

### Étape 1 — Trouver les adresses IP

```powershell
# Sur chaque PC :
ipconfig
# Relever l'IPv4 (ex: 192.168.1.10 et 192.168.1.11)
```

### Étape 2 — Lancer le serveur (PC 1)

```powershell
cd Crypto_Project
python tp6_application/bluetooth/bt_server.py
```

**Sortie :**
```
  [BT-WIN] Clé partagée (PIN 1234) : 59c3b0079cda2137...
  [BT-WIN] Serveur en écoute sur 0.0.0.0:9800
  [BT-WIN] En attente de connexions...
```

### Étape 3 — Lancer le client (PC 2)

```powershell
cd Crypto_Project
python tp6_application/bluetooth/bt_client.py 192.168.1.10
```

### Étape 4 — Envoyer des messages

**Côté client** — tapez vos messages :
```
  [BT-CLIENT] ✅ Connecté !
  [BT-CLIENT] Tapez un message (ou 'quit') :

  > Hello Bluetooth sécurisé
  📤 Envoyé (chiffré) : fce63c49cc6da637508394bbff34ec...
  📥 Réponse : ECHO: Hello Bluetooth sécurisé
  ✅ Tag GCM vérifié

  > Message confidentiel
  📤 Envoyé (chiffré) : f62d1777ad2e71474c0dd9bcc6f52d...
  📥 Réponse : ECHO: Message confidentiel
  ✅ Tag GCM vérifié
```

**Côté serveur :**
```
  [BT-WIN] Connexion de 192.168.1.11:54312
  [BT-WIN] Reçu (chiffré) : fce63c49cc6da637508394bb...
  [BT-WIN] Déchiffré      : Hello Bluetooth sécurisé
  [BT-WIN] Tag GCM vérifié ✅
```

### Étape 5 — Quitter

Tapez `quit` côté client, ou `Ctrl+C` côté serveur.

---

## ▶️ Option C — PC + Smartphone Android

1. **Installer** "Serial Bluetooth Terminal" sur Android (Play Store, par Kai Morich)
2. **Appairer** le smartphone avec le PC via Paramètres → Bluetooth
3. **Lancer le serveur** en mode simulation : `python bt_server.py --simulate`
4. Le smartphone envoie en clair via Bluetooth, le PC montre le chiffrement/déchiffrement

> ⚠️ Dans cette configuration, le chiffrement AES-GCM est démontré côté Python. Le smartphone ne fait que le transport.

---

## 🔬 Détail cryptographique d'un message

Pour chaque message envoyé :

```
Message clair : "Hello"
         │
         ▼
   ┌─────────────────────┐
   │  Nonce = random(12) │ ← 12 octets aléatoires
   │  Cipher = AES-GCM   │
   │  Key = SHA256(PIN)   │ ← 32 octets = AES-256
   └─────────────────────┘
         │
         ▼
Paquet envoyé (JSON) :
{
  "nonce": "a1b2c3d4...",     ← 12 octets hex
  "tag":   "f3a2b1c4...",     ← 16 octets hex (intégrité)
  "ct":    "8f2a1bc4..."      ← ciphertext hex
}
```

---

## ⚠️ Résolution de problèmes

| Problème | Solution |
|----------|----------|
| `Connection refused` | Vérifier que le serveur est lancé + même réseau |
| Pare-feu bloque | `netsh advfirewall firewall add rule name="CryptoLab-BT" dir=in action=allow protocol=TCP localport=9800` |
| `pybluez` échoue | Normal sur Windows — utiliser le mode TCP ou `--simulate` |
