# 📡 TP6.1 — Communication TCP/TLS Sécurisée

## 🎯 Objectif

Établir une communication chiffrée entre deux machines via **TLS 1.3** avec certificats auto-signés X.509. L'utilisateur tape ses messages en temps réel.

---

## 📋 Ce que vous allez apprendre

| Concept | Explication |
|---------|-------------|
| **TLS 1.3** | Protocole de sécurité standard du web (HTTPS) |
| **Certificat X.509** | Contient la clé publique RSA du serveur |
| **Handshake TLS** | Négociation automatique du cipher suite |
| **AES-256-GCM-SHA384** | Cipher suite négocié (confidentialité + intégrité) |
| **Certificat auto-signé** | Pas d'autorité de certification — usage interne/TP |

---

## 🔧 Prérequis

| Élément | Détail |
|---------|--------|
| **Python** | 3.10+ |
| **Paquets** | `pip install cryptography` |
| **Réseau** | 2 machines sur le même LAN, OU 1 PC + 1 VM |

---

## 📐 Architecture

```
┌──────────────────────┐                        ┌──────────────────────┐
│     MACHINE A        │    TLS 1.3 (9443)      │     MACHINE B        │
│     (serveur)        │◄═══════════════════════►│     (client)         │
│                      │   AES-256-GCM-SHA384    │                      │
│  python server.py    │   certificat X.509      │  python client.py    │
│  IP: 192.168.1.10    │                         │  IP: 192.168.1.11    │
└──────────────────────┘                        └──────────────────────┘
```

---

## ▶️ Étapes

### Étape 1 — Trouver votre adresse IP

```powershell
ipconfig
# Chercher "IPv4 Address" sous "Ethernet" ou "Wi-Fi"
# Exemple : 192.168.1.10
```

### Étape 2 — Lancer le serveur (Machine A)

```powershell
cd Crypto_Project
python tp6_application/tcp/server.py
```

**Sortie attendue :**
```
============================================================
  TP6 — Serveur TCP/TLS Sécurisé
============================================================
  🔐 Certificat généré : tp6_application\tcp\certs\server.crt

  🔌 Serveur TLS en écoute sur 0.0.0.0:9443
  📜 Certificat : tp6_application\tcp\certs\server.crt
  🔒 TLS activé — en attente de connexions...
```

### Étape 3 — Lancer le client (Machine B)

```powershell
cd Crypto_Project
python tp6_application/tcp/client.py 192.168.1.10
#                                     ↑ IP du serveur
```

> Si vous testez sur la même machine, utilisez `127.0.0.1`.

**Sortie attendue :**
```
  🔌 Connexion TLS à 192.168.1.10:9443...
  ✅ Connexion TLS établie !
  🔒 Protocole : TLSv1.3
  🔐 Cipher    : TLS_AES_256_GCM_SHA384
  📜 Serveur   : CryptoLab-Server
```

### Étape 4 — Envoyer des messages

**Côté client** — tapez vos messages :
```
  📤 Vous > Bonjour depuis la machine B !
     [23:47:41] Envoyé (31 octets, chiffré TLS)
  📩 Serveur > [SERVEUR 23:47:41] Reçu: Bonjour depuis la machine B !

  📤 Vous > Message confidentiel
     [23:47:55] Envoyé (22 octets, chiffré TLS)
  📩 Serveur > [SERVEUR 23:47:55] Reçu: Message confidentiel
```

**Côté serveur** — les messages apparaissent en temps réel :
```
  ✅ [192.168.1.11:52341] Connecté — Cipher: TLS_AES_256_GCM_SHA384
  📩 [23:47:41] 192.168.1.11:52341 → Bonjour depuis la machine B !
  📩 [23:47:55] 192.168.1.11:52341 → Message confidentiel
```

### Étape 5 — Quitter

Tapez `quit` côté client, ou `Ctrl+C` pour arrêter le serveur.

---

## 🖥️ Configuration VM (VirtualBox)

Si vous n'avez qu'un seul PC :

1. **Installer VirtualBox** + créer une VM Ubuntu/Windows
2. **Configuration réseau** : VM → Paramètres → Réseau → **Accès par pont (Bridge)**
   - ⚠️ **NE PAS utiliser NAT** — la VM ne serait pas visible sur le réseau
3. La VM obtient sa propre IP (vérifier avec `ipconfig` / `ip addr`)
4. Lancer le serveur dans la VM, le client sur le PC hôte

---

## ⚠️ Résolution de problèmes

| Problème | Solution |
|----------|----------|
| `Connection refused` | Le serveur n'est pas lancé, ou le port 9443 est bloqué |
| `Connection timed out` | Les machines ne sont pas sur le même sous-réseau |
| Pare-feu bloque | `netsh advfirewall firewall add rule name="CryptoLab-TLS" dir=in action=allow protocol=TCP localport=9443` |
| `certificate verify failed` | Normal avec un certificat auto-signé — le client gère automatiquement |
