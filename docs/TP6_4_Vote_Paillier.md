# 🗳️ TP6.4 — Vote Électronique Homomorphe (Paillier)

## 🎯 Objectif

Implémenter un système de vote où le serveur additionne les votes chiffrés **SANS jamais voir les votes individuels**, grâce au chiffrement homomorphe additif de Paillier. Chaque votant tape manuellement son choix.

---

## 📋 Ce que vous allez apprendre

| Concept | Explication |
|---------|-------------|
| **Chiffrement homomorphe** | Opérations sur les chiffrés = opérations sur les clairs |
| **Homomorphie additive** | `E(a) × E(b) = E(a + b) mod n²` |
| **Non-déterminisme** | `E(1) ≠ E(1)` — même message, chiffré différent |
| **Confidentialité totale** | Le serveur ne déchiffre QUE le total, jamais un vote individuel |
| **Paillier (1999)** | Cryptosystème à clé publique avec propriété homomorphe |

---

## 🔧 Prérequis

| Élément | Détail |
|---------|--------|
| **Python** | 3.10+ |
| **Paquets** | `pip install phe` |
| **Réseau** | 1 serveur + N clients (même LAN), OU tout en local |

---

## 📐 Architecture

```
┌──────────┐              ┌──────────────────────┐
│ Votant 1 │──E(1)──────►│                      │
│  (OUI)   │              │    SERVEUR DE VOTE   │
│          │              │                      │
│ Votant 2 │──E(0)──────►│  Calcule :           │
│  (NON)   │              │  E(1)×E(0)×E(1)×E(1)│
│          │              │  = E(1+0+1+1)        │
│ Votant 3 │──E(1)──────►│  = E(3)              │
│  (OUI)   │              │                      │
│          │              │  Déchiffre E(3) = 3  │
│ Votant 4 │──E(1)──────►│  → 3 OUI / 1 NON    │
│  (OUI)   │              │                      │
└──────────┘              │  ⚠️ Votes individuels│
                          │    JAMAIS déchiffrés !│
                          └──────────────────────┘
```

---

## ▶️ Mode 1 — Test local (1 seul PC, 2 terminaux)

### Étape 1 — Terminal 1 : Lancer le serveur

```powershell
cd Crypto_Project
python tp6_application/vote_electronique/vote_server.py
```

**Sortie :**
```
============================================================
  TP6 — Serveur de Vote Électronique (Paillier)
============================================================

  ⏳ Génération des clés Paillier (1024 bits)...
  ✅ Clés générées — n = 117457890071408441813152537779...

  🔌 Serveur de vote en écoute sur 0.0.0.0:9500
  🔑 Clé publique Paillier prête
  📊 Tapez 'r' pour dépouiller, 'q' pour quitter

  [serveur] >
```

### Étape 2 — Terminal 2 : Lancer un client

```powershell
cd Crypto_Project
python tp6_application/vote_electronique/vote_client.py 127.0.0.1
```

**Sortie :**
```
  🔌 Connexion au serveur 127.0.0.1:9500...
  ✅ Clé publique Paillier reçue
     n = 117457890071408441813152537779...

  Commandes :
    1 = voter OUI    0 = voter NON
    r = voir résultats    q = quitter
```

### Étape 3 — Voter !

**Le votant tape son choix :**
```
  🗳️  Votre action > 1
  ⏳ Chiffrement du vote (1)...
  🔒 Vote chiffré : 1147259414431410163652117336309486890761...
     Taille du chiffré : 617 chiffres
  📤 Envoyé au serveur : ok
  🔒 Le serveur NE PEUT PAS déchiffrer ce vote individuel !

  🗳️  Votre action > 0
  ⏳ Chiffrement du vote (0)...
  🔒 Vote chiffré : 8833964814418871790021093115572564264643...
     Taille du chiffré : 616 chiffres
  📤 Envoyé au serveur : ok
  🔒 Le serveur NE PEUT PAS déchiffrer ce vote individuel !

  🗳️  Votre action > 1
  ⏳ Chiffrement du vote (1)...
  🔒 Vote chiffré : 3265455962711389148081169955688058478393...
     Taille du chiffré : 615 chiffres
  📤 Envoyé au serveur : ok
  🔒 Le serveur NE PEUT PAS déchiffrer ce vote individuel !
```

> Notez que chaque `E(1)` est **différent** (617, 616, 615 chiffres) — c'est le non-déterminisme !

### Étape 4 — Dépouiller (côté serveur)

**Le serveur reçoit les votes :**
```
  [serveur] > 🗳️  Vote reçu de 127.0.0.1 — Total: 1 vote(s)
  [serveur] > 🗳️  Vote reçu de 127.0.0.1 — Total: 2 vote(s)
  [serveur] > 🗳️  Vote reçu de 127.0.0.1 — Total: 3 vote(s)
```

**Tapez `r` pour dépouiller :**
```
  [serveur] > r

  ========================================
  📊 RÉSULTATS DU VOTE
  ========================================
  Votants : 3
  ✅ OUI  : 2 (66.7%)
  ❌ NON  : 1 (33.3%)
  🔒 Votes individuels déchiffrés : JAMAIS
  ========================================
```

### Étape 5 — Commandes serveur

| Commande | Action |
|----------|--------|
| `r` | Dépouiller — afficher les résultats |
| `s` | Status — combien de votes reçus |
| `q` | Quitter le serveur |

---

## ▶️ Mode 2 — Réseau réel (serveur + N clients)

### Étape 1 — Machine serveur

```powershell
python tp6_application/vote_electronique/vote_server.py
# Le serveur écoute sur 0.0.0.0:9500
```

### Étape 2 — Machines clientes (chacune sur un PC différent)

```powershell
python tp6_application/vote_electronique/vote_client.py 192.168.1.10
#                                                        ↑ IP du serveur
```

Chaque client :
1. Récupère la clé publique Paillier du serveur
2. L'utilisateur tape `1` (OUI) ou `0` (NON)
3. Le vote est chiffré **localement** avec la clé publique
4. Le chiffré (617+ chiffres) est envoyé au serveur
5. Le serveur **ne peut pas** déchiffrer ce vote individuel

### Étape 3 — Dépouiller

Quand tous les votants ont fini, le serveur tape `r` :
- Il **multiplie** tous les chiffrés entre eux (homomorphie)
- Il **déchiffre** le résultat de la multiplication → obtient la **somme** des votes
- Il affiche `X OUI / Y NON`

---

## 🔬 Pourquoi ça marche — La magie de Paillier

### Chiffrement

```
E(m, r) = g^m × r^n  mod n²
```

- `g` : générateur
- `r` : aléa unique (rend le chiffrement non-déterministe)
- `n` : partie publique de la clé (1024 bits = ~308 chiffres)

### Propriété homomorphe additive

```
E(a) × E(b) = g^a × r₁^n × g^b × r₂^n
             = g^(a+b) × (r₁r₂)^n
             = E(a + b, r₁r₂)

→ Multiplier les chiffrés = Additionner les clairs !
```

### Pourquoi E(1) ≠ E(1) ?

Chaque chiffrement utilise un `r` aléatoire différent :
```
E(1, r₁) = g¹ × r₁^n mod n²  = 114725941443...
E(1, r₂) = g¹ × r₂^n mod n²  = 326545596271...
```

Même message `1`, mais chiffrés complètement différents !

---

## 🎓 Questions de réflexion

1. **Pourquoi les chiffrés font 617 chiffres ?**
   → `n²` a ~616 chiffres pour n de 1024 bits. Le chiffré vit dans Z/n²Z.

2. **Peut-on tricher en votant 100 au lieu de 0/1 ?**
   → Oui ! Il faudrait des **preuves à divulgation nulle** (zero-knowledge proofs) pour valider que le vote ∈ {0,1}.

3. **Le serveur peut-il retrouver un vote individuel ?**
   → NON — il ne possède que le produit total. Pour retrouver un vote, il faudrait diviser par tous les autres chiffrés, ce qui nécessiterait de les connaître individuellement ET de résoudre le problème de la résiduosité composée.

---

## ⚠️ Résolution de problèmes

| Problème | Solution |
|----------|----------|
| `phe` non trouvé | `pip install phe` |
| Génération lente | Normal — Paillier 1024 bits prend 1-3 secondes |
| `Connection refused` | Le serveur doit être lancé en premier |
| Pare-feu | `netsh advfirewall firewall add rule name="CryptoLab-Vote" dir=in action=allow protocol=TCP localport=9500` |
