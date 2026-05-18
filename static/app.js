/* ═══════════════════════════════════════════════════
   CryptoLab — Frontend Logic
   ═══════════════════════════════════════════════════ */

// ─── Navigation ──────────────────────────────────
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
        const tp = item.dataset.tp;
        navigateTo(tp);
    });
});

function navigateTo(tp) {
    // Update nav
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const navItem = document.querySelector(`.nav-item[data-tp="${tp}"]`);
    if (navItem) navItem.classList.add('active');
    // Update page
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    const page = document.getElementById(`page-${tp}`);
    if (page) page.classList.add('active');
}

// ─── César Slider ────────────────────────────────
const cesarSlider = document.getElementById('cesar-key');
const cesarDisplay = document.getElementById('cesar-key-display');
if (cesarSlider) {
    cesarSlider.addEventListener('input', () => {
        cesarDisplay.textContent = `k = ${cesarSlider.value}`;
    });
}

// ─── Vote Buttons Toggle ─────────────────────────
document.querySelectorAll('.vote-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        if (btn.classList.contains('yes')) {
            btn.classList.remove('yes');
            btn.classList.add('no');
            btn.dataset.vote = '0';
            btn.textContent = 'NON';
        } else {
            btn.classList.remove('no');
            btn.classList.add('yes');
            btn.dataset.vote = '1';
            btn.textContent = 'OUI';
        }
    });
});

// ─── API Helper ──────────────────────────────────
async function apiCall(endpoint, data) {
    try {
        const resp = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        return await resp.json();
    } catch (e) {
        return { error: e.message };
    }
}

function showResult(id, html) {
    const box = document.getElementById(id);
    box.innerHTML = html;
    box.classList.remove('hidden');
    box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function resultLine(label, value, cls = '') {
    return `<span class="label">${label}</span>\n<span class="${cls || 'value'}">${escapeHtml(String(value))}</span>\n\n`;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function loadingHtml() {
    return '<span class="loading"></span> Calcul en cours...';
}

// ─── TP1 : César ─────────────────────────────────
async function cesarAction(action) {
    const resultId = 'cesar-result';
    showResult(resultId, loadingHtml());
    const data = {
        message: document.getElementById('cesar-input').value,
        key: document.getElementById('cesar-key').value,
        action: action
    };
    const res = await apiCall('/api/tp1/cesar', data);
    if (res.error) {
        showResult(resultId, resultLine('Erreur', res.error, 'danger'));
        return;
    }
    let html = '';
    if (action === 'attack') {
        html += resultLine('Clé trouvée par IC', `k = ${res.key_found}`, 'success');
        html += resultLine('Texte déchiffré', res.decrypted);
        html += '\n<span class="label">TOP 5 — FORCE BRUTE</span>\n';
        if (res.top5) {
            res.top5.forEach(([k, text, score]) => {
                html += `  k=${k.toString().padStart(2)} | score=${score.toString().padStart(6)} | ${escapeHtml(text.substring(0, 50))}\n`;
            });
        }
    } else {
        html += resultLine('Résultat', res.result);
        if (res.ic !== undefined) {
            html += resultLine('Indice de coïncidence', res.ic, 'info');
        }
    }
    showResult(resultId, html);
}

// ─── TP1 : Vigenère ──────────────────────────────
async function vigenereAction(action) {
    const resultId = 'vigenere-result';
    showResult(resultId, loadingHtml());
    const data = {
        message: document.getElementById('vigenere-input').value,
        key: document.getElementById('vigenere-key').value,
        action: action
    };
    const res = await apiCall('/api/tp1/vigenere', data);
    if (res.error) {
        showResult(resultId, resultLine('Erreur', res.error, 'danger'));
        return;
    }
    let html = '';
    if (action === 'attack') {
        html += resultLine('Clé trouvée', res.key_found, 'success');
        html += resultLine('Texte déchiffré', res.decrypted);
    } else {
        html += resultLine('Résultat', res.result);
    }
    showResult(resultId, html);
}

// ─── TP1 : Hill ──────────────────────────────────
async function hillAction(action) {
    const resultId = 'hill-result';
    showResult(resultId, loadingHtml());
    const matrix = [
        [parseInt(document.getElementById('hill-a').value), parseInt(document.getElementById('hill-b').value)],
        [parseInt(document.getElementById('hill-c').value), parseInt(document.getElementById('hill-d').value)]
    ];
    const data = {
        message: document.getElementById('hill-input').value,
        matrix: matrix,
        action: action
    };
    const res = await apiCall('/api/tp1/hill', data);
    if (res.error) {
        showResult(resultId, resultLine('Erreur', res.error, 'danger'));
        return;
    }
    showResult(resultId, resultLine('Résultat', res.result));
}

// ─── TP2 : AES ───────────────────────────────────
async function aesAction() {
    const resultId = 'aes-result';
    showResult(resultId, loadingHtml());
    const data = {
        message: document.getElementById('aes-input').value,
        mode: document.getElementById('aes-mode').value,
        key_size: document.getElementById('aes-keysize').value,
        action: 'encrypt'
    };
    const res = await apiCall('/api/tp2/aes', data);
    if (res.error) {
        showResult(resultId, resultLine('Erreur', res.error, 'danger'));
        return;
    }
    let html = '';
    html += resultLine('Mode', data.mode + '-' + data.key_size);
    html += resultLine('Clé (hex)', res.key);
    if (res.iv) html += resultLine('IV (hex)', res.iv);
    if (res.nonce) html += resultLine('Nonce (hex)', res.nonce);
    html += resultLine('Chiffré (hex)', res.ciphertext);
    showResult(resultId, html);
}

// ─── TP3 : RSA ───────────────────────────────────
async function rsaAction() {
    const resultId = 'rsa-result';
    showResult(resultId, loadingHtml());
    const data = {
        message: document.getElementById('rsa-input').value,
        bits: document.getElementById('rsa-bits').value
    };
    const res = await apiCall('/api/tp3/rsa', data);
    if (res.error) {
        showResult(resultId, resultLine('Erreur', res.error, 'danger'));
        return;
    }
    let html = '';
    html += resultLine('Chiffré', res.ciphertext);
    html += resultLine('Déchiffré', res.decrypted, 'success');
    html += resultLine('Correct', res.correct ? '✅ Oui' : '❌ Non', res.correct ? 'success' : 'danger');
    html += resultLine('Génération clés', res.key_gen_ms + ' ms', 'info');
    html += resultLine('Chiffrement', res.encrypt_ms + ' ms', 'info');
    html += resultLine('Déchiffrement', res.decrypt_ms + ' ms', 'info');
    html += resultLine('Clé publique (PEM)', res.public_key_pem);
    showResult(resultId, html);
}

// ─── TP3 : DH ────────────────────────────────────
async function dhAction(action) {
    const resultId = 'dh-result';
    showResult(resultId, loadingHtml());
    const res = await apiCall('/api/tp3/dh', { action: action });
    if (res.error) {
        showResult(resultId, resultLine('Erreur', res.error, 'danger'));
        return;
    }
    let html = '';
    if (action === 'exchange') {
        html += resultLine('Taille du premier p', res.p_bits + ' bits');
        html += resultLine('A public', res.a_pub);
        html += resultLine('B public', res.b_pub);
        html += resultLine('Secrets identiques', res.secrets_match ? '✅ Oui' : '❌ Non', res.secrets_match ? 'success' : 'danger');
        html += resultLine('Clé AES dérivée', res.aes_key, 'success');
    } else {
        html += resultLine('Alice ↔ Mallory partagent un secret', res.alice_mallory_match ? '✅' : '❌', 'warning');
        html += resultLine('Bob ↔ Mallory partagent un secret', res.bob_mallory_match ? '✅' : '❌', 'warning');
        html += resultLine('Alice ≠ Bob (secrets différents)', res.alice_bob_different ? '⚠️ OUI — MITM réussi !' : 'Non', 'danger');
        html += resultLine('Clé Alice', res.cle_alice);
        html += resultLine('Clé Mallory→Alice', res.cle_mallory_a, 'danger');
        html += resultLine('Clé Bob', res.cle_bob);
        html += resultLine('Clé Mallory→Bob', res.cle_mallory_b, 'danger');
    }
    showResult(resultId, html);
}

// ─── TP4 : Hash ──────────────────────────────────
async function hashAction() {
    const resultId = 'hash-result';
    showResult(resultId, loadingHtml());
    const data = {
        message: document.getElementById('hash-input').value,
        algo: document.getElementById('hash-algo').value
    };
    const res = await apiCall('/api/tp4/hash', data);
    if (res.error) {
        showResult(resultId, resultLine('Erreur', res.error, 'danger'));
        return;
    }
    let html = '';
    html += resultLine('Algorithme', res.algo + ' (' + res.output_bits + ' bits)');
    html += resultLine('Hash', res.hash);
    html += resultLine('Hash (1 bit modifié)', res.hash_modified);
    html += resultLine('Effet avalanche', res.bits_diff + '/' + res.bits_total + ' bits (' + res.avalanche_pct + '%)', 'info');
    showResult(resultId, html);
}

async function sha256ScratchAction() {
    const resultId = 'hash-result';
    showResult(resultId, loadingHtml());
    const data = { message: document.getElementById('hash-input').value };
    const res = await apiCall('/api/tp4/sha256_scratch', data);
    if (res.error) {
        showResult(resultId, resultLine('Erreur', res.error, 'danger'));
        return;
    }
    let html = '';
    html += resultLine('Notre SHA-256', res.our_hash);
    html += resultLine('Référence hashlib', res.ref_hash);
    html += resultLine('Identiques', res.match ? '✅ Implémentation correcte !' : '❌ Erreur', res.match ? 'success' : 'danger');
    showResult(resultId, html);
}

// ─── TP5 : Signatures ────────────────────────────
async function sigAction(type) {
    const resultId = 'sig-result';
    showResult(resultId, loadingHtml());
    const data = { message: document.getElementById('sig-input').value };
    const endpoint = type === 'rsa_pss' ? '/api/tp5/rsa_pss' : '/api/tp5/ecdsa';
    const res = await apiCall(endpoint, data);
    if (res.error) {
        showResult(resultId, resultLine('Erreur', res.error, 'danger'));
        return;
    }
    let html = '';
    html += resultLine('Algorithme', type === 'rsa_pss' ? 'RSA-PSS (2048 bits)' : 'ECDSA P-256');
    html += resultLine('Signature', res.signature);
    html += resultLine('Taille', res.sig_size_bytes + ' octets');
    html += resultLine('Valide', res.valid ? '✅ Oui' : '❌ Non', res.valid ? 'success' : 'danger');
    html += resultLine('Falsification détectée', res.falsification_detected ? '✅ Oui' : '❌ Non', res.falsification_detected ? 'success' : 'danger');
    if (res.non_deterministic !== undefined) {
        html += resultLine('Non-déterministe (PSS)', res.non_deterministic ? '✅ Oui' : 'Non', 'info');
    }
    if (res.curve) {
        html += resultLine('Courbe', res.curve, 'info');
    }
    showResult(resultId, html);
}

// ─── TP6 : Vote Paillier ─────────────────────────
async function voteAction() {
    const resultId = 'vote-result';
    showResult(resultId, loadingHtml());
    const votes = [];
    document.querySelectorAll('.vote-btn').forEach(btn => {
        votes.push(parseInt(btn.dataset.vote));
    });
    const res = await apiCall('/api/tp6/vote', { votes: votes });
    if (res.error) {
        showResult(resultId, resultLine('Erreur', res.error, 'danger'));
        return;
    }
    let html = '';
    html += resultLine('Nombre de votants', res.nb_voters);
    html += resultLine('OUI', res.yes + ' (' + res.pct_yes + '%)', 'success');
    html += resultLine('NON', res.no + ' (' + (100 - res.pct_yes).toFixed(1) + '%)', 'danger');
    html += resultLine('Résultat correct', res.correct ? '✅' : '❌', res.correct ? 'success' : 'danger');
    html += resultLine('Chiffrement homomorphe', res.homomorphic ? '✅ Actif' : 'Non', 'info');
    html += resultLine('Votes individuels déchiffrés', res.individual_votes_decrypted ? 'Oui' : '🔒 NON — confidentialité totale', 'success');
    showResult(resultId, html);
}

// ─── TP1 : OTP ───────────────────────────────────
async function otpAction(action) {
    const resultId = 'otp-result';
    showResult(resultId, loadingHtml());
    const data = { message: document.getElementById('otp-input').value, message2: document.getElementById('otp-input2').value, action: action };
    const res = await apiCall('/api/tp1/otp', data);
    if (res.error) { showResult(resultId, resultLine('Erreur', res.error, 'danger')); return; }
    let html = '';
    if (action === 'encrypt') {
        html += resultLine('Chiffré (hex)', res.ciphertext);
        html += resultLine('Clé (hex)', res.key);
        html += resultLine('Taille clé', res.key_len + ' octets = taille message', 'info');
    } else {
        html += resultLine('C1 ⊕ C2', res.xor_ct);
        html += resultLine('M1 ⊕ M2', res.xor_pt);
        html += resultLine('C1⊕C2 = M1⊕M2 ?', res.match ? '⚠️ OUI — la clé disparaît !' : 'Non', 'danger');
        html += resultLine('Vulnérabilité', res.vuln, 'danger');
    }
    showResult(resultId, html);
}

// ─── TP2 : RC4 ───────────────────────────────────
async function rc4Action() {
    const resultId = 'rc4-result';
    showResult(resultId, loadingHtml());
    const data = { message: document.getElementById('rc4-input').value, key: document.getElementById('rc4-key').value };
    const res = await apiCall('/api/tp2/rc4', data);
    if (res.error) { showResult(resultId, resultLine('Erreur', res.error, 'danger')); return; }
    let html = '';
    html += resultLine('Keystream (16 premiers)', res.keystream_16);
    html += resultLine('Chiffré (hex)', res.ciphertext);
    html += resultLine('Déchiffré', res.decrypted, 'success');
    html += resultLine('Correct', res.correct ? '✅' : '❌', res.correct ? 'success' : 'danger');
    showResult(resultId, html);
}

// ─── TP2 : DES ───────────────────────────────────
async function desAction() {
    const resultId = 'des-result';
    showResult(resultId, loadingHtml());
    const data = { message: document.getElementById('des-input').value, algo: document.getElementById('des-algo').value, mode: document.getElementById('des-mode').value };
    const res = await apiCall('/api/tp2/des', data);
    if (res.error) { showResult(resultId, resultLine('Erreur', res.error, 'danger')); return; }
    let html = '';
    html += resultLine('Algorithme', res.algo);
    html += resultLine('Clé (hex)', res.key);
    if (res.iv) html += resultLine('IV (hex)', res.iv);
    html += resultLine('Chiffré (hex)', res.ciphertext);
    html += resultLine('Déchiffré', res.decrypted, 'success');
    html += resultLine('Correct', res.correct ? '✅' : '❌', res.correct ? 'success' : 'danger');
    showResult(resultId, html);
}

// ─── TP2 : NIST ──────────────────────────────────
async function nistAction() {
    const resultId = 'nist-result';
    showResult(resultId, loadingHtml());
    const data = { message: document.getElementById('nist-input').value, algo: document.getElementById('nist-algo').value };
    const res = await apiCall('/api/tp2/nist', data);
    if (res.error) { showResult(resultId, resultLine('Erreur', res.error, 'danger')); return; }
    let html = '';
    html += resultLine('Algorithme', res.algo);
    html += resultLine('Architecture', res.info, 'info');
    html += resultLine('Chiffré', res.ciphertext);
    html += resultLine('Temps', res.time_ms + ' ms', 'info');
    html += resultLine('Déchiffrement', String(res.correct), res.correct === true ? 'success' : 'warning');
    showResult(resultId, html);
}

// ─── TP3 : ElGamal ───────────────────────────────
async function elgamalAction() {
    const resultId = 'elgamal-result';
    showResult(resultId, loadingHtml());
    const data = { message_int: document.getElementById('elgamal-m').value };
    const res = await apiCall('/api/tp3/elgamal', data);
    if (res.error) { showResult(resultId, resultLine('Erreur', res.error, 'danger')); return; }
    let html = '';
    html += resultLine('M (clair)', res.M);
    html += resultLine('C1', res.C1);
    html += resultLine('C2', res.C2);
    html += resultLine('Déchiffré', res.decrypted, 'success');
    html += resultLine('Correct', res.correct ? '✅' : '❌', res.correct ? 'success' : 'danger');
    html += resultLine('Non-déterministe', res.non_deterministic ? '✅ E(M)₁ ≠ E(M)₂' : 'Non', 'info');
    showResult(resultId, html);
}

// ─── TP3 : ECC ───────────────────────────────────
async function eccAction(action) {
    const resultId = 'ecc-result';
    showResult(resultId, loadingHtml());
    const res = await apiCall('/api/tp3/ecc', { action: action });
    if (res.error) { showResult(resultId, resultLine('Erreur', res.error, 'danger')); return; }
    let html = '';
    for (const [k, v] of Object.entries(res)) {
        html += resultLine(k, String(v), typeof v === 'boolean' ? (v ? 'success' : 'danger') : 'value');
    }
    showResult(resultId, html);
}

// ─── TP3 : Hybrid ────────────────────────────────
async function hybridAction() {
    const resultId = 'hybrid-result';
    showResult(resultId, loadingHtml());
    const data = { message: document.getElementById('hybrid-input').value };
    const res = await apiCall('/api/tp3/hybrid', data);
    if (res.error) { showResult(resultId, resultLine('Erreur', res.error, 'danger')); return; }
    let html = '';
    html += resultLine('Nonce GCM', res.nonce);
    html += resultLine('Tag GCM', res.tag);
    html += resultLine('Chiffré', res.ciphertext);
    html += resultLine('Taille paquet', res.total_size + ' octets', 'info');
    html += resultLine('Déchiffré', res.decrypted, 'success');
    html += resultLine('Correct', res.correct ? '✅' : '❌', res.correct ? 'success' : 'danger');
    html += resultLine('Chiffrement', res.enc_ms + ' ms', 'info');
    html += resultLine('Déchiffrement', res.dec_ms + ' ms', 'info');
    showResult(resultId, html);
}

// ─── TP4 : MD5 Collision ─────────────────────────
async function md5CollisionAction() {
    const resultId = 'md5col-result';
    showResult(resultId, loadingHtml());
    const res = await apiCall('/api/tp4/md5_collision', {});
    if (res.error) { showResult(resultId, resultLine('Erreur', res.error, 'danger')); return; }
    let html = '';
    const c = res.collision;
    html += resultLine('Messages différents', c.messages_differents ? '✅ OUI' : 'Non', 'info');
    html += resultLine('Hash M1', c.hash_m1);
    html += resultLine('Hash M2', c.hash_m2);
    html += resultLine('COLLISION !', c.collision ? '💥 OUI — même hash !' : 'Non', 'danger');
    html += resultLine('Octets différents', c.octets_differents, 'warning');
    const a = res.avalanche;
    html += resultLine('Effet avalanche', a.bits_differents + '/' + a.bits_total + ' (' + a.pourcentage + '%)', 'info');
    showResult(resultId, html);
}

// ─── TP5 : ElGamal Signature ─────────────────────
async function elgamalSignAction() {
    const resultId = 'elgamal-sign-result';
    showResult(resultId, loadingHtml());
    const data = { message: document.getElementById('elgamal-sign-input').value };
    const res = await apiCall('/api/tp5/elgamal_sign', data);
    if (res.error) { showResult(resultId, resultLine('Erreur', res.error, 'danger')); return; }
    let html = '';
    html += resultLine('r', res.r);
    html += resultLine('s', res.s);
    html += resultLine('Valide', res.valid ? '✅' : '❌', res.valid ? 'success' : 'danger');
    html += resultLine('Falsification détectée', res.falsification_detected ? '✅' : '❌', res.falsification_detected ? 'success' : 'danger');
    showResult(resultId, html);
}

// ─── TP5 : DSA ───────────────────────────────────
async function dsaAction() {
    const resultId = 'dsa-result';
    showResult(resultId, loadingHtml());
    const data = { message: document.getElementById('dsa-input').value };
    const res = await apiCall('/api/tp5/dsa', data);
    if (res.error) { showResult(resultId, resultLine('Erreur', res.error, 'danger')); return; }
    let html = '';
    html += resultLine('Algorithme', res.algo);
    html += resultLine('Signature', res.signature);
    html += resultLine('Taille', res.sig_size + ' octets', 'info');
    html += resultLine('Valide', res.valid ? '✅' : '❌', res.valid ? 'success' : 'danger');
    html += resultLine('Falsification détectée', res.falsification_detected ? '✅' : '❌', res.falsification_detected ? 'success' : 'danger');
    showResult(resultId, html);
}


/* ═══════════════════════════════════════════════════════════════
   TP6 — CHAT RÉSEAU RÉEL
   WebCrypto AES-256-GCM + Flask-SocketIO
   ═══════════════════════════════════════════════════════════════ */

// ─── Singleton Socket.IO ──────────────────────────
let _socket = null;

function getSocket() {
    if (!_socket) {
        _socket = io({ transports: ['websocket', 'polling'] });
        _socket.on('connect', () => {
            console.log('[SocketIO] Connecté :', _socket.id);
        });
        _socket.on('disconnect', () => {
            console.log('[SocketIO] Déconnecté');
            setStatus('wifi', false); setStatus('bt', false); setStatus('tcp', false);
        });
        // Écouter les événements de chat pour les 3 rooms
        _socket.on('user_joined', (d) => onUserEvent(d, 'joined'));
        _socket.on('user_left',   (d) => onUserEvent(d, 'left'));
        _socket.on('message_received', (d) => onMessageReceived(d));
        _socket.on('pong_test', (d) => {
            const rtt = Date.now() - d.client_ts;
            console.log(`[Latence] RTT = ${rtt}ms`);
        });
    }
    return _socket;
}

// ─── État des chats ───────────────────────────────
const chatState = {
    wifi: { joined: false, room: 'tp6-wifi',      aesKey: null, username: '' },
    bt:   { joined: false, room: 'tp6-bluetooth', aesKey: null, username: '' },
    tcp:  { joined: false, room: 'tp6-tcp',       aesKey: null, username: '' },
};

// ─── Fonctions UI génériques ──────────────────────
function setStatus(chat, connected, text = null) {
    const el = document.getElementById(`${chat}-status`);
    if (!el) return;
    el.className = 'chat-status ' + (connected ? 'connected' : 'disconnected');
    el.textContent = connected
        ? (text || '🟢 Connecté')
        : (text || '⚪ Déconnecté');
}

function setInputEnabled(chat, enabled) {
    const msgInput = document.getElementById(`${chat}-msg`);
    const sendBtn  = document.getElementById(`${chat}-send-btn`);
    if (msgInput) msgInput.disabled = !enabled;
    if (sendBtn)  sendBtn.disabled  = !enabled;
}

function updateMembers(chat, members) {
    const el = document.getElementById(`${chat}-members`);
    if (!el) return;
    if (!members || members.length === 0) { el.textContent = 'Aucun'; return; }
    el.innerHTML = members.map(m =>
        `<span class="member-chip">${escapeHtml(m)}</span>`
    ).join('');
}

function appendChatMessage(chat, { username, text, isSelf, timestamp, nonce, ciphertextHex, tagHex }) {
    const container = document.getElementById(`${chat}-messages`);
    if (!container) return;
    // Supprimer l'écran de bienvenue si présent
    const welcome = container.querySelector('.chat-welcome');
    if (welcome) welcome.remove();

    const time = timestamp ? new Date(timestamp).toLocaleTimeString('fr-FR', {hour:'2-digit', minute:'2-digit', second:'2-digit'}) : '';
    const div = document.createElement('div');
    div.className = 'chat-bubble-wrap ' + (isSelf ? 'self' : 'other');
    div.innerHTML = `
        <div class="chat-bubble ${isSelf ? 'self' : 'other'}">
            <div class="bubble-header">
                <span class="bubble-name">${escapeHtml(username)}</span>
                <span class="bubble-time">${time}</span>
            </div>
            <div class="bubble-text">${escapeHtml(text)}</div>
            <div class="bubble-tag">🔒 AES-256-GCM</div>
        </div>
    `;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;

    // Mettre à jour le panneau crypto
    if (nonce) {
        const detail = document.getElementById(`${chat}-crypto-details`);
        if (detail) {
            detail.innerHTML =
                `<span class="cd-label">Nonce (IV)</span>\n<span class="cd-val">${nonce}</span>\n\n` +
                `<span class="cd-label">Ciphertext</span>\n<span class="cd-val">${(ciphertextHex||'').substring(0,64)}...</span>\n\n` +
                `<span class="cd-label">Auth Tag</span>\n<span class="cd-val">${tagHex||''}</span>\n\n` +
                `<span class="cd-label">Algorithme</span>\n<span class="cd-val success">AES-256-GCM ✅</span>`;
        }
    }
}

function appendSystemMessage(chat, text) {
    const container = document.getElementById(`${chat}-messages`);
    if (!container) return;
    const welcome = container.querySelector('.chat-welcome');
    if (welcome) welcome.remove();
    const div = document.createElement('div');
    div.className = 'chat-sys-msg';
    div.textContent = text;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

// ─── Dérivation de clé AES (PBKDF2 via node-forge) ──
// node-forge fonctionne sur HTTP (pas besoin de HTTPS contrairement à WebCrypto)
async function deriveAESKey(password, salt = 'CryptoLabSalt2024') {
    return new Promise((resolve, reject) => {
        try {
            // PBKDF2-SHA256, 100 000 itérations, 32 bytes (256 bits)
            const key = forge.pkcs5.pbkdf2(
                password, salt, 100000, 32,
                forge.md.sha256.create()
            );
            resolve(key); // binary string (forge format)
        } catch (e) {
            reject(e);
        }
    });
}

// ─── Chiffrement AES-256-GCM (node-forge) ────────
async function aesGcmEncrypt(text, keyBytes) {
    const iv = forge.random.getBytesSync(12); // 96-bit nonce
    const cipher = forge.cipher.createCipher('AES-GCM', keyBytes);
    cipher.start({ iv: iv, tagLength: 128 });
    cipher.update(forge.util.createBuffer(forge.util.encodeUtf8(text)));
    cipher.finish();

    const ciphertext = cipher.output.getBytes();
    const tag = cipher.mode.tag.getBytes();
    // combined = ciphertext + tag (tag appended at end, comme WebCrypto)
    const combined = ciphertext + tag;

    return {
        iv:         forge.util.bytesToHex(iv),
        ciphertext: forge.util.bytesToHex(ciphertext),
        tag:        forge.util.bytesToHex(tag),
        combined:   forge.util.bytesToHex(combined)
    };
}

// ─── Déchiffrement AES-256-GCM (node-forge) ──────
async function aesGcmDecrypt(encrypted, keyBytes) {
    const iv         = forge.util.hexToBytes(encrypted.iv);
    const combined   = forge.util.hexToBytes(encrypted.combined);
    // Les 16 derniers bytes sont le tag GCM
    const ciphertext = combined.slice(0, -16);
    const tag        = combined.slice(-16);

    const decipher = forge.cipher.createDecipher('AES-GCM', keyBytes);
    decipher.start({
        iv:        iv,
        tag:       forge.util.createBuffer(tag),
        tagLength: 128
    });
    decipher.update(forge.util.createBuffer(ciphertext));
    const pass = decipher.finish();
    if (!pass) throw new Error('Dechiffrement echoue - mauvaise cle ou donnees corrompues');
    return decipher.output.toString('utf8');
}

// ─── Utilitaires hex (garde compat) ──────────────
function bufToHex(buf) {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}
function hexToBuf(hex) {
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) arr[i/2] = parseInt(hex.substr(i,2), 16);
    return arr.buffer;
}


// ─── Événements Socket.IO ─────────────────────────
function onUserEvent(data, type) {
    const room = data.room;
    // Trouver quel chat correspond à la room
    for (const [chat, state] of Object.entries(chatState)) {
        if (state.room === room) {
            updateMembers(chat, data.members);
            const verb = type === 'joined' ? 'a rejoint' : 'a quitté';
            appendSystemMessage(chat, `👤 ${data.username} ${verb} le chat (${data.count} membre(s))`);
        }
    }
}

async function onMessageReceived(data) {
    // Trouver le chat correspondant à la room du message
    const sock = getSocket();
    for (const [chat, state] of Object.entries(chatState)) {
        if (!state.joined || !state.aesKey) continue;
        // Le message peut venir de n'importe quelle room — on filtre par room stockée
        // Le backend envoie à la room, donc on reçoit seulement les messages de nos rooms
        const isSelf = (data.sender_sid === sock.id);
        try {
            const text = await aesGcmDecrypt(data.encrypted, state.aesKey);
            appendChatMessage(chat, {
                username: data.username,
                text: text,
                isSelf: isSelf,
                timestamp: data.timestamp,
                nonce: data.encrypted.iv,
                ciphertextHex: data.encrypted.ciphertext,
                tagHex: data.encrypted.tag
            });
        } catch (e) {
            // Mauvaise clé ou autre room → ignorer
        }
    }
}

// ─── TP6 : Récupérer l'IP serveur ─────────────────
async function wifiGetIP() {
    try {
        const res = await fetch('/api/tp6/my_ip');
        const data = await res.json();
        const ipEl = document.getElementById('wifi-server-ip');
        const urlEl = document.getElementById('wifi-server-url');
        if (ipEl) ipEl.textContent = data.ip;
        if (urlEl) { urlEl.textContent = data.url; urlEl.title = 'Ouvrir dans Chrome sur Android'; }
        // Afficher dans une petite alerte
        const msg = `📡 IP Serveur : ${data.ip}\n🌐 URL Android : ${data.url}\n\nOuvrez cette URL dans Chrome sur votre Android !`;
        alert(msg);
    } catch(e) {
        alert('Erreur: ' + e.message);
    }
}

// ─── TP6 : Fonction générique de connexion ────────
async function chatJoin(chat, room, usernameId, passwordId, btnId, salt) {
    const state = chatState[chat];
    if (state.joined) {
        // Déconnexion
        getSocket().emit('leave_chat', { room: state.room });
        state.joined = false;
        state.aesKey = null;
        setStatus(chat, false);
        setInputEnabled(chat, false);
        document.getElementById(btnId).textContent = chat === 'wifi' ? '📡 Rejoindre WiFi Chat'
            : chat === 'bt' ? '🔵 Appairer et Rejoindre' : '🔒 Connexion TLS';
        appendSystemMessage(chat, '🔌 Vous avez quitté le chat.');
        return;
    }

    const username = document.getElementById(usernameId).value.trim() || `User_${Math.random().toString(36).substr(2,4)}`;
    const password = document.getElementById(passwordId).value.trim() || 'default';
    setStatus(chat, false, '⏳ Connexion...');

    try {
        // Dériver la clé AES à partir du mot de passe
        state.aesKey = await deriveAESKey(password, salt);
        state.username = username;
        state.joined = true;

        const sock = getSocket();
        sock.emit('join_chat', { room: state.room, username: username });

        setStatus(chat, true, `🟢 Connecté (${username})`);
        setInputEnabled(chat, true);
        document.getElementById(btnId).textContent = '🔌 Quitter';
        document.getElementById(btnId).style.background = 'linear-gradient(135deg, #ef4444, #dc2626)';
    } catch(e) {
        setStatus(chat, false, '❌ Erreur: ' + e.message);
        state.joined = false; state.aesKey = null;
    }
}

// ─── Fonction générique d'envoi ───────────────────
async function chatSend(chat, msgInputId) {
    const state = chatState[chat];
    if (!state.joined || !state.aesKey) return;

    const input = document.getElementById(msgInputId);
    const text = input.value.trim();
    if (!text) return;

    input.value = '';
    try {
        const encrypted = await aesGcmEncrypt(text, state.aesKey);
        const sock = getSocket();
        const timestamp = new Date().toISOString();
        const msg_id = Math.random().toString(36).substr(2) + Date.now().toString(36);

        sock.emit('send_message', {
            room: state.room,
            username: state.username,
            encrypted: encrypted,
            timestamp: timestamp,
            msg_id: msg_id
        });
    } catch(e) {
        appendSystemMessage(chat, '❌ Erreur de chiffrement: ' + e.message);
    }
}

// ─── TP6 WiFi Chat ────────────────────────────────
async function wifiJoin() {
    await chatJoin('wifi', 'tp6-wifi', 'wifi-username', 'wifi-password', 'wifi-join-btn', 'WiFiSalt2024');
}
async function wifiSend() {
    await chatSend('wifi', 'wifi-msg');
}

// ─── TP6 Bluetooth Chat ───────────────────────────
async function btJoin() {
    await chatJoin('bt', 'tp6-bluetooth', 'bt-username', 'bt-password', 'bt-join-btn', 'BluetoothPairingSalt');
}
async function btSend() {
    await chatSend('bt', 'bt-msg');
}

// ─── TP6 TCP/TLS Chat ─────────────────────────────
async function tcpJoin() {
    await chatJoin('tcp', 'tp6-tcp', 'tcp-username', 'tcp-password', 'tcp-join-btn', 'TLSSalt2024');
}
async function tcpSend() {
    await chatSend('tcp', 'tcp-msg');
}
