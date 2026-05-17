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
