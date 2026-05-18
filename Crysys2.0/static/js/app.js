// Tab switching logic
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(btn.dataset.tab).classList.add('active');
  });
});

function toast(msg) {
  const tc = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = 'toast';
  el.textContent = msg;
  tc.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

function displayOutput(id, success, data) {
  const out = document.getElementById(id);
  out.classList.remove('empty');
  out.textContent = success ? data : 'Error: ' + data;
  if(!success) out.style.color = 'var(--accent-pink)';
  else out.style.color = 'var(--text-main)';
}

// Check status
fetch('/api/status').then(r => r.json()).then(s => {
  const dot = document.getElementById('status-dot');
  const txt = document.getElementById('status-text');
  if(s.cli_available) { dot.style.background = 'var(--success)'; txt.textContent = 'Engine Online'; }
  else { dot.style.background = 'var(--accent-pink)'; txt.textContent = 'Engine Offline'; }
}).catch(e => console.error(e));

// ==========================================
// TP1: Classic Crypto
// ==========================================
async function runTp1(mode) {
  const algo = document.getElementById('tp1-algo').value;
  const key = document.getElementById('tp1-key').value;
  const text = document.getElementById('tp1-input').value;
  if(!text) return toast('Enter text');
  const endpoint = mode === 'encrypt' ? '/api/encrypt' : '/api/decrypt';
  
  let extras = {};
  if(algo === 'caesar') extras.shift = parseInt(key) || 3;
  if(algo === 'hill') {
    const hasDigits = /\d/.test(key);
    let elementsCount = 0;
    if (hasDigits) {
      elementsCount = key.trim().split(/[\s,;]+/).filter(x => x.length > 0).length;
    } else {
      elementsCount = key.replace(/[^A-Za-z]/g, '').length;
    }
    const size = Math.sqrt(elementsCount);
    extras.matrix_size = (size === 2 || size === 3) ? size : 2;
  }
  // affine params handled simply or ignored if format is bad for now

  const res = await fetch(endpoint, {
    method: 'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({algo, key, text, extras})
  }).then(r => r.json());
  displayOutput('tp1-output', res.success, res.success ? res.output : res.error);
}

document.getElementById('btn-tp1-encrypt').addEventListener('click', () => runTp1('encrypt'));
document.getElementById('btn-tp1-decrypt').addEventListener('click', () => runTp1('decrypt'));

document.getElementById('btn-tp1-analyze').addEventListener('click', async () => {
  const algo = document.getElementById('tp1-analysis-type').value;
  const text = document.getElementById('tp1-analysis-input').value;
  const param = document.getElementById('tp1-analysis-param').value;
  if(!text) return toast('Enter ciphertext to analyze');
  
  let extras = {};
  if(algo === 'freq_analysis') extras.key_len = parseInt(param) || 6;
  if(algo === 'probable_word') extras.probable_word = param;

  const res = await fetch('/api/tp/analyze', {
    method: 'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({algo, text, extras})
  }).then(r => r.json());
  const term = document.getElementById('tp1-analysis-output');
  term.classList.remove('empty');
  if (res.success) {
    term.style.color = '#00ff00';
    term.style.background = '#000000';
    term.style.borderColor = '#00ff00';
    term.style.boxShadow = '0 0 10px rgba(0, 255, 0, 0.2)';
    term.innerHTML = `&gt; ANALYSIS COMPLETE:\n\n${res.output}`;
  } else {
    term.style.color = '#ff003c';
    term.style.background = '#000000';
    term.style.borderColor = '#ff003c';
    term.style.boxShadow = '0 0 10px rgba(255, 0, 60, 0.2)';
    term.innerHTML = `&gt; ERROR: ${res.error}`;
  }
});

// ==========================================
// TP2: Symmetric Crypto
// ==========================================
async function runTp2Text(mode) {
  const algo = document.getElementById('tp2-algo').value;
  const key = document.getElementById('tp2-key').value;
  const text = document.getElementById('tp2-text-input').value;
  if(!text) return toast('Enter text');
  
  const endpoint = mode === 'encrypt' ? '/api/encrypt' : '/api/decrypt';
  const res = await fetch(endpoint, {
    method: 'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({algo, key, text})
  }).then(r => r.json());
  displayOutput('tp2-text-output', res.success, res.success ? res.output : res.error);
}

document.getElementById('btn-tp2-encrypt-text').addEventListener('click', () => runTp2Text('encrypt'));
document.getElementById('btn-tp2-decrypt-text').addEventListener('click', () => runTp2Text('decrypt'));

document.getElementById('btn-tp2-encrypt-file').addEventListener('click', async () => {
  const algo = document.getElementById('tp2-algo').value;
  const key = document.getElementById('tp2-key').value;
  const fileInput = document.getElementById('tp2-file-enc-input');
  if(!fileInput.files[0]) return toast('Select a file');
  
  const fd = new FormData();
  fd.append('file', fileInput.files[0]);
  fd.append('algo', algo);
  fd.append('key', key);
  
  const res = await fetch('/api/encrypt_file', { method: 'POST', body: fd }).then(r => r.json());
  if(res.success) {
    const out = document.getElementById('tp2-file-enc-output');
    out.classList.remove('empty');
    out.innerHTML = `Encrypted successfully! <br><a href="${res.download_url}" style="color:var(--accent-cyan)">Download ${res.filename}</a>`;
  } else {
    displayOutput('tp2-file-enc-output', false, res.error);
  }
});

document.getElementById('btn-tp2-decrypt-file').addEventListener('click', async () => {
  const algo = document.getElementById('tp2-algo').value;
  const key = document.getElementById('tp2-key').value;
  const fileInput = document.getElementById('tp2-file-dec-input');
  if(!fileInput.files[0]) return toast('Select a file');
  
  const fd = new FormData();
  fd.append('file', fileInput.files[0]);
  fd.append('algo', algo);
  fd.append('key', key);
  
  const res = await fetch('/api/decrypt_file', { method: 'POST', body: fd }).then(r => r.json());
  displayOutput('tp2-file-dec-output', res.success, res.success ? "Decryption complete. First 500 chars:\n" + res.output.substring(0, 500) : res.error);
});


// ==========================================
// TP3: Asymmetric Crypto
// ==========================================
document.getElementById('btn-tp3-keygen').addEventListener('click', async () => {
  const algo = document.getElementById('tp3-keygen-algo').value;
  const res = await fetch('/api/keygen', {
    method: 'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({algo})
  }).then(r => r.json());
  displayOutput('tp3-keygen-output', res.success, res.success ? res.output : res.error);
});

async function runTp3(mode) {
  const algo = document.getElementById('tp3-algo').value;
  const key = mode === 'encrypt' ? document.getElementById('tp3-pubkey').value : document.getElementById('tp3-privkey').value;
  const text = document.getElementById('tp3-input').value;
  if(!text || !key) return toast(`Enter ${mode === 'encrypt' ? 'Public' : 'Private'} Key and text`);
  
  const endpoint = mode === 'encrypt' ? '/api/encrypt' : '/api/decrypt';
  const res = await fetch(endpoint, {
    method: 'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({algo, key, text})
  }).then(r => r.json());
  displayOutput('tp3-output', res.success, res.success ? res.output : res.error);
}

document.getElementById('btn-tp3-encrypt').addEventListener('click', () => runTp3('encrypt'));
document.getElementById('btn-tp3-decrypt').addEventListener('click', () => runTp3('decrypt'));

// ==========================================
// TP4: Hash Functions
// ==========================================
document.getElementById('btn-tp4-hash').addEventListener('click', async () => {
  const algo = document.getElementById('tp4-algo').value;
  const text = document.getElementById('tp4-input').value;
  if(!text) return toast('Enter text to hash');
  const res = await fetch('/api/hash', {
    method: 'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({algo, text})
  }).then(r => r.json());
  displayOutput('tp4-output', res.success, res.success ? res.output : res.error);
});

// ==========================================
// TP5: Digital Signatures
// ==========================================
document.getElementById('btn-tp5-keygen').addEventListener('click', async () => {
  const algo = document.getElementById('tp5-algo').value;
  const res = await fetch('/api/keygen', {
    method: 'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({algo})
  }).then(r => r.json());
  
  if (res.success) {
    if (res.private_key) document.getElementById('tp5-privkey').value = res.private_key;
    if (res.public_key) document.getElementById('tp5-pubkey').value = res.public_key;
    displayOutput('tp5-output', true, "🔑 Signature Keypair successfully generated! Keys have been automatically populated below.");
  } else {
    displayOutput('tp5-output', false, res.error);
  }
});

document.getElementById('btn-tp5-sign').addEventListener('click', async () => {
  const algo = document.getElementById('tp5-algo').value;
  const text = document.getElementById('tp5-msg').value;
  const key = document.getElementById('tp5-privkey').value;
  if(!text || !key) return toast('Message and Private Key required');
  const res = await fetch('/api/tp/sign', {
    method: 'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({algo, text, key})
  }).then(r => r.json());
  if (res.success) {
    document.getElementById('tp5-sig').value = res.signature;
    displayOutput('tp5-output', true, `✍️ Message signed successfully!\nSignature generated and populated: \n${res.signature}`);
  } else {
    displayOutput('tp5-output', false, res.error);
  }
});

document.getElementById('btn-tp5-verify').addEventListener('click', async () => {
  const algo = document.getElementById('tp5-algo').value;
  const text = document.getElementById('tp5-msg').value;
  const key = document.getElementById('tp5-pubkey').value;
  const sig = document.getElementById('tp5-sig').value;
  if(!text || !key || !sig) return toast('Message, Public Key, and Signature required');
  const res = await fetch('/api/tp/verify', {
    method: 'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({algo, text, key, signature: sig})
  }).then(r => r.json());
  displayOutput('tp5-output', res.success, res.success ? (res.valid ? "✅ SIGNATURE IS VALID" : "❌ SIGNATURE IS INVALID (Data may have been altered!)") : res.error);
});

// ==========================================
// TP6: Secure Chat
// ==========================================
document.getElementById('btn-send-msg').addEventListener('click', async () => {
  const target_ip = document.getElementById('target-ip').value;
  const sender_name = document.getElementById('sender-name').value;
  const algo = document.getElementById('chat-algo').value;
  const key = document.getElementById('chat-key').value;
  const message = document.getElementById('chat-message').value;
  if(!target_ip || !message) return toast('Target IP and message required');
  const res = await fetch('/api/send', {
    method: 'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({target_ip, sender_name, algo, key, message})
  }).then(r => r.json());
  if(res.success) {
    document.getElementById('chat-message').value = '';
    toast('Message encrypted and sent!');
    loadMessages();
  } else toast('Error sending message: ' + (res.error || 'Connection failed'));
});

document.getElementById('btn-clear-chat').addEventListener('click', async () => {
  await fetch('/api/clear_messages', {method: 'POST'});
  loadMessages();
});

const chatDecryptionCache = {};

async function loadMessages() {
  const area = document.getElementById('messages-area');
  if(!area) return;
  const chatKey = document.getElementById('chat-key').value.trim();
  
  try {
    const msgs = await fetch('/api/messages').then(r => r.json());
    let html = '';
    
    for (let i = 0; i < msgs.length; i++) {
      const m = msgs[i];
      let plainDisplay = m.plain;
      
      if (!plainDisplay && m.direction === 'received') {
        const cacheKey = m.id + '_' + chatKey;
        if (chatDecryptionCache[cacheKey] !== undefined) {
          plainDisplay = chatDecryptionCache[cacheKey];
        } else if (chatKey) {
          chatDecryptionCache[cacheKey] = '⏳ Decrypting...';
          fetch('/api/decrypt', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ algo: m.algo, text: m.encrypted_content, key: chatKey })
          })
          .then(r => r.json())
          .then(res => {
            if (res.success) {
              chatDecryptionCache[cacheKey] = res.output;
            } else {
              chatDecryptionCache[cacheKey] = '❌ (Decryption Failed - Check key)';
            }
            loadMessages();
          })
          .catch(e => {
            chatDecryptionCache[cacheKey] = '❌ (Error)';
            loadMessages();
          });
          plainDisplay = '⏳ Decrypting...';
        } else {
          plainDisplay = '🔒 [Encrypted Content]';
        }
      }
      
      const sender = m.sender_name || 'Anonymous';
      const time = new Date(m.timestamp).toLocaleTimeString();
      const plainText = plainDisplay || '';
      const isFailed = plainText.includes('❌') || plainText.includes('Decryption Failed');
      const isPending = plainText.includes('⏳');
      
      let displayStyle = '';
      if (isFailed) displayStyle = 'color: var(--accent-pink); font-style: italic;';
      else if (isPending) displayStyle = 'color: var(--accent-cyan); font-style: italic;';
      
      html += `
        <div class="msg-bubble ${m.direction}">
          <div class="msg-meta">
            <span>${sender} [${m.algo.toUpperCase()}]</span>
            <span>${time}</span>
          </div>
          <div class="msg-content" style="${displayStyle}">${plainText}</div>
          ${!m.plain ? `<div class="msg-encrypted" title="Encrypted Data">${m.encrypted_content}</div>` : ''}
        </div>
      `;
    }
    
    // Store current scroll position to see if we should scroll to bottom
    const isAtBottom = area.scrollHeight - area.clientHeight <= area.scrollTop + 50;
    area.innerHTML = html;
    if (isAtBottom || html !== '') {
      area.scrollTop = area.scrollHeight;
    }
  } catch (e) {
    console.error("Failed to load messages:", e);
  }
}

setInterval(loadMessages, 3000);
loadMessages();

// ==========================================
// TP1: Extras
// ==========================================
document.getElementById('tp1-input').addEventListener('input', (e) => {
  document.getElementById('tp1-char-count').textContent = e.target.value.length + ' chars';
});

// ==========================================
// TP6: Electronic Voting (Homomorphic)
// ==========================================
let encryptedVotes = [];

document.getElementById('btn-vote-keygen').addEventListener('click', async () => {
  const res = await fetch('/api/vote/keygen', {method: 'POST'}).then(r => r.json());
  if(res.success) {
    document.getElementById('vote-pub-n').value = res.pub_n;
    document.getElementById('vote-priv-pq').value = `p: ${res.priv_p}\nq: ${res.priv_q}`;
    toast('Election Keys Generated');
    encryptedVotes = [];
    document.getElementById('vote-ballot-box').innerHTML = 'No votes cast yet.';
    document.getElementById('vote-tally-output').classList.add('empty');
    document.getElementById('vote-tally-output').textContent = '';
  } else toast('Error generating keys: ' + res.error);
});

document.getElementById('btn-vote-cast').addEventListener('click', async () => {
  const pub_n = document.getElementById('vote-pub-n').value;
  const vote = document.getElementById('vote-choice').value;
  if(!pub_n) return toast('Generate Election Keys first!');
  
  const res = await fetch('/api/vote/cast', {
    method: 'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({pub_n, vote})
  }).then(r => r.json());
  
  if(res.success) {
    encryptedVotes.push(res.ciphertext);
    const box = document.getElementById('vote-ballot-box');
    if(encryptedVotes.length === 1) box.innerHTML = '';
    const voteEl = document.createElement('div');
    voteEl.style.marginBottom = '5px';
    voteEl.textContent = `Vote #${encryptedVotes.length}: ${res.ciphertext.substring(0, 40)}...`;
    box.appendChild(voteEl);
    box.scrollTop = box.scrollHeight;
    toast('Vote encrypted and cast!');
  } else toast('Error casting vote: ' + res.error);
});

document.getElementById('btn-vote-tally').addEventListener('click', async () => {
  const pub_n = document.getElementById('vote-pub-n').value;
  if(!pub_n) return toast('No keys found');
  if(encryptedVotes.length === 0) return toast('No votes to tally');
  
  const res = await fetch('/api/vote/tally', {
    method: 'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({pub_n, votes: encryptedVotes})
  }).then(r => r.json());
  
  if(res.success) {
    document.getElementById('vote-tally-output').dataset.ciphertext = res.tally_ciphertext;
    displayOutput('vote-tally-output', true, `Homomorphic Tally Complete! \nEncrypted Tally: ${res.tally_ciphertext.substring(0, 30)}...`);
  } else toast('Error tallying votes: ' + res.error);
});

document.getElementById('btn-vote-decrypt').addEventListener('click', async () => {
  const pub_n = document.getElementById('vote-pub-n').value;
  const priv_pq = document.getElementById('vote-priv-pq').value;
  const tallyOutput = document.getElementById('vote-tally-output');
  const ciphertext = tallyOutput.dataset.ciphertext;
  
  if(!pub_n || !priv_pq) return toast('Missing keys');
  if(!ciphertext) return toast('Must tally votes first!');
  
  const lines = priv_pq.split('\n');
  const priv_p = lines[0].replace('p: ', '').trim();
  const priv_q = lines[1].replace('q: ', '').trim();
  
  const res = await fetch('/api/vote/decrypt', {
    method: 'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({pub_n, priv_p, priv_q, ciphertext})
  }).then(r => r.json());
  
  if(res.success) {
    displayOutput('vote-tally-output', true, `Final Result Decrypted!\nTotal "Yes" (1) Votes: ${res.result}\nTotal Votes Cast: ${encryptedVotes.length}`);
    tallyOutput.style.color = 'var(--accent-cyan)';
  } else toast('Error decrypting: ' + res.error);
});
