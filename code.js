/* ============================================================
   CareZone2 — encryption module (extracted from cz.html)

   All cryptographic operations live here: key derivation,
   asymmetric keypair setup, and per-message sealing.

   Loaded as a classic <script> BEFORE the inline app script in
   cz.html, so its top-level declarations (COOKIE, the encoding
   helpers, deriveSeed, runSetup, sealEncrypt, hasValidPubKey…)
   are available to the app code as globals — exactly as they
   were when this code lived inline. Depends on TweetNaCl (nacl)
   being loaded first, and calls startApp() (defined in cz.html)
   at the end of setup.
   ============================================================ */

const COOKIE = 'CAREZONE2_PUBLIC_KEY';   // holds the Curve25519 PUBLIC key (encrypt-only)
const ARGON_CDN = 'https://cdn.jsdelivr.net/npm/argon2-browser@1.18.0/dist/argon2-bundled.min.js';
const ARGON_SRI = 'sha384-XOR3aNvHciLPIf6r+2glkrmbBbLmIJ1EChMXjw8eBKBf8gE0rDq1TyUNuRdorOqi';

/* ---------- tiny helpers ---------- */
function getCookie(name){
  const m = document.cookie.match(new RegExp('(?:^|; )'+name+'=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : null;
}
function setCookie(name,value,days){
  document.cookie = name+'='+encodeURIComponent(value)+
    '; max-age='+(days*24*3600)+'; path=/; SameSite=Lax';
  setupDate= 0;
}
// Absolute expiry on a shared calendar boundary: day 0 of the month six months
// on, i.e. the last day of the fifth. Everyone who sets up in the same month
// lands on the same instant, so the jar narrows the setup date to a month
// rather than pinning it to the second the way max-age from now does.
function boundaryExpiry(d){
  d = d || new Date();
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth()+6, 0));
}
function setCookieUntil(name,value,when){
  document.cookie = name+'='+encodeURIComponent(value)+
    '; expires='+when.toUTCString()+'; path=/; SameSite=Lax';
}
// Empties the stored public key and expires the cookie in one go: max-age=0
// tells the browser to drop it, so we don't leave "NAME=" sitting in the jar
// as a trace that something was once set up here.
function clearPubKey(){
  setCookie(COOKIE, '', 0);
  return !hasValidPubKey();
}
function bufToHex(buf){
  return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
// chunked base64 so large video buffers don't blow the call stack
function abToB64(buf){
  const bytes = new Uint8Array(buf);
  let out = '';
  const CH = 0x8000;
  for(let i=0;i<bytes.length;i+=CH){
    out += String.fromCharCode.apply(null, bytes.subarray(i, i+CH));
  }
  return btoa(out);
}
function utf8ToB64(str){
  return abToB64(new TextEncoder().encode(str));
}
function b64ToU8(b64){
  const bin = atob(b64);
  const u = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) u[i] = bin.charCodeAt(i);
  return u;
}
function loadScript(src, integrity){
  return new Promise((res,rej)=>{
    const s=document.createElement('script');
    s.src=src;
    if(integrity){ s.integrity=integrity; s.crossOrigin='anonymous'; }
    s.onload=res; s.onerror=()=>rej(new Error('Failed to load '+src));
    document.head.appendChild(s);
  });
}

/* ==================================================================
   SETUP  ·  derive an asymmetric keypair from the cat's name
   cat's name -> SHA-256 -> Argon2id (32 bytes) -> Curve25519 SECRET key.
   We store ONLY the derived PUBLIC key in the cookie. This app can seal
   messages to it but can NEVER open them. Decryption happens in a separate
   tool that re-derives the SECRET key from the same cat's name.
   ================================================================== */
// Local calendar date as YYYYMMDD (used in the salt, so the keypair is tied
// to the day it was derived). A decryptor must reproduce this exact date.
function localYMD(d){
  d = d || new Date();
  const p = n => String(n).padStart(2,'0');
  return `${d.getFullYear()}${p(d.getMonth()+1)}${p(d.getDate())}`;
}

async function deriveSeed(pw, ymd){
  // SHA-256 the input string, then stretch with Argon2id.
  // Salt = base salt + local YYYYMMDD, so the same name yields a different
  // keypair on different local dates (deterministic within a given date).
  const shaBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pw));
  const shaHex = bufToHex(shaBuf);
  if(typeof argon2 === 'undefined') await loadScript(ARGON_CDN, ARGON_SRI);
  const res = await argon2.hash({
    pass: shaHex,
    salt: 'CAREZONE2SALT01' + ymd.replace(/-/g,''),
    time: 15,           // iterations
    mem: 64 * 1024,     // 16 MB in KiB
    hashLen: 32,        // 32-byte output
    parallelism: 1,
    type: argon2.ArgonType.Argon2id
  });
  return res.hash;      // Uint8Array(32)
}

// Called with the final hex digest produced by the #setup component once the
// user has answered all three screens. Derives the keypair from that digest
// (in place of the old cat's-name input) and starts the app.
async function runSetup(hashed, setupDate){
  if(!hashed){ console.error('runSetup: no digest received from setup'); return; }
  try{
    if(typeof nacl === 'undefined'){
      throw new Error('crypto library not loaded — check your connection or CDN access');
    }
    const seed = await deriveSeed(hashed, setupDate);
    // The 32-byte seed IS the Curve25519 secret key; derive its public key.
    const kp = nacl.box.keyPair.fromSecretKey(seed);
    setCookieUntil(COOKIE, abToB64(kp.publicKey), boundaryExpiry());   // PUBLIC key only
    kp.secretKey.fill(0); seed.fill(0);              // wipe secret material
    startApp();
  }catch(err){
    console.error('Setup failed:', err);
  }
}
// The setup component signals completion via this hook (and a bubbling
// "setup-complete" event); either path lands here with the digest.
window.onSetupComplete = runSetup;

// NaCl box (Curve25519 + XSalsa20-Poly1305) sealed to the stored public key.
// A fresh ephemeral keypair is used per message; its public half travels with
// the ciphertext. Only the SECRET key — re-derived from the cat's name in the
// separate decryptor — can open it. This app cannot.
async function sealEncrypt(base64Str){
  const recipientPub = b64ToU8(getCookie(COOKIE));
  const eph   = nacl.box.keyPair();
  const nonce = nacl.randomBytes(24);
  const msg   = new TextEncoder().encode(base64Str);
  const boxed = nacl.box(msg, nonce, recipientPub, eph.secretKey);
  eph.secretKey.fill(0);   // drop the only local value that could re-open this
  return abToB64(eph.publicKey) + ':' + abToB64(nonce) + ':' + abToB64(boxed);
}

// Only skip setup if the cookie holds a real 32-byte public key (older builds
// stored other things there, so validate rather than trust).
function hasValidPubKey(){
  const c = getCookie(COOKIE);
  if(!c) return false;
  try{ return b64ToU8(c).length === 32; }catch(e){ return false; }
}


/* ==================================================================
   SEAL · a 5x5 mirrored mark derived from the stored PUBLIC key.
   Same key -> same mark, always. A different key -> a different mark,
   which is the only signal this app can give that someone else set it
   up. Read from the cookie on every call, never cached: a cached mark
   would keep showing the old colours at exactly the moment it matters.
   ================================================================== */
const SEAL_PAL = ['#1f3a93','#d97706','#0d9488','#b02a7a',
                  '#c9a227','#3f3f46','#9a3412','#7c9fd4'];

// 15 independent cells (3 columns, mirrored to 5). Each cell takes one
// digest byte: low 3 bits pick the colour, bits 3-4 blank it a quarter
// of the time. Blanks are the one part of the mark that doesn't rely on
// colour vision, so they carry more weight than their share suggests.
async function sealSvg(){
  const c = getCookie(COOKIE);
  if(!c) return '';
  let key;
  try{ key = b64ToU8(c); }catch(e){ return ''; }
  if(key.length !== 32) return '';
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', key));
  let g = '', i = 0;
  for(let row=0; row<5; row++){
    for(let col=0; col<3; col++){
      const v = d[i++];
      if((v & 24) === 0) continue;
      const fill = SEAL_PAL[v & 7];
      g += '<rect x="'+(col*12)+'" y="'+(row*12)+'" width="12" height="12" fill="'+fill+'"/>';
      if(col < 2){
        g += '<rect x="'+((4-col)*12)+'" y="'+(row*12)+'" width="12" height="12" fill="'+fill+'"/>';
      }
    }
  }
  return '<svg viewBox="0 0 60 60" width="22" height="22" '+
         'xmlns="http://www.w3.org/2000/svg" focusable="false">'+g+'</svg>';
}

// Paints into #seal if it's there. Silent on every failure path: a broken
// mark must not become a broken Help button.
async function renderSeal(){
  const host = document.getElementById('seal');
  if(!host) return;
  try{ host.innerHTML = await sealSvg(); }
  catch(e){ host.innerHTML = ''; }
}
