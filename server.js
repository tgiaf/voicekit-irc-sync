// server.js — Voice signaling (tek oda, konuşmacı zorunlu, Eggdrop webhook)
// ENV: PORT, ALLOWED_ORIGINS, ADMIN_NICKS, CHANNEL_WHITELIST, SECRET_TOKEN, INVITE_TTL_MS, EGGDROP_SECRET
import http from 'http';
import { WebSocketServer } from 'ws';
import { nanoid } from 'nanoid';
import crypto from 'crypto';

const PORT = process.env.PORT || 8080;

// Örn: "https://fisilti.org,https://www.fisilti.org"
// boşsa "*" = hepsi (önerilmez)
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// admin nickleri küçük harf saklıyoruz
const ADMIN_NICKS = new Set(
  (process.env.ADMIN_NICKS || 'erik,lestat')
    .split(',')
    .map(s => s.trim().toLowerCase())
);

// sadece bu kanaldan katılsın
const CHANNEL_WHITELIST = new Set(
  (process.env.CHANNEL_WHITELIST || '#radyo')
    .split(',')
    .map(s => s.trim().toLowerCase())
);

const SINGLE_ROOM   = 'roomA'; // tek oda
const SECRET_TOKEN  = process.env.SECRET_TOKEN   || 'change-this-secret';
const INVITE_TTL_MS = Number(process.env.INVITE_TTL_MS || 60_000); // 1 dk
const EGGDROP_SECRET= process.env.EGGDROP_SECRET || '5f7a2c7f3b2a9f0b0cd1d5e2a1b47b8fa7c2bd31f8f8479a6b3c2d1e0f9a7c5d'; // Eggdrop secret'ı ENV'den gelmezse Tcl'deki varsayılanı kullan

function okOrigin(origin){
  if (!origin) return true; // bazı istemciler Origin yollamaz
  if (ALLOWED_ORIGINS.includes('*')) return true;
  try {
    const o = new URL(origin);
    return ALLOWED_ORIGINS.some(a => {
      const A = new URL(a);
      return A.protocol === o.protocol && A.host === o.host;
    });
  } catch { return false; }
}

const now = () => Date.now();

function json(res, code, obj){
  res.writeHead(code, { 'Content-Type':'application/json' });
  res.end(JSON.stringify(obj));
}

function sanitizeNick(n){
  return String(n || '').replace(/[^A-Za-z0-9_\-\[\]{}^`|]/g,'').slice(0,24);
}
function normNick(n){ return sanitizeNick(n).toLowerCase(); }

function safeEqualHex(a, b){
  try{
    const A = Buffer.from(String(a), 'hex');
    const B = Buffer.from(String(b), 'hex');
    if (A.length !== B.length) return false;
    return crypto.timingSafeEqual(A, B);
  } catch { return false; }
}

// ---- Oda durumu ----
const state = {
  rooms: {
    [SINGLE_ROOM]: {
      members: new Map(),       // clientId -> { ws, nick, norm, isAdmin, isSpeaker: true }
      visibleToAll: false,
      pendingInvites: new Map() // normNick -> expiry(ms)
    }
  },
  // Artık sadece Odaya Katılanlar veya Davet alanlar bu listede olacak.
  // Pasif dinleyici konsepti KALDIRILDI.
  clients: new Map()            // clientId -> { ws, nick, norm, channel, room|null, isAdmin }
};

// Eski davetleri temizle (30 sn)
setInterval(() => {
  const r = state.rooms[SINGLE_ROOM];
  for (const [nk, exp] of r.pendingInvites.entries()){
    if (exp <= now()) r.pendingInvites.delete(nk);
  }
}, 30_000);

// ---- HTTP server ----
const server = http.createServer((req, res) => {
  // Sağlık
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'Content-Type':'text/plain' });
    res.end('voicekit signaling online');
    return;
  }

  // === Eggdrop -> Voice webhook (invite / revoke / kick) ===
if (req.method === 'POST' && req.url === '/webhook/eggdrop') {
  let body = '';
  req.on('data', ch => body += ch);
  req.on('end', () => {
    try {
      const sigHdr = String(req.headers['x-signature'] || '');
      const calc = crypto.createHmac('sha256', EGGDROP_SECRET)
        .update(body)
        .digest('hex');

      // ✅ Gelişmiş Teşhis Logları (Sorunu bulmak için eklendi)
      console.log('--- Eggdrop Webhook Request ---');
      console.log('Received Signature (Bottan gelen):', sigHdr);
      console.log('Calculated Signature (Sunucunun hesapladığı):', calc);
      console.log('Kullanılan Secret Uzunluğu:', (EGGDROP_SECRET || '').length);
      console.log('Gelen Ham Veri (Body):', body);
      console.log('---------------------------------');

      if (!safeEqualHex(calc, sigHdr)) {
        console.error('[EGG] HATA: İMZALAR UYUŞMUYOR!');
        res.writeHead(401);
        res.end('invalid signature'); // Doğru hata mesajı
        return;
      }

      const data = JSON.parse(body || '{}');
      const action = String(data.action || '');
      const byRaw = sanitizeNick(String(data.by || ''));
      const tgtRaw = sanitizeNick(String(data.target || ''));
      const chan = String(data.channel || '#radyo').toLowerCase();
      const room = SINGLE_ROOM;

      if (!chan || !CHANNEL_WHITELIST.has(chan)) {
        json(res, 403, { ok: false, error: 'channel-not-allowed' });
        return;
      }
      
      const byNorm = normNick(byRaw);
      const tgtNorm = normNick(tgtRaw);

      if (action === 'invite') {
        const expiry = now() + INVITE_TTL_MS;
        state.rooms[room].pendingInvites.set(tgtNorm, expiry);

        // O an bağlı olan ve odaya katılmamış tüm istemcilere (yeni modelde bu, `join` yapmaya çalışanlardır) davet gönder.
        // NOT: Yeni modelde 'passive' mod kaldırıldığı için, bu döngü daveti sadece ZATEN ODAYA BAĞLI OLANLARA
        // veya Henüz `join` yapmamış ama `hello` yerine bağlanmış olanlara ulaştırır.
        // Yeni modelde davetin alınması client'ın join denemesi sırasında davetli olup olmadığının kontrolüyle sağlanacak.
        // Ancak yine de client açıksa popup gözüksün diye gönderelim.
        for (const [cid, c] of state.clients.entries()) {
          if (c.norm === tgtNorm) { // Sadece nick eşleşenlere
             // Eğer ODA'daysa ve admin değilse 'speakerGranted' (Zaten isSpeaker:true yapılacak)
             // send(c.ws, 'speakerGranted', { room, ttl: INVITE_TTL_MS });
             send(c.ws, 'invited', { from: byRaw, ttl: INVITE_TTL_MS, room });
          }
        }
        
        console.log(`[INVITE] ${byRaw} -> ${tgtRaw}`);
        json(res, 200, { ok: true });
        return;
      }

      // Diğer action'lar (revoke, kick) olduğu gibi kalabilir...
      if (action === 'revoke') {
        state.rooms[room].pendingInvites.delete(tgtNorm);
        for (const [cid, m] of state.rooms[room].members.entries()) {
          if (m.norm === tgtNorm && !m.isAdmin) {
            // isSpeaker=false ayarı artık gereksiz, herkes isSpeaker:true olacak
            // m.isSpeaker = false; // KALDIRILDI
            send(m.ws, 'speakerRevoked', { room }); // Yine de client'a bilgi verelim
            // Revoke edilirse, davet kalktığı için odaya katılımı engellemek gereksiz (tekrar davet edilene kadar)
            // Ama o an odadaysa admin değilse kickleyebiliriz. (Şimdilik kicklemiyoruz, sadece daveti kaldırıyoruz)
          }
        }
        console.log(`[REVOKE] ${byRaw} -> ${tgtRaw}`);
        json(res, 200, { ok: true });
        return;
      }

      if (action === 'kick') {
        let kicked = false;
        for (const [cid, m] of state.rooms[room].members.entries()) {
          if (m.norm === tgtNorm) {
            send(m.ws, 'kicked', { reason: `Eggdrop by ${byRaw}` });
            state.rooms[room].members.delete(cid);
            try { m.ws.close(4000, 'kicked'); } catch {}
            broadcastRoom(room, { type: 'peer-leave', nick: m.nick });
            kicked = true;
          }
        }
        console.log(`[KICK] ${byRaw} -> ${tgtRaw} ${kicked ? 'OK' : 'NOT-IN-ROOM'}`);
        json(res, 200, { ok: true });
        return;
      }

      json(res, 400, { ok: false, error: 'unknown-action' });

    } catch (e) {
      console.error('webhook/eggdrop parse fail', e);
      json(res, 400, { ok: false, error: 'bad-json' });
    }
  });
  return;
}
// ... [HTTP sunucusunun geri kalanı, /irc-kick ve /irc-invite dahil] ...
  // === Basit /irc-kick (token'lı) — istersen tut ===
  if (req.method === 'POST' && req.url === '/irc-kick') {
    let body=''; req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        if (data.token !== SECRET_TOKEN) { json(res, 403, { ok:false, error:'bad-token' }); return; }
        const nickRaw = sanitizeNick(String(data.nick || ''));
        const tgtNorm = normNick(nickRaw);
        const room    = SINGLE_ROOM;

        let kicked = false;
        for (const [cid, m] of state.rooms[room].members.entries()){
          if (m.norm === tgtNorm){
            try { send(m.ws, 'kicked', { reason:'irc-kick' }); } catch {}
            try { m.ws.close(4002, 'irc-kick'); } catch {}
            state.rooms[room].members.delete(cid);
            kicked = true;
          }
        }
        if (kicked) {
          broadcastRoom(room, { type:'peer-leave', nick: nickRaw });
          json(res, 200, { ok:true, status:'kicked-from-voice' });
        } else {
          json(res, 200, { ok:true, status:'nick-not-in-voice' });
        }
      } catch (e) {
        json(res, 500, { ok:false, error:'bad-json' });
      }
    });
    return;
  }

  // === Token'lı /irc-invite (opsiyonel) ===
  if (req.method === 'POST' && req.url === '/irc-invite') {
    let body=''; req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const data  = JSON.parse(body || '{}');
        if (data.token !== SECRET_TOKEN) { json(res, 403, { ok:false, error:'bad-token' }); return; }

        const fromRaw = sanitizeNick(String(data.from || 'Yönetici'));
        const tgtRaw  = sanitizeNick(String(data.nick  || ''));
        if (!tgtRaw) { json(res, 400, { ok:false, error:'no-target' }); return; }
        const tgtNorm = normNick(tgtRaw);
        const room    = SINGLE_ROOM;

        const expiry = now() + INVITE_TTL_MS;
        state.rooms[room].pendingInvites.set(tgtNorm, expiry);

        // Odadaysa terfi + popup (Artık herkes speaker)
        for (const [cid, m] of state.rooms[room].members.entries()){
          if (m.norm === tgtNorm){
            m.isSpeaker = true; // Zaten true olacak ama yine de...
            send(m.ws, 'invited', { from: fromRaw, ttl: INVITE_TTL_MS, room });
          }
        }
        // Pasif WS varsa popup (yeni modelde passive yok, ama bağlanmış olanlara gönder)
        for (const [cid, c] of state.clients.entries()){
          if ((c.norm || normNick(c.nick)) === tgtNorm){
            send(c.ws, 'invited', { from: fromRaw, ttl: INVITE_TTL_MS, room });
          }
        }
        console.log(`[INVITE/token] ${fromRaw} -> ${tgtRaw}`);
        json(res, 200, { ok:true, invited: tgtRaw });
      } catch (e) {
        console.error('irc-invite parse fail', e);
        json(res, 500, { ok:false, error:'bad-json' });
      }
    });
    return;
  }

  // 404
  res.writeHead(404); res.end();
});

// ---- WebSocket ----
const wss = new WebSocketServer({ noServer: true });
server.on('upgrade', (req, socket, head) => {
  const origin = req.headers['origin'];
  if (!okOrigin(origin)) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
});

function send(ws, type, payload = {}) {
  try { ws.send(JSON.stringify({ type, ...payload })); } catch {}
}
function broadcastRoom(roomKey, msgObj, exceptId = null){
  const r = state.rooms[roomKey]; if (!r) return;
  const s = JSON.stringify(msgObj);
  for (const [cid, m] of r.members.entries()){
    if (cid === exceptId) continue;
    try { m.ws.send(s); } catch {}
  }
}

wss.on('connection', (ws) => {
  const clientId = nanoid(10);
  let meta = null;

  ws.on('message', (buf) => {
    let msg;
    try { msg = JSON.parse(buf.toString()); } catch { return; }
    const t = msg.type;

    // Pasif tanıtım (hello) KALDIRILDI. Artık ilk mesaj join olacak.
    if (t === 'hello') {
      // Yine de client'ın nick bilgisini alıp, davet mesajını atabilmek için
      // Client listesine ekleyelim ama "passive" mode'da.
      const nickRaw  = sanitizeNick(msg.nick);
      const nickNorm = normNick(nickRaw);
      const channel  = String(msg.channel || '').toLowerCase();
      
      // Geçici olarak client listesine ekleyelim ki davet geldiğinde popup çıksın.
      // Room'a katılana kadar `meta` null kalacak.
      state.clients.set(clientId, {
        ws, nick: nickRaw, norm: nickNorm, channel, room: null,
        isAdmin: ADMIN_NICKS.has(nickNorm), mode:'passive'
      });
      
      const exp = state.rooms[SINGLE_ROOM].pendingInvites.get(nickNorm);
      if (exp && exp > now()) {
        send(ws, 'invited', { from:'Yönetici', ttl:(exp-now()), room:SINGLE_ROOM });
      }
      return;
    }

    // Odaya katıl (dinleyici KABUL EDİLMEYECEK)
    if (t === 'join') {
      const nickRaw  = sanitizeNick(msg.nick);
      const nickNorm = normNick(nickRaw);
      const channel  = String(msg.channel || '').toLowerCase();
      const room     = SINGLE_ROOM;

      if (!CHANNEL_WHITELIST.has(channel)) { send(ws, 'error', { error:'channel-not-allowed' }); return; }

      const isAdmin  = ADMIN_NICKS.has(nickNorm);
      let isInvited  = false;
      
      const exp = state.rooms[room].pendingInvites.get(nickNorm);
      if (exp && exp > now()) {
        isInvited = true;
        state.rooms[room].pendingInvites.delete(nickNorm);
      }
      
      // **YENİ KURAL: YALNIZCA ADMIN VEYA DAVETLİLER KATILABİLİR**
      if (!isAdmin && !isInvited) {
        send(ws, 'error', { error:'not-authorized-to-join' });
        console.log(`[JOIN FAIL] ${nickRaw} -> Not Admin or Invited`);
        return;
      }
      
      // Artık katılan herkes KONUŞMACI
      const isSpeaker = true;
      
      meta = { nick: nickRaw, norm: nickNorm, channel, room, isAdmin };
      state.clients.set(clientId, { ws, ...meta }); // Eğer client önceden hello ile kaydolduysa bu update eder.
      state.rooms[room].members.set(clientId, { ws, nick: nickRaw, norm: nickNorm, isAdmin, isSpeaker });

      send(ws, 'joined', {
        clientId, room,
        you: { nick: nickRaw, isAdmin, isSpeaker },
        visibleToAll: state.rooms[room].visibleToAll,
        members: [...state.rooms[room].members.values()].map(m => ({
          nick: m.nick, isAdmin: m.isAdmin, isSpeaker: m.isSpeaker
        }))
      });

      broadcastRoom(room, { type:'peer-join', nick: nickRaw, isSpeaker }, clientId);
      console.log(`[JOIN SUCCESS] ${nickRaw} -> isSpeaker: ${isSpeaker}, isAdmin: ${isAdmin}, isInvited: ${isInvited}`);
      return;
    }

    if (!meta && !state.clients.has(clientId)) return; // Meta null ise ve hello da geçilmemişse (eskiden join denemesi yapmamışsa)

    // Eğer hello ile bağlanmış bir client, odaya katılmadan signal göndermeye çalışırsa engelle.
    if (!meta && state.clients.get(clientId)?.mode === 'passive') return;
    
    // Eğer meta yoksa, (hello ile passive bağlanmış) ama `join` değilse, hata ver.
    if (!meta) {
      // Eğer client daha önce hello ile bağlanmışsa, meta'yı alalım.
      meta = state.clients.get(clientId);
      if (!meta || !meta.room) return; // Hala odaya katılmamış.
    }
    
    const { room, isAdmin } = meta;

    if (t === 'signal') {
      // Odaya katılmamışsa signal göndermeyi engelle
      if (!state.rooms[room]?.members.has(clientId)) return;
      
      const { to, data } = msg;
      const toNorm = normNick(to);
      try {
        console.log('[SIGNAL]', meta.nick, '→', to, data?.sdp?.type || (data?.candidate ? 'candidate' : ''));
      } catch {}
      for (const [cid, m] of state.rooms[room].members.entries()){
        if (m.norm === toNorm){
          send(m.ws, 'signal', { from: meta.nick, data });
          break;
        }
      }
      return;
    }

    if (t === 'admin:setVisibleToAll' && isAdmin) {
      state.rooms[room].visibleToAll = !!msg.value;
      broadcastRoom(room, { type:'visibleToAll', value: !!msg.value });
      return;
    }

    // istemciden admin komutları kapalı
    if (t === 'admin:invite' || t === 'admin:kick' || t === 'admin:revoke' || t === 'admin:forceMute') {
      send(ws, 'error', { error:'not-authorized' });
      return;
    }
  });

  ws.on('close', () => {
    const c = state.clients.get(clientId);
    if (c) {
      const { room, nick } = c;
      state.clients.delete(clientId);
      if (room) { // Sadece Odaya KATILMIŞSA (meta.room !== null)
        state.rooms[room]?.members.delete(clientId);
        broadcastRoom(room, { type:'peer-leave', nick });
      }
    }
  });
});

server.listen(PORT, () => console.log('listening on', PORT));
