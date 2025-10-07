// server.js — Voice signaling (tek oda, dinleyici/konuşmacı, Eggdrop webhook)
// ENV: PORT, ALLOWED_ORIGINS, ADMIN_NICKS, CHANNEL_WHITELIST, SECRET_TOKEN, INVITE_TTL_MS, EGGDROP_SECRET
import http from 'http';
import { WebSocketServer } from 'ws';
import { nanoid } from 'nanoid';
import crypto from 'crypto';

const PORT = process.env.PORT || 8080;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*')
  .split(',').map(s => s.trim()).filter(Boolean);
const ADMIN_NICKS = new Set((process.env.ADMIN_NICKS || 'Erik,Lestat')
  .split(',').map(s => s.trim().toLowerCase()));
const CHANNEL_WHITELIST = new Set((process.env.CHANNEL_WHITELIST || '#radyo')
  .split(',').map(s => s.trim().toLowerCase()));
const ROOM_KEYS = ["roomA"];           // tek oda
const SINGLE_ROOM = "roomA";
const SECRET_TOKEN = process.env.SECRET_TOKEN || 'change-this-secret';
const INVITE_TTL_MS = Number(process.env.INVITE_TTL_MS || 60000); // 1 dk
const EGGDROP_SECRET = process.env.EGGDROP_SECRET || '';

function okOrigin(origin){
  if (!origin) return true; // bazı istemciler Origin göndermez
  try {
    const o = new URL(origin);
    // SADECE bu iki kökeni kabul et
    const allow = ["https://www.fisilti.org","https://fisilti.org"];
    return allow.some(a => {
      const A = new URL(a);
      return A.protocol === o.protocol && A.host === o.host;
    });
  } catch { return false; }
}

const now = () => Date.now();
function json(res, code, obj) {
  res.writeHead(code, {'Content-Type':'application/json'});
  res.end(JSON.stringify(obj));
}
function sanitizeNick(n) {
  return String(n || '').replace(/[^A-Za-z0-9_\-\[\]{}^`|]/g,'').slice(0,24);
}
function normNick(n){ return sanitizeNick(n).toLowerCase(); }

function safeEqualHex(a,b){
  try{
    const A = Buffer.from(a,'hex');
    const B = Buffer.from(b,'hex');
    if (A.length !== B.length) return false;
    return crypto.timingSafeEqual(A,B);
  } catch { return false; }
}

// Oda durumu
const state = {
  rooms: Object.fromEntries(ROOM_KEYS.map(k => [k, {
    members: new Map(),        // clientId -> { ws, nick, isAdmin, isSpeaker }
    visibleToAll: false,
    pendingInvites: new Map(), // nick -> expiryTimestamp(ms)
  }])),
  clients: new Map(),          // clientId -> { ws, nick, channel, room, isAdmin, mode? }
};

// Eski davetleri temizle (30 sn)
setInterval(() => {
  for (const key of ROOM_KEYS) {
    const r = state.rooms[key];
    for (const [nick, expiry] of r.pendingInvites.entries()) {
      if (expiry <= now()) r.pendingInvites.delete(nick);
    }
  }
}, 30000);

// HTTP server
const server = http.createServer((req, res) => {
  // Basit sağlık kontrolü
  if (req.method==='GET' && req.url==='/') {
    res.writeHead(200, {'Content-Type':'text/plain'});
    res.end('voicekit signaling online');
    return;
  }

  // === Eggdrop -> Voice webhook (invite / revoke / kick) ===
  if (req.method === 'POST' && req.url === '/webhook/eggdrop') {
    let body=''; req.on('data',ch=>body+=ch);
    req.on('end', async ()=>{
      try{
        const sig = String(req.headers['x-signature'] || '');
        const h   = crypto.createHmac('sha256', EGGDROP_SECRET).update(body).digest('hex');
        if (!safeEqualHex(h, sig)) { res.writeHead(401); res.end('invalid signature'); return; }

        const data    = JSON.parse(body);
        const action  = String(data.action || '');
        const by      = sanitizeNick(String(data.by || ''));
        const target  = sanitizeNick(String(data.target || ''));
        const channel = String(data.channel || '#radyo').toLowerCase();
        const room    = SINGLE_ROOM;

        // (İstersen) sadece belirli kanaldan çağrı kabul et
        if (!CHANNEL_WHITELIST.has(channel)) {
          json(res, 403, { ok:false, error:'channel-not-allowed' }); return;
        }

        if (action === 'invite') {
  const byNorm     = normNick(by);
  const targetNorm = normNick(target);
  const expiry     = now() + INVITE_TTL_MS;

  state.rooms[room].pendingInvites.set(targetNorm, expiry);

  // Oda içindeyse konuşmacıya terfi + popup
  for (const [cid, m] of state.rooms[room].members.entries()) {
    if (m.norm === targetNorm) {
      m.isSpeaker = true;
      send(m.ws, 'speakerGranted', { room, ttl: INVITE_TTL_MS });
      send(m.ws, 'invited', { from: by, ttl: INVITE_TTL_MS, room });
    }
  }
  // Pasif WS bağlantısına popup
  for (const [cid, c] of state.clients.entries()) {
    if ((c.norm || normNick(c.nick)) === targetNorm) {
      send(c.ws, 'invited', { from: by, ttl: INVITE_TTL_MS, room });
    }
  }
  console.log(`[INVITE] ${by} -> ${target} (${room})`);
  json(res, 200, { ok:true }); return;
}

if (action === 'revoke') {
  const targetNorm = normNick(target);
  state.rooms[room].pendingInvites.delete(targetNorm);
  for (const [cid, m] of state.rooms[room].members.entries()) {
    if (m.norm === targetNorm && !m.isAdmin) {
      m.isSpeaker = false;
      send(m.ws, 'speakerRevoked', { room });
    }
  }
  console.log(`[REVOKE] ${by} -> ${target} (${room})`);
  json(res, 200, { ok:true }); return;
}

if (action === 'kick') {
  const targetNorm = normNick(target);
  let kicked = false;
  for (const [cid, m] of state.rooms[room].members.entries()) {
    if (m.norm === targetNorm) {
      send(m.ws, 'kicked', { reason: `Eggdrop by ${by}` });
      state.rooms[room].members.delete(cid);
      try { m.ws.close(4000, 'kicked'); } catch {}
      broadcastRoom(room, { type:'peer-leave', nick: m.nick });
      kicked = true;
    }
  }
  console.log(`[KICK] ${by} -> ${target} (${room}) ${kicked?'OK':'NOT-IN-ROOM'}`);
  json(res, 200, { ok:true }); return;
}
    });
    return;
  }

  // IRC -> webhook: /irc-kick (istersen bırak)
  if (req.method==='POST' && req.url==='/irc-kick') {
    let body=''; req.on('data', c => body+=c);
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        if (data.token !== SECRET_TOKEN) return json(res, 403, { ok:false, error:'bad-token' });
        const room = SINGLE_ROOM;
        const nick = sanitizeNick(String(data.nick || '').trim());
        if (!nick) return json(res, 400, { ok:false, error:'no-nick' });

        const r = state.rooms[room];
        if (!r) return json(res, 404, { ok:false, error:'no-room' });

        let kicked = false;
        for (const [cid, m] of r.members.entries()) {
          if (m.nick === nick) {
            try { m.ws.send(JSON.stringify({ type:'kicked', reason:'irc-kick' })); } catch {}
            try { m.ws.close(4002, 'irc-kick'); } catch {}
            r.members.delete(cid);
            kicked = true;
          }
        }
        if (kicked) {
          broadcastRoom(room, { type:'peer-leave', nick });
          return json(res, 200, { ok:true, status:'kicked-from-voice' });
        }
        return json(res, 200, { ok:true, status:'nick-not-in-voice' });
      } catch {
        return json(res, 500, { ok:false, error:'bad-json' });
      }
    });
    return;
  }
  // IRC -> webhook: /irc-invite  (TOKEN ile basit davet)
  if (req.method === 'POST' && req.url === '/irc-invite') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        if (data.token !== SECRET_TOKEN) return json(res, 403, { ok: false, error: 'bad-token' });

        const room = SINGLE_ROOM;
        const from = sanitizeNick(String(data.from || '').trim());
        const target = sanitizeNick(String(data.nick || '').trim());
        if (!target || !from) return json(res, 400, { ok: false, error: 'missing-from-or-target' });

        const r = state.rooms[room];
        if (!r) return json(res, 404, { ok: false, error: 'no-room' });

        // 1) Daveti pending listesine ekle (1 dakika geçerli)
        const expiry = now() + INVITE_TTL_MS;
        r.pendingInvites.set(target, expiry);

        // 2) Oda içindeyse popup + konuşmacı terfisi
        for (const [cid, m] of r.members.entries()) {
          if (m.nick === target) {
            m.isSpeaker = true;
            send(m.ws, 'speakerGranted', { room, ttl: INVITE_TTL_MS });
            send(m.ws, 'invited', { from, ttl: INVITE_TTL_MS, room });
          }
        }
        // 3) Pasif bağlı ise popup
        for (const [cid, c] of state.clients.entries()) {
          if (c.nick === target) {
            send(c.ws, 'invited', { from, ttl: INVITE_TTL_MS, room });
          }
        }

        console.log(`[INVITE] ${from} -> ${target}`);
        return json(res, { ok: true, invited: target });
      } catch (e) {
        console.error('invite parse fail', e);
        return json(res, 500, { ok: false, error: 'bad-json' });
      }
    });
    return;
  }

  res.writeHead(404); res.end();
});

// WebSocket
const wss = new WebSocketServer({ noServer: true });
server.on('upgrade', (req, socket, head) => {
  const origin = req.headers['origin'];
  if (!okOrigin(origin)) { socket.write('HTTP/1.1 403 Forbidden\r\n\r\n'); socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
});

function send(ws, type, payload = {}) {
  try { ws.send(JSON.stringify({ type, ...payload })); } catch {}
}
function broadcastRoom(roomKey, msgObj, exceptId=null){
  const r = state.rooms[roomKey]; if (!r) return;
  const msg = JSON.stringify(msgObj);
  for (const [cid, m] of r.members.entries()) {
    if (cid === exceptId) continue;
    try { m.ws.send(msg); } catch {}
  }
}

wss.on('connection', (ws) => {
  const clientId = nanoid(10);
  let meta = null;

  ws.on('message', async (buf) => {
    let msg; try { msg = JSON.parse(buf.toString()); } catch { return; }
    const t = msg.type;

    // Pasif tanıtım (panel açmadan WS'e bağlananlar davet popup'ı alabilsin)
    if (t === 'hello') {
  const nickRaw  = sanitizeNick(msg.nick);
  const nickNorm = normNick(nickRaw);
  const channel  = String(msg.channel || '').toLowerCase();

  state.clients.set(clientId, {
    ws, nick: nickRaw, norm: nickNorm, channel, room: null,
    isAdmin: ADMIN_NICKS.has(nickNorm), mode:'passive'
  });

  const exp = state.rooms[SINGLE_ROOM].pendingInvites.get(nickNorm);
  if (exp && exp > now()) {
    send(ws, 'invited', { from: 'Yönetici', ttl: (exp - now()), room: SINGLE_ROOM });
  }
  return;
}


    // Odaya katıl (herkes dinleyici olabilir; konuşma = admin/davet)
    if (t === 'join') {
  const nickRaw  = sanitizeNick(msg.nick);
  const nickNorm = normNick(nickRaw);
  const channel  = String(msg.channel || '').toLowerCase();
  const room     = SINGLE_ROOM;

  if (!CHANNEL_WHITELIST.has(channel)) { send(ws, 'error', { error: 'channel-not-allowed' }); return; }

  const isAdmin  = ADMIN_NICKS.has(nickNorm);

  // konuşma izni: admin -> true; davetli -> true; aksi -> false
  let isSpeaker = isAdmin;
  if (!isAdmin) {
    const expiry = state.rooms[room].pendingInvites.get(nickNorm);
    if (expiry && expiry > now()) {
      isSpeaker = true;
      state.rooms[room].pendingInvites.delete(nickNorm);
    } else { isSpeaker = false; }
  }

  const metaObj = { nick: nickRaw, norm: nickNorm, channel, room, isAdmin };
  state.clients.set(clientId, { ws, ...metaObj });
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
  return;
}


    // meta yoksa diğer mesajları alma
    if (!meta) return;
    const { room, isAdmin } = meta;

    if (t === 'signal') {
  const { to, data } = msg;
  const toNorm = normNick(to);
  for (const [cid, m] of state.rooms[room].members.entries()) {
    if (m.norm === toNorm) { send(m.ws, 'signal', { from: meta.nick, data }); break; }
  }
  return;
}



    // Liste görünürlüğü (istersen açık bırak)
    if (t === 'admin:setVisibleToAll' && isAdmin) {
      state.rooms[room].visibleToAll = !!msg.value;
      broadcastRoom(room, { type:'visibleToAll', value: !!msg.value });
      return;
    }

    // 🔒 İstemciden admin komutlarını kapat (invite/kick/revoke/forceMute)
    if (t === 'admin:invite' || t === 'admin:kick' || t === 'admin:revoke' || t === 'admin:forceMute') {
      send(ws, 'error', { error: 'not-authorized' });
      return;
    }
  });

  ws.on('close', () => {
    const c = state.clients.get(clientId);
    if (c) {
      const { room, nick } = c;
      state.clients.delete(clientId);
      state.rooms[room]?.members.delete(clientId);
      if (room) broadcastRoom(room, { type:'peer-leave', nick });
    }
  });
});

server.listen(PORT, () => console.log('listening on', PORT));





