// server.js (WebSocket + /irc-kick webhook + admin-only invites with 1-minute expiry)
// ENV: PORT, ALLOWED_ORIGINS, ADMIN_NICKS, CHANNEL_WHITELIST, ROOM_KEYS, SECRET_TOKEN, INVITE_TTL_MS
import http from 'http';
import { WebSocketServer } from 'ws';
import { nanoid } from 'nanoid';

const PORT = process.env.PORT || 8080;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*').split(',').map(s=>s.trim());
const ADMIN_NICKS = new Set((process.env.ADMIN_NICKS || 'Erik,Lestat').split(',').map(s=>s.trim()));
const CHANNEL_WHITELIST = new Set((process.env.CHANNEL_WHITELIST || '#radyo').split(',').map(s=>s.trim()));
const ROOM_KEYS = (process.env.ROOM_KEYS || 'roomA,roomB,roomC').split(',').map(s=>s.trim());
const SECRET_TOKEN = process.env.SECRET_TOKEN || 'change-this-secret';
const INVITE_TTL_MS = Number(process.env.INVITE_TTL_MS || 60000); // 1 dakika

function okOrigin(origin){ if(!origin) return false; if(ALLOWED_ORIGINS.includes('*')) return true; return ALLOWED_ORIGINS.some(a=>origin.startsWith(a)); }
const now = () => Date.now();

// Oda durumu
const state = {
  rooms: Object.fromEntries(ROOM_KEYS.map(k => [k, {
    members: new Map(),         // clientId -> { ws, nick, isAdmin }
    visibleToAll: false,
    pendingInvites: new Map()   // nick -> expiryTimestamp(ms)
  }])),
  clients: new Map()            // clientId -> { ws, nick, channel, room, isAdmin }
};

// Geçmiş davetleri temizlik (30 sn)
setInterval(() => {
  for (const key of ROOM_KEYS) {
    const r = state.rooms[key];
    for (const [nick, expiry] of r.pendingInvites.entries()) {
      if (expiry <= now()) r.pendingInvites.delete(nick);
    }
  }
}, 30000);

function json(res, code, obj){ res.writeHead(code, {'Content-Type':'application/json'}); res.end(JSON.stringify(obj)); }
function sanitizeNick(n){ return String(n||'').replace(/[^A-Za-z0-9_\-\[\]{}^`|]/g,'').slice(0,24); }

const server = http.createServer((req, res) => {
  if (req.method==='GET' && req.url==='/') {
    res.writeHead(200, {'Content-Type':'text/plain'});
    res.end('voicekit signaling online');
    return;
  }

  // IRC -> webhook: /irc-kick
  if (req.method==='POST' && req.url==='/irc-kick') {
    let body=''; req.on('data', c => body+=c); req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        if (data.token !== SECRET_TOKEN) return json(res, 403, { ok:false, error:'bad-token' });
        const room = (data.room || ROOM_KEYS[0]);
        const nick = String(data.nick || '').trim();
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

  res.writeHead(404); res.end();
});

const wss = new WebSocketServer({ noServer: true });
server.on('upgrade', (req, socket, head) => {
  const origin = req.headers['origin'];
  if (!okOrigin(origin)) { socket.write('HTTP/1.1 403 Forbidden\r\n\r\n'); socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
});

function send(ws, type, payload){ try { ws.send(JSON.stringify({ type, ...payload })); } catch {} }
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

  ws.on('message', (buf) => {
    let msg; try { msg = JSON.parse(buf.toString()); } catch { return; }
    const t = msg.type;

    if (t === 'join') {
  const nick = sanitizeNick(msg.nick);
  const channel = String(msg.channel || '');
  const room = String(msg.room || ROOM_KEYS[0]);

  if (!CHANNEL_WHITELIST.has(channel)) { send(ws, 'error', { error: 'channel-not-allowed' }); return; }
  if (!ROOM_KEYS.includes(room)) { send(ws, 'error', { error: 'invalid-room' }); return; }

  const isAdmin = ADMIN_NICKS.has(nick.toLowerCase());

  // Konuşma izni (speaker):
  // - admin ise: true
  // - admin değilse: yalnızca geçerli daveti varsa true, yoksa false (dinleyici)
  let isSpeaker = isAdmin;
  if (!isAdmin) {
    const expiry = state.rooms[room].pendingInvites.get(nick);
    if (expiry && expiry > now()) {
      isSpeaker = true;
      state.rooms[room].pendingInvites.delete(nick); // daveti tüket
    } else {
      isSpeaker = false; // davetsiz -> dinleyici
    }
  }

  // client meta & oda kaydı
  const metaObj = { ws, nick, channel, room, isAdmin };
  state.clients.set(clientId, metaObj);
  state.rooms[room].members.set(clientId, { ws, nick, isAdmin, isSpeaker });

  // Katılana yanıt
  send(ws, 'joined', {
    clientId, room,
    you: { nick, isAdmin, isSpeaker },
    visibleToAll: state.rooms[room].visibleToAll,
    members: [...state.rooms[room].members.values()].map(m => ({
      nick: m.nick, isAdmin: m.isAdmin, isSpeaker: m.isSpeaker
    }))
  });

  // Diğerlerine duyur
  broadcastRoom(room, { type: 'peer-join', nick, isSpeaker }, clientId);
  return;
}


      // admin dışı kullanıcı: son 1 dk içinde davet şart (tek kullanımlık)
      if (!isAdmin) {
        const expiry = state.rooms[room].pendingInvites.get(nick);
        if (!expiry || expiry < now()) {
          send(ws, 'error', { error: 'not-invited-or-expired' });
          return;
        }
        state.rooms[room].pendingInvites.delete(nick); // daveti tüket
      }

      meta = { nick, channel, room, isAdmin };
      state.clients.set(clientId, { ws, ...meta });
      state.rooms[room].members.set(clientId, { ws, nick, isAdmin });

      send(ws, 'joined', {
        clientId, room,
        you: { nick, isAdmin },
        visibleToAll: state.rooms[room].visibleToAll,
        members: [...state.rooms[room].members.values()].map(m => ({ nick:m.nick, isAdmin:m.isAdmin }))
      });

      broadcastRoom(room, { type:'peer-join', nick }, clientId);
      return;
    }

    if (!meta) return;
    const { room, isAdmin } = meta;

    if (t === 'signal') {
      const { to, data } = msg;
      for (const [cid, m] of state.rooms[room].members.entries()) {
        if (m.nick === to) { send(m.ws, 'signal', { from: meta.nick, data }); break; }
      }
      return;
    }

    // admin kontrolleri
    if (t === 'admin:setVisibleToAll' && isAdmin) {
      state.rooms[room].visibleToAll = !!msg.value;
      broadcastRoom(room, { type:'visibleToAll', value: !!msg.value });
      return;
    }

   // admin daveti: tek kullanımlık + süreli (1 dk)
if (t === 'admin:invite' && isAdmin) {
  const target = sanitizeNick(msg.nick);
  const expiry = now() + INVITE_TTL_MS;
  state.rooms[room].pendingInvites.set(target, expiry);

  // admin’e bilgi (echo)
  send(ws, 'invited', { nick: target, expiresAt: expiry });

  // 1) Oda içindeki hedefi anında konuşmacı yap (dinleyiciyse terfi)
  for (const [cid, m] of state.rooms[room].members.entries()) {
    if (m.nick === target) {
      m.isSpeaker = true;
      send(m.ws, 'speakerGranted', { room, ttl: INVITE_TTL_MS });
      break;
    }
  }

  // 2) Pasif/aktif bağlı hedefe davet popup’ı gönder
  for (const [cid, m] of state.rooms[room].members.entries()) {
    if (m.nick === target) send(m.ws, 'invited', { from: meta.nick, ttl: INVITE_TTL_MS, room });
  }
  for (const [cid, c] of state.clients.entries()) {
    if (c.nick === target && c.mode === 'passive') {
      send(c.ws, 'invited', { from: meta.nick, ttl: INVITE_TTL_MS, room });
    }
  }

  return;
}




    // bekleyen daveti kaldır + içerdeyse at
    if (t === 'admin:revoke' && isAdmin) {
      const target = sanitizeNick(msg.nick);
      state.rooms[room].pendingInvites.delete(target);
      for (const [cid, m] of state.rooms[room].members.entries()) {
        if (m.nick === target) {
          send(m.ws,'kicked',{reason:'revoked'});
          try { m.ws.close(4001,'revoked'); } catch {}
          state.rooms[room].members.delete(cid);
        }
      }
      broadcastRoom(room,{type:'peer-leave',nick:target});
      return;
    }

    if (t === 'admin:kick' && isAdmin) {
      const target = sanitizeNick(msg.nick);
      for (const [cid, m] of state.rooms[room].members.entries()) {
        if (m.nick === target) {
          send(m.ws,'kicked',{reason:'kicked'});
          try { m.ws.close(4000,'kicked'); } catch {}
          state.rooms[room].members.delete(cid);
        }
      }
      broadcastRoom(room,{type:'peer-leave',nick:target});
      return;
    }

    if (t === 'admin:forceMute' && isAdmin) {
      broadcastRoom(room, { type:'forceMute' });
      return;
    }
  });

  ws.on('close', () => {
    const c = state.clients.get(clientId);
    if (c) {
      const { room, nick } = c;
      state.clients.delete(clientId);
      state.rooms[room]?.members.delete(clientId);
      broadcastRoom(room, { type:'peer-leave', nick });
    }
  });
});

server.listen(PORT, () => console.log('listening on', PORT));



