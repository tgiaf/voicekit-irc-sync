// server.js — Voice signaling (tek oda, konuşmacı zorunlu, Eggdrop webhook, sadece seslichat yetkili)
import http from 'http';
import { WebSocketServer } from 'ws';
import { nanoid } from 'nanoid';
import crypto from 'crypto';

const PORT = process.env.PORT || 8080;

// Örn: "https://fisilti.org,https://www.fisilti.org"
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

// sadece bu kanaldan katılım
const CHANNEL_WHITELIST = new Set(
  (process.env.CHANNEL_WHITELIST || '#sesli')
    .split(',')
    .map(s => s.trim().toLowerCase())
);
// --- ODA ADI BELİRLEME ---
function getRoomNameFromChannel(channel) {
    const ch = channel.toLowerCase();
    if (ch.startsWith('private_')) return ch; 
    if (ch === '#sesli') return 'roomA';
    return ch.replace('#', 'room_'); 
}

const INVITE_TTL_MS = Number(process.env.INVITE_TTL_MS || 60_000);
const EGGDROP_SECRET = process.env.EGGDROP_SECRET || '5f7a2c7f3b2a9f0b0cd1d5e2a1b47b8fa7c2bd31f8f8479a6b3c2d1e0f9a7c5d';
const ALLOWED_BOT = 'seslichat';

// ---- STATE (MULTI-ROOM) ----
const state = {
  rooms: new Map(),
  clients: new Map(),
};

function getOrCreateRoom(roomName) {
    if (!state.rooms.has(roomName)) {
        state.rooms.set(roomName, {
            members: new Map(),
            visibleToAll: false,
            pendingInvites: new Map(),
            createdAt: Date.now()
        });
        if (roomName === 'roomA') ensureSeslichatBot(roomName);
    }
    return state.rooms.get(roomName);
}

function ensureSeslichatBot(roomName) {
  const r = state.rooms.get(roomName);
  if (!r) return;
  const already = [...r.members.values()].some(m => m.norm === ALLOWED_BOT);
  if (!already) {
    const fakeId = `bot-${ALLOWED_BOT}-${roomName}`;
    r.members.set(fakeId, {
      ws: null, nick: ALLOWED_BOT, norm: ALLOWED_BOT,
      isAdmin: true, isSpeaker: false, isBot: true, isMuted: true,
    });
  }
}

// Oda Temizliği (Garbage Collection)
setInterval(() => {
    for (const [roomName, room] of state.rooms.entries()) {
        if (roomName === 'roomA') continue;
        if (room.members.size === 0 && room.pendingInvites.size === 0) {
            state.rooms.delete(roomName);
        }
    }
}, 600_000);

// Davet Temizliği
setInterval(() => {
  for (const [name, room] of state.rooms.entries()) {
      for (const [nk, exp] of room.pendingInvites.entries()) {
        if (exp <= Date.now()) room.pendingInvites.delete(nk);
      }
  }
}, 30_000);

getOrCreateRoom('roomA');
const server = http.createServer((req, res) => {
  // Sağlık
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('voicekit signaling online');
    return;
  }

  // === Eggdrop -> Voice webhook (invite / revoke / kick) ===
  if (req.method === 'POST' && req.url === '/webhook/eggdrop') {
    let body = '';
    req.on('data', ch => (body += ch));
    req.on('end', () => {
      try {
        const sigHdr = String(req.headers['x-signature'] || '');
        const calc = crypto
          .createHmac('sha256', EGGDROP_SECRET)
          .update(body)
          .digest('hex');

        if (!safeEqualHex(calc, sigHdr)) {
          console.error('[EGG] HATA: İMZALAR UYUŞMUYOR!');
          res.writeHead(401);
          res.end('invalid signature');
          return;
        }

        const data = JSON.parse(body || '{}');
        const action = String(data.action || '');
        const byRaw = sanitizeNick(String(data.by || ''));
        const tgtRaw = sanitizeNick(String(data.target || ''));
        const chan = String(data.channel || '#sesli').toLowerCase();
        const roomName = getRoomNameFromChannel(chan);
        const room = getOrCreateRoom(roomName);
        const byNorm = normNick(byRaw);
        const tgtNorm = normNick(tgtRaw);

        // 🔒 Kanal beyaz liste
        if (!chan || !CHANNEL_WHITELIST.has(chan)) {
          json(res, 403, { ok: false, error: 'channel-not-allowed' });
          return;
        }

        // 🔒 Sadece seslichat botu izinli
        if (byNorm !== ALLOWED_BOT) {
          console.warn(`[SECURITY] Non-bot action rejected from ${byRaw}`);
          json(res, 401, { ok: false, error: 'only-bot-can-act' });
          return;
        }

        if (action === 'invite') {
          const expiry = now() + INVITE_TTL_MS;
          state.rooms[room].pendingInvites.set(tgtNorm, expiry);

          // Daveti ilgili kullanıcıya bildir
          for (const [cid, c] of state.clients.entries()) {
            if (c.norm === tgtNorm) {
              send(c.ws, 'invited', {
                from: byRaw,
                ttl: INVITE_TTL_MS,
                room,
              });
            }
          }

          console.log(`[INVITE] ${byRaw} -> ${tgtRaw}`);
          json(res, 200, { ok: true });
          return;
        }

        if (action === 'revoke') {
          state.rooms[room].pendingInvites.delete(tgtNorm);
          for (const [cid, m] of state.rooms[room].members.entries()) {
            if (m.norm === tgtNorm && !m.isAdmin) {
              send(m.ws, 'speakerRevoked', { room });
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
              try {
                m.ws.close(4000, 'kicked');
              } catch {}
              broadcastRoom(room, { type: 'peer-leave', nick: m.nick });
              kicked = true;
            }
          }
          console.log(
            `[KICK] ${byRaw} -> ${tgtRaw} ${kicked ? 'OK' : 'NOT-IN-ROOM'}`
          );
          json(res, 200, { ok: true });
          return;
        }

        // --- YENİ: OTOMATİK ADMİN EKLEME ---
        if (action === 'add_admin') {
           // Nicki admin listesine ekle
           ADMIN_NICKS.add(tgtNorm);
           console.log(`[AUTO-ADMIN] ${tgtRaw} added to admin list by bot.`);
           
           // Eğer kullanıcı zaten bağlıysa, ona anlık olarak admin yetkisi ver
           for (const [cid, c] of state.clients.entries()) {
             if (c.norm === tgtNorm) {
               c.isAdmin = true;
               // Odadaysa oradaki yetkisini de güncelle
               if (c.room && state.rooms[c.room]) {
                 const m = state.rooms[c.room].members.get(cid);
                 if(m) m.isAdmin = true;
               }
             }
           }
           json(res, 200, { ok: true });
           return;
        }
        // -----------------------------------

        json(res, 400, { ok: false, error: 'unknown-action' });
      } catch (e) {
        console.error('webhook/eggdrop parse fail', e);
        json(res, 400, { ok: false, error: 'bad-json' });
      }
    });
    return;
  }

  // 404
  res.writeHead(404);
  res.end();
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
  wss.handleUpgrade(req, socket, head, ws =>
    wss.emit('connection', ws, req)
  );
});

function send(ws, type, payload = {}) {
  try {
    // Sadece bağlantı AÇIK (readyState === 1) ise gönder
    if (ws && ws.readyState === 1) { 
      ws.send(JSON.stringify({ type, ...payload }));
    }
  } catch {}
}

function broadcastRoom(roomKey, msgObj, exceptId = null) {
  const r = state.rooms[roomKey];
  if (!r) return;
  const s = JSON.stringify(msgObj);
  for (const [cid, m] of r.members.entries()) {
    if (cid === exceptId || !m.ws) continue;
    try {
      if (m.ws.readyState === 1) m.ws.send(s);
    } catch {}
  }
}

// --- Heartbeat (Ping/Pong) ---
// Render.com bağlantıyı kesmesin diye 30 saniyede bir kontrol
const interval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

wss.on('close', () => {
  clearInterval(interval);
});

wss.on('connection', ws => {
  ensureSeslichatBot();
  
  // Heartbeat başlangıcı
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  const clientId = nanoid(10);
  let meta = null;

  ws.on('message', buf => {
    let msg;
    try {
      msg = JSON.parse(buf.toString());
    } catch {
      return;
    }
    const t = msg.type;

    if (t === 'hello') {
      const nickRaw = sanitizeNick(msg.nick);
      const nickNorm = normNick(nickRaw);
      const channel = String(msg.channel || '').toLowerCase();

      // Duplicate Check: Eğer kullanıcı zaten bağlı görünüyorsa eski bağlantısını kapat
      for (const [cid, client] of state.clients.entries()) {
         if (client.norm === nickNorm) {
            console.log(`[DUPLICATE] Closing old connection for ${nickNorm}`);
            try { client.ws.close(); } catch {}
            state.clients.delete(cid);
         }
      }

      state.clients.set(clientId, {
        ws,
        nick: nickRaw,
        norm: nickNorm,
        channel,
        room: null,
        isAdmin: ADMIN_NICKS.has(nickNorm),
        mode: 'passive',
      });

      const exp = state.rooms[SINGLE_ROOM].pendingInvites.get(nickNorm);
      if (exp && exp > now()) {
        send(ws, 'invited', {
          from: 'Yönetici',
          ttl: exp - now(),
          room: SINGLE_ROOM,
        });
      }
      return;
    }

   if (t === 'join') {
      if (!state.clients.has(clientId)) return;
      const clientMeta = state.clients.get(clientId);
      
      // 1. ESKİ ODADAN ÇIKIŞ (Aynı anda tek yerde bulunma kuralı)
      if (clientMeta.room && state.rooms.has(clientMeta.room)) {
          const oldRoom = state.rooms.get(clientMeta.room);
          if (oldRoom.members.has(clientId)) {
             oldRoom.members.delete(clientId);
             broadcastRoom(clientMeta.room, { type: 'peer-leave', nick: clientMeta.nick });
          }
      }
      
      const nickRaw = clientMeta.nick;
      const nickNorm = clientMeta.norm;
      const reqChannel = String(msg.channel || clientMeta.channel).toLowerCase();
      
      // 2. YENİ ODAYI BELİRLE
      const roomName = getRoomNameFromChannel(reqChannel);
      const room = getOrCreateRoom(roomName);

      const isAdmin = ADMIN_NICKS.has(nickNorm);
      let isInvited = false;
      const exp = room.pendingInvites.get(nickNorm);
      if (exp && exp > Date.now()) {
        isInvited = true;
        room.pendingInvites.delete(nickNorm);
      }

      // 3. YETKİ VE KAPASİTE KONTROLÜ
      const isLobbyRoom = (roomName === 'roomA');
      const isPrivateRoom = roomName.startsWith('private_');

      // Lobi Kontrolü
      if (isLobbyRoom && !isAdmin && !isInvited) {
        send(ws, 'error', { error: 'not-authorized-to-join' });
        return;
      }

      // Özel Oda Kapasite Kontrolü (Max 2 Kişi - Onaylama Mantığı)
      if (isPrivateRoom && room.members.size >= 2 && !room.members.has(clientId)) {
         send(ws, 'error', { error: 'room-full' });
         return;
      }

      const isSpeaker = true; 

      clientMeta.room = roomName;
      clientMeta.mode = 'active';
      state.clients.set(clientId, clientMeta);

      room.members.set(clientId, {
        ws, nick: nickRaw, norm: nickNorm,
        isAdmin, isSpeaker, isMuted: true, isBot: false
      });

      if (isLobbyRoom) {
          const realCount = [...room.members.values()].filter(m => !m.isBot).length;
          if (realCount === 1) ensureSeslichatBot(roomName);
      }

      send(ws, 'joined', {
        clientId, room: roomName,
        you: { nick: nickRaw, isAdmin, isSpeaker },
        visibleToAll: room.visibleToAll,
        members: [...room.members.values()].filter(m => !m.isBot).map(m => ({
            nick: m.nick, isAdmin: m.isAdmin, isSpeaker: m.isSpeaker, isMuted: !!m.isMuted
        })),
      });

      broadcastRoom(roomName, { type: 'peer-join', nick: nickRaw, isSpeaker, isMuted: true }, clientId);
      return;
    }

    if (!meta && !state.clients.has(clientId)) return;
    if (!meta && state.clients.get(clientId)?.mode === 'passive') return;
    if (!meta) {
      meta = state.clients.get(clientId);
      if (!meta || !meta.room) return;
    }

    const { room, isAdmin } = meta;

    // --- Mute Durumu Güncelleme ---
    if (t === 'muteStatus') {
      if (!state.rooms[room]?.members.has(clientId)) return;
      const m = state.rooms[room].members.get(clientId);
      m.isMuted = !!msg.value;
      // Odadaki diğer herkese bildir (Flutter'daki peer-update'i tetikler)
      broadcastRoom(room, { type: 'peer-update', nick: m.nick, isMuted: m.isMuted });
      return;
    }

    // --- YENİ: ODADAN AYRILMA (LEAVE) ---
    if (t === 'leave') {
      if (state.rooms[room] && state.rooms[room].members.has(clientId)) {
        state.rooms[room].members.delete(clientId);
        // Herkese bildir
        broadcastRoom(room, { type: 'peer-leave', nick: meta.nick, clientId });
        
        // Kullanıcıyı 'passive' moda çek (Socket kopmaz ama odadan çıkar)
        meta.room = null;
        meta.mode = 'passive';
        state.clients.set(clientId, meta);
        console.log(`[LEAVE] ${meta.nick} left the room.`);
      }
      return;
    }
    // -----------------------------------

    if (t === 'signal') {
      if (!state.rooms[room]?.members.has(clientId)) return;
      const { to, data } = msg;
      const toNorm = normNick(to);
      for (const [cid, m] of state.rooms[room].members.entries()) {
        if (m.norm === toNorm && m.ws) {
          send(m.ws, 'signal', { from: meta.nick, data });
          break;
        }
      }
      return;
    }

    if (t === 'admin:setVisibleToAll' && isAdmin) {
      state.rooms[room].visibleToAll = !!msg.value;
      broadcastRoom(room, { type: 'visibleToAll', value: !!msg.value });
      return;
    }

    if (
      t === 'admin:invite' ||
      t === 'admin:kick' ||
      t === 'admin:revoke' ||
      t === 'admin:forceMute'
    ) {
      send(ws, 'error', { error: 'not-authorized' });
      return;
    }
  });

  ws.on('close', () => {
    const c = state.clients.get(clientId);
    if (c) {
      const { room, nick } = c;
      state.clients.delete(clientId);
      if (room) {
        state.rooms[room]?.members.delete(clientId);
        broadcastRoom(room, { type: 'peer-leave', nick });
      }
    }
    // Eğer oda boşaldıysa botu yeniden ekle
    ensureSeslichatBot();
  });
});

server.listen(PORT, () =>
  console.log(`✅ Voice signaling server listening on port ${PORT}`)
);












