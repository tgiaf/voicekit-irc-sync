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
  (process.env.CHANNEL_WHITELIST || '#radyo')
    .split(',')
    .map(s => s.trim().toLowerCase())
);

const SINGLE_ROOM = 'roomA';
const SECRET_TOKEN = process.env.SECRET_TOKEN || 'change-this-secret';
const INVITE_TTL_MS = Number(process.env.INVITE_TTL_MS || 60_000);
const EGGDROP_SECRET =
  process.env.EGGDROP_SECRET ||
  '5f7a2c7f3b2a9f0b0cd1d5e2a1b47b8fa7c2bd31f8f8479a6b3c2d1e0f9a7c5d';

// 🔐 Sadece bu bot davet gönderebilir
const ALLOWED_BOT = 'seslichat';

function okOrigin(origin) {
  if (!origin) return true;
  if (ALLOWED_ORIGINS.includes('*')) return true;
  try {
    const o = new URL(origin);
    return ALLOWED_ORIGINS.some(a => {
      const A = new URL(a);
      return A.protocol === o.protocol && A.host === o.host;
    });
  } catch {
    return false;
  }
}

const now = () => Date.now();

function json(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

function sanitizeNick(n) {
  return String(n || '')
    .replace(/[^A-Za-z0-9_\-\[\]{}^`|]/g, '')
    .slice(0, 24);
}
function normNick(n) {
  return sanitizeNick(n).toLowerCase();
}

function safeEqualHex(a, b) {
  try {
    const A = Buffer.from(String(a), 'hex');
    const B = Buffer.from(String(b), 'hex');
    if (A.length !== B.length) return false;
    return crypto.timingSafeEqual(A, B);
  } catch {
    return false;
  }
}

// ---- Oda durumu ----

// Oda her zaman en az bir "seslichat" botu içersin
function ensureSeslichatBot() {
  const r = state.rooms[SINGLE_ROOM];
  if (!r) return;
  const already = [...r.members.values()].some(m => m.norm === ALLOWED_BOT);
  if (!already) {
    const fakeId = `bot-${ALLOWED_BOT}`;
    r.members.set(fakeId, {
      ws: null,
      nick: ALLOWED_BOT,
      norm: ALLOWED_BOT,
      isAdmin: true,
      isSpeaker: false,
      isBot: true,
    });
    console.log(`[BOT] Seslichat bot added to room`);
  }
}

const state = {
  rooms: {
    [SINGLE_ROOM]: {
      members: new Map(),
      visibleToAll: false,
      pendingInvites: new Map(),
    },
  },
  clients: new Map(),
};

// Başlangıçta odayı botla doldur
ensureSeslichatBot();

// Eski davetleri temizle (30 sn)
setInterval(() => {
  const r = state.rooms[SINGLE_ROOM];
  for (const [nk, exp] of r.pendingInvites.entries()) {
    if (exp <= now()) r.pendingInvites.delete(nk);
  }
}, 30_000);

// ---- HTTP server ----
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
        const chan = String(data.channel || '#radyo').toLowerCase();
        const room = SINGLE_ROOM;
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
    if (!ws) return;
    ws.send(JSON.stringify({ type, ...payload }));
  } catch {}
}

function broadcastRoom(roomKey, msgObj, exceptId = null) {
  const r = state.rooms[roomKey];
  if (!r) return;
  const s = JSON.stringify(msgObj);
  for (const [cid, m] of r.members.entries()) {
    if (cid === exceptId || !m.ws) continue;
    try {
      m.ws.send(s);
    } catch {}
  }
}

wss.on('connection', ws => {
  // Odayı her bağlantıda kontrol et
  ensureSeslichatBot();

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
      const nickRaw = sanitizeNick(msg.nick);
      const nickNorm = normNick(nickRaw);
      const channel = String(msg.channel || '').toLowerCase();
      const room = SINGLE_ROOM;

      if (!CHANNEL_WHITELIST.has(channel)) {
        send(ws, 'error', { error: 'channel-not-allowed' });
        return;
      }

      const isAdmin = ADMIN_NICKS.has(nickNorm);
      let isInvited = false;

      const exp = state.rooms[room].pendingInvites.get(nickNorm);
      if (exp && exp > now()) {
        isInvited = true;
        state.rooms[room].pendingInvites.delete(nickNorm);
      }

      // 🔒 Yalnızca admin veya davetliler katılabilir
      if (!isAdmin && !isInvited) {
        send(ws, 'error', { error: 'not-authorized-to-join' });
        console.log(`[JOIN FAIL] ${nickRaw} -> Not Admin or Invited`);
        return;
      }

      const isSpeaker = true;

      meta = { nick: nickRaw, norm: nickNorm, channel, room, isAdmin };
      state.clients.set(clientId, { ws, ...meta });
      state.rooms[room].members.set(clientId, {
        ws,
        nick: nickRaw,
        norm: nickNorm,
        isAdmin,
        isSpeaker,
      });

      // 🟢 Eğer sadece bot varsa, bu ilk gerçek katılımcıdır.
// Odaya otomatik olarak seslichat botunu "aktif" olarak ekle.
const r = state.rooms[room];
const realCount = [...r.members.values()].filter(m => !m.isBot).length;
if (realCount === 1) {
  const botAlready = [...r.members.values()].some(m => m.isBot);
  if (!botAlready) {
    const fakeId = `bot-${ALLOWED_BOT}`;
    r.members.set(fakeId, {
      ws: null,
      nick: ALLOWED_BOT,
      norm: ALLOWED_BOT,
      isAdmin: true,
      isSpeaker: false,
      isBot: true,
    });
    console.log(`[AUTO] Seslichat bot added to room for first joiner.`);
  }
}


      send(ws, 'joined', {
        clientId,
        room,
        you: { nick: nickRaw, isAdmin, isSpeaker },
        visibleToAll: state.rooms[room].visibleToAll,
        members: [...state.rooms[room].members.values()]
          .filter(m => !m.isBot) // <-- BU SATIRI EKLEYİN
          .map(m => ({
            nick: m.nick,
            isAdmin: m.isAdmin,
            isSpeaker: m.isSpeaker,
          })),
      });

      broadcastRoom(room, { type: 'peer-join', nick: nickRaw, isSpeaker }, clientId);
      console.log(`[JOIN SUCCESS] ${nickRaw}`);
      return;
    }

    if (!meta && !state.clients.has(clientId)) return;
    if (!meta && state.clients.get(clientId)?.mode === 'passive') return;
    if (!meta) {
      meta = state.clients.get(clientId);
      if (!meta || !meta.room) return;
    }

    const { room, isAdmin } = meta;

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


