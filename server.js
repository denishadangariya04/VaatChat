// ---------- Setup ----------
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const DB_FILE = path.join(__dirname, 'users.json'); // simple file "database"

const app = express();
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 4e6 }); // allows photos up to ~3 MB

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Tiny user store (users.json) ----------
const loadUsers = () => {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return []; }
};
const saveUsers = (users) => fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
const makeToken = (u) => jwt.sign({ id: u.id, name: u.name }, SECRET, { expiresIn: '7d' });

// ---------- REST: register & login ----------
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password || password.length < 6) {
    return res.status(400).json({ error: 'Enter a name, an email and a password of at least 6 characters.' });
  }
  const users = loadUsers();
  const mail = email.trim().toLowerCase();
  if (users.some((u) => u.email === mail)) {
    return res.status(409).json({ error: 'This email is already registered. Try logging in.' });
  }
  const user = {
    id: crypto.randomUUID(),
    name: name.trim().slice(0, 20),
    email: mail,
    hash: await bcrypt.hash(password, 10),
  };
  users.push(user);
  saveUsers(users);
  res.json({ token: makeToken(user) });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = loadUsers().find((u) => u.email === String(email || '').trim().toLowerCase());
  if (!user || !(await bcrypt.compare(String(password || ''), user.hash))) {
    return res.status(401).json({ error: 'Wrong email or password.' });
  }
  res.json({ token: makeToken(user) });
});

// ---------- Socket auth: token (registered) OR guestName (no login) ----------
io.use((socket, next) => {
  const { token, guestName } = socket.handshake.auth || {};
  if (token) {
    try {
      const p = jwt.verify(token, SECRET);
      socket.user = { id: p.id, name: p.name, guest: false };
      return next();
    } catch {
      return next(new Error('Session expired. Please log in again.'));
    }
  }
  const name = String(guestName || '').trim().slice(0, 20);
  if (!name) return next(new Error('Please enter your name.'));
  socket.user = { id: 'g-' + crypto.randomUUID(), name, guest: true };
  next();
});

// ---------- In-memory chat state ----------
const online = new Map();          // userId -> { id, name, guest, count }
const publicHistory = [];          // messages of the public room
const privateHistory = new Map();  // "idA|idB" -> messages
const pairKey = (a, b) => [a, b].sort().join('|');
const MAX_HISTORY = 200;

function makeMessage(user, to, p) {
  const raw = typeof p === 'string' ? { text: p } : p || {};
  const text = String(raw.text || '').trim().slice(0, 1000);
  const okImage = typeof raw.image === 'string' && /^data:image\/(png|jpe?g|gif|webp);base64,/.test(raw.image) && raw.image.length < 3e6;
  const image = okImage ? raw.image : null;
  if (!text && !image) return null;
  return { id: crypto.randomUUID(), from: user.id, fromName: user.name, to, text, image, time: Date.now(), status: to ? 'delivered' : undefined };
}
const pushLimited = (arr, msg) => { arr.push(msg); if (arr.length > MAX_HISTORY) arr.shift(); };
const broadcastUsers = () =>
  io.emit('users', [...online.values()].map(({ id, name, guest }) => ({ id, name, guest })));

// ---------- Socket events ----------
io.on('connection', (socket) => {
  const u = socket.user;
  socket.join(u.id); // every user has a personal room (works with many tabs)

  const entry = online.get(u.id) || { id: u.id, name: u.name, guest: u.guest, count: 0 };
  entry.count++;
  online.set(u.id, entry);

  socket.emit('me', u);
  socket.emit('history:public', publicHistory);
  broadcastUsers();

  socket.on('history:private', (withId, cb) => {
    if (typeof cb === 'function') cb(privateHistory.get(pairKey(u.id, withId)) || []);
  });

  socket.on('message:public', (text) => {
    const msg = makeMessage(u, null, text);
    if (!msg) return;
    pushLimited(publicHistory, msg);
    io.emit('message:public', msg);
  });

  socket.on('message:private', ({ to, text, image } = {}) => {
    if (!online.has(to)) return; // receiver must be online
    const msg = makeMessage(u, to, { text, image });
    if (!msg) return;
    const key = pairKey(u.id, to);
    if (!privateHistory.has(key)) privateHistory.set(key, []);
    pushLimited(privateHistory.get(key), msg);
    io.to(to).to(u.id).emit('message:private', msg); // receiver + sender's tabs
  });

  // Delete for everyone (only your own messages)
  socket.on('message:delete', ({ id, to } = {}) => {
    const list = to ? privateHistory.get(pairKey(u.id, to)) : publicHistory;
    const msg = list && list.find((m) => m.id === id);
    if (!msg || msg.from !== u.id) return;
    msg.text = ''; msg.image = null; msg.deleted = true;
    const payload = { id, to: to || null, from: u.id };
    if (to) io.to(to).to(u.id).emit('message:deleted', payload);
    else io.emit('message:deleted', payload);
  });

  // Read receipts (blue ticks)
  socket.on('read', (withId) => {
    let changed = false;
    (privateHistory.get(pairKey(u.id, withId)) || []).forEach((m) => {
      if (m.from === withId && m.status !== 'read') { m.status = 'read'; changed = true; }
    });
    if (changed) io.to(withId).emit('read', { by: u.id });
  });

  socket.on('typing', (to) => {
    const payload = { from: u.id, name: u.name, to: to || null };
    if (to) socket.to(to).emit('typing', payload);
    else socket.broadcast.emit('typing', payload);
  });

  socket.on('disconnect', () => {
    entry.count--;
    if (entry.count <= 0) online.delete(u.id);
    broadcastUsers();
  });
});

server.listen(PORT, () => console.log(`Chat running at http://localhost:${PORT}`));
