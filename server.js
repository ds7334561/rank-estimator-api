import express from 'express';
import session from 'express-session';
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import { randomUUID } from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize app
const app = express();
app.use(express.urlencoded({ extended: true }));

// Sessions (MemoryStore for dev)
const sessionSecret = process.env.SESSION_SECRET || 'dev-secret-change-me';
app.use(
  session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 1000 * 60 * 60 * 24 * 7 },
  })
);

// Database setup
const dbPath = path.join(__dirname, 'app.sqlite');
const db = new Database(dbPath);
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    dob TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    magic_token TEXT,
    magic_expires INTEGER
  );
`);

function getUserByEmail(email) {
  if (!email) return null;
  return db.prepare('SELECT * FROM users WHERE email = ?').get(email);
}

async function createUser(email, dob, password) {
  const id = randomUUID();
  const password_hash = await bcrypt.hash(password, 10);
  db.prepare('INSERT INTO users (id, email, dob, password_hash) VALUES (?, ?, ?, ?)').run(id, email, dob, password_hash);
  return id;
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

async function setMagicToken(userId) {
  const token = randomUUID().replace(/-/g, '');
  const expires = Date.now() + 15 * 60 * 1000; // 15 minutes
  db.prepare('UPDATE users SET magic_token = ?, magic_expires = ? WHERE id = ?').run(token, expires, userId);
  const base = process.env.PUBLIC_BASE_URL || 'http://localhost:3000';
  return `${base}/magic/login/${token}`;
}

function getUserByMagicToken(token) {
  const row = db.prepare('SELECT * FROM users WHERE magic_token = ?').get(token);
  if (!row) return null;
  if (!row.magic_expires || row.magic_expires < Date.now()) return null;
  return row;
}

async function consumeMagicToken(userId) {
  db.prepare('UPDATE users SET magic_token = NULL, magic_expires = NULL WHERE id = ?').run(userId);
}

function ensureAuth(req, res, next) {
  if (req.session?.userId) {
    req.user = { id: req.session.userId };
    return next();
  }
  res.redirect('/login');
}

function redirectIfAuth(req, res, next) {
  if (req.session?.userId) return res.redirect('/dashboard');
  next();
}

// Routes
app.get('/', (req, res) => res.redirect('/dashboard'));

app.get('/register', redirectIfAuth, (req, res) => {
  res.send(`
    <h1>Register</h1>
    <form method="post" action="/register">
      <label>Email <input type="email" name="email" required /></label><br/>
      <label>DOB (YYYY-MM-DD) <input type="text" name="dob" placeholder="1990-01-01" required /></label><br/>
      <label>Password <input type="password" name="password" required /></label><br/>
      <button type="submit">Create Account</button>
    </form>
    <p><a href="/login">Login</a></p>
  `);
});

app.post('/register', redirectIfAuth, async (req, res) => {
  const { email, dob, password } = req.body;
  if (!email || !dob || !password) return res.status(400).send('All fields required');
  try {
    await createUser(email.toLowerCase(), dob, password);
    res.redirect('/login');
  } catch (e) {
    res.status(400).send('User exists or invalid data');
  }
});

app.get('/login', redirectIfAuth, (req, res) => {
  const msg = req.session.msg || '';
  req.session.msg = '';
  res.send(`
    <h1>Login</h1>
    <form method="post" action="/login">
      <label>Email <input type="email" name="email" required /></label><br/>
      <label>DOB (YYYY-MM-DD) <input type="text" name="dob" placeholder="1990-01-01" required /></label><br/>
      <label>Password <input type="password" name="password" required /></label><br/>
      <button type="submit">Login</button>
    </form>
    <p><a href="/magic">Login with magic link</a> | <a href="/register">Register</a></p>
    ${msg ? `<p style="color:red">${msg}</p>` : ''}
  `);
});

app.post('/login', redirectIfAuth, async (req, res) => {
  const { email, dob, password } = req.body;
  const user = getUserByEmail(email?.toLowerCase());
  if (!user) {
    req.session.msg = 'Invalid credentials';
    return res.redirect('/login');
  }
  if (user.dob !== dob) {
    req.session.msg = 'Invalid credentials';
    return res.redirect('/login');
  }
  const ok = await verifyPassword(password || '', user.password_hash);
  if (!ok) {
    req.session.msg = 'Invalid credentials';
    return res.redirect('/login');
  }
  req.session.userId = user.id;
  res.redirect('/dashboard');
});

app.get('/magic', redirectIfAuth, (req, res) => {
  const msg = req.session.msg || '';
  req.session.msg = '';
  res.send(`
    <h1>Magic Link</h1>
    <form method="post" action="/magic">
      <label>Email <input type="email" name="email" required /></label><br/>
      <button type="submit">Send Magic Link</button>
    </form>
    <p><a href="/login">Back to login</a></p>
    ${msg ? `<p>${msg}</p>` : ''}
  `);
});

app.post('/magic', redirectIfAuth, async (req, res) => {
  const { email } = req.body;
  const user = getUserByEmail(email?.toLowerCase());
  if (!user) {
    req.session.msg = 'If the email exists, a link has been generated.';
    return res.redirect('/magic');
  }
  const magicUrl = await setMagicToken(user.id);
  console.log('Magic link (development):', magicUrl);
  req.session.msg = `Magic link generated (dev): <a href="${magicUrl}">${magicUrl}</a>`;
  res.redirect('/magic');
});

app.get('/magic/login/:token', async (req, res) => {
  const user = getUserByMagicToken(req.params.token);
  if (!user) return res.status(400).send('Invalid or expired token');
  await consumeMagicToken(user.id);
  req.session.userId = user.id;
  res.redirect('/dashboard');
});

app.get('/dashboard', ensureAuth, (req, res) => {
  res.send(`
    <h1>Dashboard</h1>
    <p>Welcome! You are logged in.</p>
    <p><a href="/rank">Keyword Rank Checker</a></p>
    <form method="post" action="/logout"><button type="submit">Logout</button></form>
  `);
});

app.post('/logout', ensureAuth, (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Rank checker routes (uses SerpAPI if SERPAPI_KEY is set)
app.get('/rank', ensureAuth, async (req, res) => {
  res.send(`
    <h1>Keyword Rank Checker</h1>
    <form method="post" action="/rank">
      <label>Keyword <input type="text" name="keyword" required /></label><br/>
      <label>Domain (example.com) <input type="text" name="domain" required /></label><br/>
      <button type="submit">Check Rank</button>
    </form>
    <p><a href="/dashboard">Back</a></p>
  `);
});

app.post('/rank', ensureAuth, async (req, res) => {
  const { keyword, domain } = req.body;
  const apiKey = process.env.SERPAPI_KEY || '';
  if (!apiKey) {
    return res.send(`
      <h1>Keyword Rank Checker</h1>
      <p>Set SERPAPI_KEY env var to use live Google results.</p>
      <pre>SERPAPI_KEY=your_key node server.js</pre>
      <p><a href="/rank">Back</a></p>
    `);
  }
  try {
    const url = `https://serpapi.com/search.json?q=${encodeURIComponent(keyword)}&engine=google&num=100&api_key=${apiKey}`;
    const response = await fetch(url);
    if (!response.ok) throw new Error('SERP API error');
    const data = await response.json();
    const organic = data.organic_results || [];
    const target = (domain || '').toLowerCase().replace(/^https?:\/\//,'').replace(/^www\./,'');
    let foundRank = null;
    let matches = [];
    for (const item of organic) {
      const link = item.link || '';
      try {
        const hostname = new URL(link).hostname.replace(/^www\./,'').toLowerCase();
        if (hostname.endsWith(target)) {
          matches.push({ position: item.position, title: item.title, link });
          if (foundRank === null) foundRank = item.position;
        }
      } catch {}
    }
    res.send(`
      <h1>Results for "${keyword}"</h1>
      <p>Domain: ${domain}</p>
      <p>${foundRank !== null ? `Best rank: ${foundRank}` : 'No results in top 100'}</p>
      <ul>
        ${matches.map(m => `<li>#${m.position} - <a href="${m.link}">${m.title}</a></li>`).join('')}
      </ul>
      <p><a href="/rank">Check another</a></p>
    `);
  } catch (e) {
    res.status(500).send(`Error: ${e.message} <p><a href=\"/rank\">Back</a></p>`);
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server started on http://localhost:${port}`));