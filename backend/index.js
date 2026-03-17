require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const JWT_SECRET = process.env.JWT_SECRET;
const SALT_ROUNDS = 12;
const PORT = process.env.PORT || 3000;

if (!JWT_SECRET) {
  console.error('ERROR: JWT_SECRET env variable is required');
  process.exit(1);
}

// ── Middleware ────────────────────────────────────────────────────────────────

app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json());

function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── Routes ────────────────────────────────────────────────────────────────────

// POST /auth/signup
app.post('/auth/signup', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }
  if (username.length < 2 || username.length > 50) {
    return res.status(400).json({ error: 'username must be 2–50 characters' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'password must be at least 6 characters' });
  }

  try {
    const password_hash = await bcrypt.hash(password, SALT_ROUNDS);
    const { rows } = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
      [username, password_hash]
    );
    const token = jwt.sign({ userId: rows[0].id, username: rows[0].username }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, username: rows[0].username });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Username already taken' });
    }
    console.error('signup error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /auth/login
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  try {
    const { rows } = await pool.query(
      'SELECT id, username, password_hash FROM users WHERE username = $1',
      [username]
    );
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username });
  } catch (err) {
    console.error('login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /score  (JWT required)
app.post('/score', requireAuth, async (req, res) => {
  const { score } = req.body;

  if (score === undefined || score === null) {
    return res.status(400).json({ error: 'score is required' });
  }
  if (!Number.isInteger(score) || score < 0) {
    return res.status(400).json({ error: 'score must be a non-negative integer' });
  }

  try {
    const { rows } = await pool.query(
      'INSERT INTO scores (user_id, score) VALUES ($1, $2) RETURNING id, score, created_at',
      [req.user.userId, score]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('score error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /leaderboard  (top 10)
app.get('/leaderboard', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.username, MAX(s.score) AS best_score
      FROM scores s
      JOIN users u ON u.id = s.user_id
      GROUP BY u.id, u.username
      ORDER BY best_score DESC
      LIMIT 10
    `);
    res.json(rows);
  } catch (err) {
    console.error('leaderboard error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
