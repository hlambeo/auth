const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const cors = require('cors');
const app = express();

app.use(cors({
    origin: 'https://panel-production-c886.up.railway.app',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'x-admin-secret'],
}));

app.options('*', cors());

app.use(express.json({ limit: '10mb' }));

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function initDb() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            name TEXT DEFAULT NULL,
            hwid TEXT DEFAULT NULL,
            created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
            expires_at BIGINT DEFAULT NULL,
            banned INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS attempts (
            id SERIAL PRIMARY KEY,
            key TEXT,
            hwid TEXT,
            ip TEXT,
            success INTEGER,
            reason TEXT,
            timestamp BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
        );
        CREATE TABLE IF NOT EXISTS debug_logs (
            id SERIAL PRIMARY KEY,
            session_id TEXT,
            timestamp BIGINT,
            msg_num INTEGER,
            direction TEXT,
            msg_type TEXT,
            size INTEGER,
            hex_data TEXT
        );
        CREATE TABLE IF NOT EXISTS debug_tokens (
            token TEXT PRIMARY KEY,
            license_key TEXT,
            created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
            expires_at BIGINT,
            used INTEGER DEFAULT 0
        );
    `);
    console.log('db ready');
}

const ADMIN_SECRET = process.env.ADMIN_SECRET || 'lam200610';

async function logAttempt(key, hwid, ip, success, reason) {
    await pool.query(
        'INSERT INTO attempts (key, hwid, ip, success, reason) VALUES ($1, $2, $3, $4, $5)',
        [key, hwid, ip, success ? 1 : 0, reason]
    );
}

app.post('/auth', async (req, res) => {
    const { key, hwid } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    if (!key || !hwid)
        return res.json({ success: false, message: 'missing fields' });

    const { rows } = await pool.query('SELECT * FROM keys WHERE key = $1', [key]);
    const row = rows[0];

    if (!row) {
        await logAttempt(key, hwid, ip, false, 'invalid key');
        return res.json({ success: false, message: 'invalid key' });
    }

    if (row.banned) {
        await logAttempt(key, hwid, ip, false, 'banned');
        return res.json({ success: false, message: 'key banned' });
    }

    const now = Math.floor(Date.now() / 1000);
    if (row.expires_at && row.expires_at < now) {
        await logAttempt(key, hwid, ip, false, 'expired');
        return res.json({ success: false, message: 'key expired' });
    }

    if (!row.hwid) {
        await pool.query('UPDATE keys SET hwid = $1 WHERE key = $2', [hwid, key]);
        await logAttempt(key, hwid, ip, true, 'first use - hwid bound');
        return res.json({ success: true, message: 'authenticated' });
    }

    if (row.hwid !== hwid) {
        await logAttempt(key, hwid, ip, false, 'hwid mismatch');
        return res.json({ success: false, message: 'hwid mismatch' });
    }

    await logAttempt(key, hwid, ip, true, 'ok');
    return res.json({ success: true, message: 'authenticated' });
});

// New endpoint: Get debug token using license key
app.post('/auth/debug-token', async (req, res) => {
    const { key, hwid } = req.body;

    if (!key || !hwid)
        return res.json({ success: false, message: 'missing fields' });

    // Verify license key first
    const { rows } = await pool.query('SELECT * FROM keys WHERE key = $1', [key]);
    const row = rows[0];

    if (!row || row.banned) {
        return res.json({ success: false, message: 'invalid or banned key' });
    }

    const now = Math.floor(Date.now() / 1000);
    if (row.expires_at && row.expires_at < now) {
        return res.json({ success: false, message: 'key expired' });
    }

    if (row.hwid && row.hwid !== hwid) {
        return res.json({ success: false, message: 'hwid mismatch' });
    }

    // Generate temporary debug token (valid 24 hours)
    const token = crypto.randomBytes(32).toString('hex');
    const expires_at = now + (24 * 60 * 60);

    await pool.query(
        'INSERT INTO debug_tokens (token, license_key, expires_at) VALUES ($1, $2, $3)',
        [token, key, expires_at]
    );

    res.json({ 
        success: true, 
        debug_token: token,
        expires_at: expires_at
    });
});

// Debug log endpoint - uses debug token instead of admin secret
app.post('/debug/log', async (req, res) => {
    const token = req.headers['x-debug-token'];
    
    if (!token) {
        return res.status(403).json({ error: 'missing debug token' });
    }

    // Verify token
    const { rows } = await pool.query(
        'SELECT * FROM debug_tokens WHERE token = $1',
        [token]
    );
    
    if (rows.length === 0) {
        return res.status(403).json({ error: 'invalid token' });
    }

    const tokenData = rows[0];
    const now = Math.floor(Date.now() / 1000);

    if (tokenData.expires_at < now) {
        return res.status(403).json({ error: 'token expired' });
    }

    // Log the debug data
    const { session_id, timestamp, msg_num, direction, msg_type, size, hex_data } = req.body;
    
    await pool.query(
        'INSERT INTO debug_logs (session_id, timestamp, msg_num, direction, msg_type, size, hex_data) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [session_id, timestamp, msg_num, direction, msg_type, size, hex_data]
    );
    
    res.json({ success: true });
});

// Admin endpoints (still use admin secret)
app.post('/admin/genkey', async (req, res) => {
    if (req.headers['x-admin-secret'] !== ADMIN_SECRET)
        return res.status(403).json({ error: 'forbidden' });

    const { key, expires_days } = req.body;

    if (!key)
        return res.status(400).json({ error: 'key required' });

    const expires_at = expires_days
        ? Math.floor(Date.now() / 1000) + (expires_days * 86400)
        : null;

    await pool.query(
        'INSERT INTO keys (key, expires_at) VALUES ($1, $2)',
        [key, expires_at]
    );

    res.json({ key, expires_at });
});

app.get('/admin/keys', async (req, res) => {
    if (req.headers['x-admin-secret'] !== ADMIN_SECRET)
        return res.status(403).json({ error: 'forbidden' });
    const { rows } = await pool.query('SELECT * FROM keys ORDER BY created_at DESC');
    res.json(rows);
});

app.post('/admin/ban', async (req, res) => {
    if (req.headers['x-admin-secret'] !== ADMIN_SECRET)
        return res.status(403).json({ error: 'forbidden' });
    await pool.query('UPDATE keys SET banned = 1 WHERE key = $1', [req.body.key]);
    res.json({ success: true });
});

app.post('/admin/resethwid', async (req, res) => {
    if (req.headers['x-admin-secret'] !== ADMIN_SECRET)
        return res.status(403).json({ error: 'forbidden' });
    await pool.query('UPDATE keys SET hwid = NULL WHERE key = $1', [req.body.key]);
    res.json({ success: true });
});

app.get('/admin/attempts', async (req, res) => {
    if (req.headers['x-admin-secret'] !== ADMIN_SECRET)
        return res.status(403).json({ error: 'forbidden' });
    const { rows } = await pool.query('SELECT * FROM attempts ORDER BY timestamp DESC LIMIT 100');
    res.json(rows);
});

app.get('/admin/debug/:session_id', async (req, res) => {
    if (req.headers['x-admin-secret'] !== ADMIN_SECRET)
        return res.status(403).json({ error: 'forbidden' });
    
    const { rows } = await pool.query(
        'SELECT * FROM debug_logs WHERE session_id = $1 ORDER BY msg_num ASC',
        [req.params.session_id]
    );
    res.json(rows);
});

app.get('/admin/debug/sessions/list', async (req, res) => {
    if (req.headers['x-admin-secret'] !== ADMIN_SECRET)
        return res.status(403).json({ error: 'forbidden' });
    
    const { rows } = await pool.query(
        'SELECT DISTINCT session_id, MIN(timestamp) as started FROM debug_logs GROUP BY session_id ORDER BY started DESC LIMIT 50'
    );
    res.json(rows);
});

app.delete('/admin/debug/clear', async (req, res) => {
    if (req.headers['x-admin-secret'] !== ADMIN_SECRET)
        return res.status(403).json({ error: 'forbidden' });
    
    await pool.query('DELETE FROM debug_logs');
    await pool.query('DELETE FROM debug_tokens');
    res.json({ success: true, message: 'all logs and tokens cleared' });
});

const PORT = process.env.PORT || 3000;
initDb().then(() => app.listen(PORT, () => console.log(`running on ${PORT}`)));
