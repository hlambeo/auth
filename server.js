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

app.use(express.json());

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

app.post('/admin/genkey', async (req, res) => {
    if (req.headers['x-admin-secret'] !== ADMIN_SECRET)
        return res.status(403).json({ error: 'forbidden' });

    const { expires_days, name } = req.body;
    const key = [
        crypto.randomBytes(4).toString('hex').toUpperCase(),
        crypto.randomBytes(4).toString('hex').toUpperCase(),
        crypto.randomBytes(4).toString('hex').toUpperCase(),
        crypto.randomBytes(4).toString('hex').toUpperCase()
    ].join('-');

    const expires_at = expires_days
        ? Math.floor(Date.now() / 1000) + (expires_days * 86400)
        : null;

    await pool.query('INSERT INTO keys (key, name, expires_at) VALUES ($1, $2, $3)', [key, name || null, expires_at]);
    res.json({ key, name, expires_at });
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

const PORT = process.env.PORT || 3000;
initDb().then(() => app.listen(PORT, () => console.log(`running on ${PORT}`)));
