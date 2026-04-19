'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const multer = require('multer');
const axios = require('axios');
const cheerio = require('cheerio');
const dns = require('dns').promises;
const { URL } = require('url');
const net = require('net');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const sanitizeHtml = require('sanitize-html');

const app = express();
const PORT = parseInt(process.env.PORT, 10) || 1106;
const NODE_ENV = process.env.NODE_ENV || 'production';
const BEHIND_PROXY = process.env.TRUST_PROXY || 'loopback, linklocal, uniquelocal';
const PUBLIC_ORIGIN = (process.env.PUBLIC_ORIGIN || '').trim();          // e.g. https://ladiosa.fr
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || PUBLIC_ORIGIN)
    .split(',').map(s => s.trim()).filter(Boolean);
const SETUP_TOKEN = process.env.SETUP_TOKEN || '';                       // optional one-shot token

// ── Paths ────────────────────────────────────────────────────────────────────
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'recipes'));
const RECIPES_FILE = path.join(DATA_DIR, 'recipes.json');
const ARTICLES_FILE = path.join(DATA_DIR, 'articles.json');
const COMMENTS_FILE = path.join(DATA_DIR, 'comments.json');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const MEDIA_DIR = path.resolve(path.join(DATA_DIR, 'medias'));
const PUBLIC_DIR = path.resolve(path.join(__dirname, 'public'));
const ASSETS_DIR = path.resolve(path.join(__dirname, 'assets'));
const INDEX_HTML = path.join(__dirname, 'index.html');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(MEDIA_DIR)) fs.mkdirSync(MEDIA_DIR, { recursive: true });

// ── Configuration ────────────────────────────────────────────────────────────
const DEFAULT_CONFIG = {
    site: {
        name: 'LA DIOSA',
        tagline: 'Cuisine Tropicale & Terroir',
        description: 'Recettes authentiques, articles culinaires et inspirations du monde.',
        language: 'fr',
        author: 'Chef LaDiosa'
    },
    social: { instagram: '', facebook: '', youtube: '', tiktok: '', twitter: '', pinterest: '' },
    contact: { email: '', message: 'Bienvenue !', showForm: false },
    rss: { enabled: true, itemsPerFeed: 20 },
    auth: { passwordHash: '', jwtSecret: '' }
};

function deepMerge(target, source) {
    const result = { ...target };
    for (const key of Object.keys(source || {})) {
        if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
            result[key] = deepMerge(target[key] || {}, source[key]);
        } else {
            result[key] = source[key];
        }
    }
    return result;
}

function loadConfig() {
    if (fs.existsSync(CONFIG_FILE)) {
        try {
            const data = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
            return deepMerge(DEFAULT_CONFIG, data);
        } catch { return { ...DEFAULT_CONFIG }; }
    }
    return { ...DEFAULT_CONFIG };
}

function saveConfig(cfg) {
    const tmp = CONFIG_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, CONFIG_FILE);
    try { fs.chmodSync(CONFIG_FILE, 0o600); } catch {}
}

let config = loadConfig();
if (!config.auth.jwtSecret) {
    config.auth.jwtSecret = crypto.randomBytes(64).toString('hex');
    saveConfig(config);
}
if (!config.auth.passwordHash && process.env.ADMIN_PASSWORD) {
    config.auth.passwordHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
    saveConfig(config);
    console.log('[Auth] Admin password initialized from ADMIN_PASSWORD env.');
}

function getJwtSecret() { return config.auth.jwtSecret; }

// ── Data Access ──────────────────────────────────────────────────────────────
function loadJSON(file, fallback = []) {
    if (!fs.existsSync(file)) return fallback;
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function saveJSON(file, data) {
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
    fs.renameSync(tmp, file);
}
const loadRecipes = () => loadJSON(RECIPES_FILE, []);
const saveRecipes = d => saveJSON(RECIPES_FILE, d);
const loadArticles = () => loadJSON(ARTICLES_FILE, []);
const saveArticles = d => saveJSON(ARTICLES_FILE, d);
const loadComments = () => loadJSON(COMMENTS_FILE, []);
const saveComments = d => saveJSON(COMMENTS_FILE, d);

// ── Helpers ──────────────────────────────────────────────────────────────────
function isPathWithin(target, base) {
    const b = path.resolve(base) + path.sep;
    const t = path.resolve(target);
    return t === path.resolve(base) || t.startsWith(b);
}

function sanitizeSlug(text) {
    return String(text || '').toLowerCase()
        .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .substring(0, 100);
}

function escapeXml(str) {
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

function sanitizeRichHtml(html) {
    return sanitizeHtml(String(html || ''), {
        allowedTags: [
            'h1','h2','h3','h4','h5','h6','p','br','hr','strong','em','b','i','u','s','code','pre',
            'ul','ol','li','blockquote','a','img','figure','figcaption','table','thead','tbody','tr','th','td'
        ],
        allowedAttributes: {
            a: ['href','title','target','rel'],
            img: ['src','alt','title','loading','width','height'],
            '*': ['class']
        },
        allowedSchemes: ['http','https','mailto'],
        transformTags: {
            a: sanitizeHtml.simpleTransform('a', { rel: 'noopener noreferrer nofollow', target: '_blank' })
        }
    });
}

// IP-based rate limiter for comments (in addition to express-rate-limit)
const commentRateMap = new Map();
const COMMENT_RATE_WINDOW = 60_000;
const COMMENT_RATE_LIMIT = 3;
function checkCommentRate(ip) {
    const now = Date.now();
    const entry = commentRateMap.get(ip);
    if (!entry || now > entry.resetAt) {
        commentRateMap.set(ip, { count: 1, resetAt: now + COMMENT_RATE_WINDOW });
        return true;
    }
    if (entry.count >= COMMENT_RATE_LIMIT) return false;
    entry.count++;
    return true;
}
// periodic cleanup
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of commentRateMap) if (now > v.resetAt) commentRateMap.delete(k);
}, 5 * 60_000).unref();

// ── Auth (SOTA: httpOnly cookies + CSRF double-submit + refresh rotation) ────
const COOKIE_AUTH = 'ladiosa_auth';
const COOKIE_REFRESH = 'ladiosa_refresh';
const COOKIE_CSRF = 'ladiosa_csrf';
const COOKIE_LOGGED_IN = 'ladiosa_logged_in';
const ACCESS_TTL_SEC = 30 * 60;            // 30 min
const REFRESH_TTL_SEC = 7 * 24 * 3600;     // 7 days
const REFRESH_PATH = '/api/auth';          // refresh cookie only sent on auth routes

// In-memory refresh-token registry (keyed by sha256 hash of token)
const refreshStore = new Map();            // hash -> { exp, role, createdAt, ua }
function pruneRefresh() {
    const now = Date.now();
    for (const [k, v] of refreshStore) if (v.exp < now) refreshStore.delete(k);
}
setInterval(pruneRefresh, 10 * 60_000).unref();

function hashToken(t) { return crypto.createHash('sha256').update(t).digest('hex'); }

function cookieBase(maxAgeMs, httpOnly = true, path = '/') {
    return {
        httpOnly,
        secure: NODE_ENV === 'production',
        sameSite: 'lax',
        path,
        maxAge: maxAgeMs
    };
}

function issueSession(res, req, role = 'admin') {
    // Access JWT — 30 min, httpOnly
    const accessToken = jwt.sign({ role, sub: 'admin' }, getJwtSecret(), { expiresIn: ACCESS_TTL_SEC });
    // Refresh token — opaque random, stored hashed, 7 days, rotated on every refresh
    const refreshToken = crypto.randomBytes(32).toString('hex');
    refreshStore.set(hashToken(refreshToken), {
        exp: Date.now() + REFRESH_TTL_SEC * 1000,
        role,
        createdAt: Date.now(),
        ua: (req.get('user-agent') || '').slice(0, 120)
    });
    // CSRF token — random, readable by JS, double-submit pattern
    const csrf = crypto.randomBytes(24).toString('hex');

    res.cookie(COOKIE_AUTH, accessToken, cookieBase(ACCESS_TTL_SEC * 1000, true));
    res.cookie(COOKIE_REFRESH, refreshToken, cookieBase(REFRESH_TTL_SEC * 1000, true, REFRESH_PATH));
    res.cookie(COOKIE_CSRF, csrf, cookieBase(REFRESH_TTL_SEC * 1000, false));
    res.cookie(COOKIE_LOGGED_IN, '1', cookieBase(REFRESH_TTL_SEC * 1000, false));
    return csrf;
}

function clearSession(res) {
    const clr = { path: '/', httpOnly: true, secure: NODE_ENV === 'production', sameSite: 'lax' };
    res.clearCookie(COOKIE_AUTH, clr);
    res.clearCookie(COOKIE_CSRF, { ...clr, httpOnly: false });
    res.clearCookie(COOKIE_LOGGED_IN, { ...clr, httpOnly: false });
    res.clearCookie(COOKIE_REFRESH, { ...clr, path: REFRESH_PATH });
}

function extractToken(req) {
    // 1. HttpOnly cookie (preferred)
    if (req.cookies && req.cookies[COOKIE_AUTH]) return { token: req.cookies[COOKIE_AUTH], src: 'cookie' };
    // 2. Bearer header (for curl / backward compatibility)
    const h = req.headers.authorization;
    if (h && h.startsWith('Bearer ')) return { token: h.slice(7), src: 'bearer' };
    return null;
}

function verifyCsrf(req) {
    const cookie = req.cookies && req.cookies[COOKIE_CSRF];
    const hdr = req.get('X-CSRF-Token');
    if (!cookie || !hdr) return false;
    // constant-time compare
    const a = Buffer.from(String(cookie));
    const b = Buffer.from(String(hdr));
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
}

function verifyToken(req, res, next) {
    const t = extractToken(req);
    if (!t) return res.status(401).json({ error: 'Authentication required' });
    try {
        req.user = jwt.verify(t.token, getJwtSecret());
        // CSRF required when auth is cookie-based AND the request mutates state
        if (t.src === 'cookie' && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
            if (!verifyCsrf(req)) return res.status(403).json({ error: 'CSRF token invalid' });
        }
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

function optionalAuth(req, res, next) {
    const t = extractToken(req);
    if (t) { try { req.user = jwt.verify(t.token, getJwtSecret()); } catch {} }
    next();
}

// ── Progressive backoff (anti-bruteforce) ────────────────────────────────────
const MAX_FAILS_BEFORE_LOCK = 5;
const LOCK_BASE_MS = 30_000;        // 30s, doubles each failure past threshold
const LOCK_CAP_MS = 15 * 60_000;    // capped at 15 min
const FAIL_WINDOW_MS = 30 * 60_000; // reset counter after 30 min of no failures

const loginFailures = new Map();    // key -> { count, lockedUntil, lastAt }

function failKey(req) {
    // Combine IP and user-agent hash to mitigate IP rotation within a single bot
    const ip = req.ip || 'unknown';
    const ua = (req.get('user-agent') || '').slice(0, 80);
    return ip + '|' + crypto.createHash('sha1').update(ua).digest('hex').slice(0, 8);
}

function checkLoginLock(req) {
    const k = failKey(req);
    const e = loginFailures.get(k);
    if (!e) return 0;
    if (Date.now() - (e.lastAt || 0) > FAIL_WINDOW_MS) { loginFailures.delete(k); return 0; }
    if (e.lockedUntil && Date.now() < e.lockedUntil) {
        return Math.ceil((e.lockedUntil - Date.now()) / 1000);
    }
    return 0;
}

function recordLoginFail(req) {
    const k = failKey(req);
    const e = loginFailures.get(k) || { count: 0, lockedUntil: 0, lastAt: 0 };
    e.count++;
    e.lastAt = Date.now();
    if (e.count >= MAX_FAILS_BEFORE_LOCK) {
        const n = e.count - MAX_FAILS_BEFORE_LOCK + 1;
        e.lockedUntil = Date.now() + Math.min(LOCK_BASE_MS * Math.pow(2, n - 1), LOCK_CAP_MS);
    }
    loginFailures.set(k, e);
}

function recordLoginSuccess(req) { loginFailures.delete(failKey(req)); }

setInterval(() => {
    const now = Date.now();
    for (const [k, v] of loginFailures) if (now - v.lastAt > FAIL_WINDOW_MS) loginFailures.delete(k);
}, 5 * 60_000).unref();

// ── Audit log (in-memory ring buffer) ────────────────────────────────────────
const AUDIT_MAX = 500;
const auditLog = [];
function audit(event, req, extra = {}) {
    auditLog.push({
        ts: Date.now(),
        event,
        ip: (req && req.ip) || 'unknown',
        ua: ((req && req.get('user-agent')) || '').slice(0, 120),
        ...extra
    });
    if (auditLog.length > AUDIT_MAX) auditLog.shift();
}

// ── Middleware (order matters) ───────────────────────────────────────────────
app.set('trust proxy', BEHIND_PROXY);
app.disable('x-powered-by');

// CORS: restrict to configured origins in prod. credentials:true required for
// cookie auth, which means we cannot use "*" — always echo the matched origin.
app.use(cors({
    origin: (origin, cb) => {
        if (!origin) return cb(null, true);                        // same-origin / curl / mobile apps
        if (NODE_ENV !== 'production') return cb(null, true);
        if (ALLOWED_ORIGINS.length === 0) return cb(null, false);  // fail closed in prod if unset
        return cb(null, ALLOWED_ORIGINS.includes(origin));
    },
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Setup-Token'],
    exposedHeaders: ['X-CSRF-Token']
}));

app.use(cookieParser());

app.use(helmet({
    contentSecurityPolicy: {
        useDefaults: true,
        directives: {
            defaultSrc: ["'self'"],
            baseUri: ["'self'"],
            frameAncestors: ["'none'"],
            objectSrc: ["'none'"],
            formAction: ["'self'"],
            imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
            mediaSrc: ["'self'", 'https:', 'blob:'],
            fontSrc: ["'self'", 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com', 'data:'],
            styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdnjs.cloudflare.com'],
            scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
            connectSrc: ["'self'"],
            frameSrc: ["'self'", 'https://www.youtube.com', 'https://player.vimeo.com', 'https://www.dailymotion.com'],
            upgradeInsecureRequests: [] // only meaningful when served over HTTPS
        }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    hsts: NODE_ENV === 'production' ? { maxAge: 15552000, includeSubDomains: true, preload: false } : false
}));

app.use(compression());
app.use(express.json({ limit: '2mb' }));

// Rate limiters
const authLimiter = rateLimit({
    windowMs: 15 * 60_000, max: 10, standardHeaders: true, legacyHeaders: false,
    message: { error: 'Too many authentication attempts. Try again later.' }
});
const apiLimiter = rateLimit({
    windowMs: 15 * 60_000, max: 600, standardHeaders: true, legacyHeaders: false,
    message: { error: 'Rate limit exceeded.' }
});
const uploadLimiter = rateLimit({ windowMs: 60_000, max: 30, standardHeaders: true, legacyHeaders: false });
const commentPostLimiter = rateLimit({ windowMs: 10 * 60_000, max: 20, standardHeaders: true, legacyHeaders: false });

app.use('/api/', apiLimiter);

// ── Static assets (WHITELIST approach, do NOT expose __dirname) ──────────────
const staticOpts = { maxAge: '7d', dotfiles: 'ignore', index: false };
app.use('/assets', express.static(ASSETS_DIR, staticOpts));
// Only serve the medias subfolder of DATA_DIR, never the JSON files.
app.use('/recipes/medias', express.static(MEDIA_DIR, {
    ...staticOpts,
    setHeaders: (res, filePath) => {
        // Force safe content-types; block execution as HTML for non-html assets.
        res.setHeader('X-Content-Type-Options', 'nosniff');
        if (/\.(svg|svgz)$/i.test(filePath)) res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'");
    }
}));
// Serve /public for robots, manifest, sw, well-known
app.use(express.static(PUBLIC_DIR, { ...staticOpts, dotfiles: 'allow' }));

// Explicit well-known routes (served from /public/.well-known if present)
app.get('/.well-known/security.txt', (req, res) => {
    const f = path.join(PUBLIC_DIR, '.well-known', 'security.txt');
    if (fs.existsSync(f)) return res.type('text/plain').sendFile(f);
    res.status(404).end();
});

// Explicit index.html serve for SPA root
app.get('/', (req, res) => res.sendFile(INDEX_HTML));
app.get(['/recipes', '/blog', '/contact', '/tulum', '/article/*', '/recipe/*'], (req, res) => {
    res.sendFile(INDEX_HTML);
});

// ── AUTH ROUTES ──────────────────────────────────────────────────────────────
// Dummy hash used to keep /api/auth/login work-factor constant even when no
// password is configured yet (prevents trivial timing oracle).
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(32).toString('hex'), 12);

app.post('/api/auth/setup', authLimiter, async (req, res) => {
    config = loadConfig();
    if (config.auth.passwordHash) {
        audit('setup_blocked_existing', req);
        return res.status(403).json({ error: 'Password already configured' });
    }
    if (SETUP_TOKEN) {
        const tok = (req.headers['x-setup-token'] || '').toString();
        const a = crypto.createHash('sha256').update(tok).digest();
        const b = crypto.createHash('sha256').update(SETUP_TOKEN).digest();
        if (!tok || !crypto.timingSafeEqual(a, b)) {
            audit('setup_token_invalid', req);
            return res.status(403).json({ error: 'Setup token required' });
        }
    }
    const { password } = req.body || {};
    if (!password || typeof password !== 'string' || password.length < 12) {
        return res.status(400).json({ error: 'Password must be at least 12 characters' });
    }
    config.auth.passwordHash = await bcrypt.hash(password, 12);
    saveConfig(config);
    audit('setup_success', req);
    res.json({ success: true });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
    const lockedFor = checkLoginLock(req);
    if (lockedFor > 0) {
        audit('login_locked', req, { retryAfter: lockedFor });
        res.set('Retry-After', String(lockedFor));
        return res.status(429).json({ error: `Trop de tentatives. Réessayez dans ${lockedFor}s.`, retryAfter: lockedFor });
    }
    config = loadConfig();
    const { password } = req.body || {};
    // Always run bcrypt against *some* hash to keep timing constant.
    const hashToCheck = config.auth.passwordHash || DUMMY_HASH;
    const providedPassword = typeof password === 'string' ? password : '';
    const bcryptOk = await bcrypt.compare(providedPassword, hashToCheck);
    const ok = !!config.auth.passwordHash && bcryptOk;

    if (!ok) {
        recordLoginFail(req);
        audit('login_fail', req);
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    recordLoginSuccess(req);
    const csrf = issueSession(res, req, 'admin');
    audit('login_success', req);
    res.json({ success: true, csrf, expiresIn: ACCESS_TTL_SEC });
});

// Refresh — rotates the refresh token (single-use) and issues a new access JWT.
app.post('/api/auth/refresh', authLimiter, (req, res) => {
    const rt = req.cookies && req.cookies[COOKIE_REFRESH];
    if (!rt) return res.status(401).json({ error: 'No refresh token' });
    const key = hashToken(rt);
    const entry = refreshStore.get(key);
    if (!entry || entry.exp < Date.now()) {
        refreshStore.delete(key);
        clearSession(res);
        audit('refresh_invalid', req);
        return res.status(401).json({ error: 'Refresh invalid' });
    }
    refreshStore.delete(key); // one-shot rotation
    const csrf = issueSession(res, req, entry.role);
    audit('refresh_success', req);
    res.json({ success: true, csrf, expiresIn: ACCESS_TTL_SEC });
});

// Logout — revoke current refresh token + clear cookies (no CSRF check needed
// since the worst a CSRF could achieve here is logging the user out).
app.post('/api/auth/logout', (req, res) => {
    const rt = req.cookies && req.cookies[COOKIE_REFRESH];
    if (rt) refreshStore.delete(hashToken(rt));
    clearSession(res);
    audit('logout', req);
    res.json({ success: true });
});

// Logout from *all* sessions — useful after password change or if compromised.
app.post('/api/auth/logout-all', verifyToken, (req, res) => {
    refreshStore.clear();
    clearSession(res);
    audit('logout_all', req);
    res.json({ success: true });
});

app.get('/api/auth/check', verifyToken, (req, res) => {
    // Also surface a fresh CSRF token for the client to pick up if it lost it.
    const csrf = req.cookies && req.cookies[COOKIE_CSRF];
    res.json({ valid: true, role: req.user.role, csrf: csrf || null });
});

app.put('/api/auth/password', verifyToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body || {};
    config = loadConfig();
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords required' });
    if (newPassword.length < 12) return res.status(400).json({ error: 'Password must be at least 12 characters' });
    const ok = await bcrypt.compare(currentPassword, config.auth.passwordHash);
    if (!ok) { audit('password_change_wrong_current', req); return res.status(401).json({ error: 'Current password is incorrect' }); }
    config.auth.passwordHash = await bcrypt.hash(newPassword, 12);
    saveConfig(config);
    // Revoke all refresh tokens so other sessions are forced to re-login.
    refreshStore.clear();
    audit('password_changed', req);
    res.json({ success: true });
});

app.get('/api/auth/status', (req, res) => {
    config = loadConfig();
    res.json({ needsSetup: !config.auth.passwordHash });
});

// Admin audit log (last 200 events).
app.get('/api/admin/audit-log', verifyToken, (req, res) => {
    res.json(auditLog.slice(-200));
});

// Active sessions (refresh tokens currently in memory).
app.get('/api/admin/sessions', verifyToken, (req, res) => {
    const now = Date.now();
    res.json(Array.from(refreshStore.values())
        .filter(v => v.exp > now)
        .map(v => ({ createdAt: v.createdAt, exp: v.exp, ua: v.ua, role: v.role })));
});

// ── CONFIG ROUTES ────────────────────────────────────────────────────────────
app.get('/api/config/public', (req, res) => {
    config = loadConfig();
    const { auth, ...publicConfig } = config;
    res.json(publicConfig);
});

app.get('/api/config', verifyToken, (req, res) => {
    config = loadConfig();
    const { auth, ...safe } = config;
    res.json(safe);
});

app.put('/api/config', verifyToken, (req, res) => {
    config = loadConfig();
    const updates = { ...(req.body || {}) };
    delete updates.auth;
    const newConfig = deepMerge(config, updates);
    newConfig.auth = config.auth;
    saveConfig(newConfig);
    config = newConfig;
    res.json({ success: true });
});

// ── RECIPE ROUTES ────────────────────────────────────────────────────────────
app.get('/api/recipes', optionalAuth, (req, res) => {
    let recipes = loadRecipes();
    if (!req.user) recipes = recipes.filter(r => r.status !== 'draft');
    res.json(recipes);
});

app.get('/api/recipes/:id', optionalAuth, (req, res) => {
    const recipe = loadRecipes().find(r => r.id === req.params.id);
    if (!recipe) return res.status(404).json({ error: 'Recipe not found' });
    if (!req.user && recipe.status === 'draft') return res.status(404).json({ error: 'Recipe not found' });
    res.json(recipe);
});

app.post('/api/recipes', verifyToken, (req, res) => {
    const recipes = req.body;
    if (!Array.isArray(recipes)) return res.status(400).json({ error: 'Expected array' });
    saveRecipes(recipes);
    res.json({ success: true, count: recipes.length });
});

// ── UPLOADS ──────────────────────────────────────────────────────────────────
const ALLOWED_IMG_EXT = new Set(['.jpg', '.jpeg', '.png', '.webp', '.gif', '.avif']);
const ALLOWED_VIDEO_EXT = new Set(['.mp4', '.webm', '.mov']);
const BLOCKED_EXT = new Set(['.svg', '.svgz', '.xml', '.html', '.htm', '.js', '.mjs', '.php', '.phtml', '.sh']);

function safeFolderPath(folder) {
    if (!folder) return '';
    const parts = String(folder).split(/[/\\]/);
    return parts.map(p => p.replace(/[^a-z0-9\-_]/gi, '_')).filter(Boolean).join('/');
}

const storage = multer.diskStorage({
    destination(req, file, cb) {
        const folder = safeFolderPath(req.body.folder);
        const uploadPath = folder ? path.join(MEDIA_DIR, folder) : MEDIA_DIR;
        if (!isPathWithin(uploadPath, MEDIA_DIR)) return cb(new Error('Invalid path'));
        if (!fs.existsSync(uploadPath)) fs.mkdirSync(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename(req, file, cb) {
        let ext = path.extname(file.originalname).toLowerCase();
        if (BLOCKED_EXT.has(ext)) return cb(new Error('File type not allowed'));
        if (!ALLOWED_IMG_EXT.has(ext) && !ALLOWED_VIDEO_EXT.has(ext)) ext = '.bin';
        const suffix = Date.now() + '-' + crypto.randomBytes(6).toString('hex');
        cb(null, 'img-' + suffix + ext);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 20 * 1024 * 1024, files: 1 },
    fileFilter(req, file, cb) {
        const mt = (file.mimetype || '').toLowerCase();
        const ext = path.extname(file.originalname).toLowerCase();
        if (BLOCKED_EXT.has(ext)) return cb(new Error('File type not allowed'));
        const okImg = mt.startsWith('image/') && !mt.includes('svg') && ALLOWED_IMG_EXT.has(ext);
        const okVid = mt.startsWith('video/') && ALLOWED_VIDEO_EXT.has(ext);
        if (okImg || okVid) return cb(null, true);
        cb(new Error('Only images/videos (no SVG) are allowed'));
    }
});

app.post('/api/upload', verifyToken, uploadLimiter, upload.single('image'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const folder = safeFolderPath(req.body.folder);
    const rel = '/recipes/medias/' + (folder ? folder + '/' : '') + req.file.filename;
    res.json({ path: rel });
});

app.delete('/api/file', verifyToken, (req, res) => {
    const rel = (req.body && req.body.path) || '';
    if (!rel) return res.status(400).json({ error: 'No path' });
    const full = path.resolve(path.join(DATA_DIR, rel.replace(/^\/recipes\/?/, '')));
    if (!isPathWithin(full, MEDIA_DIR)) return res.status(403).json({ error: 'Access denied' });
    fs.promises.unlink(full).then(() => res.json({ success: true })).catch(() => res.json({ success: true }));
});

app.delete('/api/folder', verifyToken, (req, res) => {
    const rel = (req.body && req.body.path) || '';
    if (!rel) return res.status(400).json({ error: 'No path' });
    const full = path.resolve(path.join(DATA_DIR, rel.replace(/^\/recipes\/?/, '')));
    if (!isPathWithin(full, MEDIA_DIR)) return res.status(403).json({ error: 'Access denied' });
    if (path.resolve(full) === path.resolve(MEDIA_DIR)) return res.status(400).json({ error: 'Cannot delete media root' });
    fs.rm(full, { recursive: true, force: true }, err => err ? res.status(500).json({ error: 'Failed' }) : res.json({ success: true }));
});

app.post('/api/rename-folder', verifyToken, (req, res) => {
    const { oldPath, newPath } = req.body || {};
    if (!oldPath || !newPath) return res.status(400).json({ error: 'Missing paths' });
    const oldResolved = path.resolve(path.join(DATA_DIR, oldPath.replace(/^\/recipes\/?/, '')));
    const newResolved = path.resolve(path.join(DATA_DIR, newPath.replace(/^\/recipes\/?/, '')));
    if (!isPathWithin(oldResolved, MEDIA_DIR) || !isPathWithin(newResolved, MEDIA_DIR)) {
        return res.status(403).json({ error: 'Access denied' });
    }
    if (!fs.existsSync(oldResolved)) return res.json({ success: true, message: 'Old folder not found' });
    const parent = path.dirname(newResolved);
    if (!fs.existsSync(parent)) fs.mkdirSync(parent, { recursive: true });
    fs.rename(oldResolved, newResolved, err => err ? res.status(500).json({ error: 'Rename failed' }) : res.json({ success: true }));
});

// ── SSRF-safe URL fetcher ────────────────────────────────────────────────────
async function isPublicHostname(hostname) {
    const h = hostname.toLowerCase();
    if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal')) return false;
    const ipFamilyBlocked = (ip) => {
        if (net.isIPv4(ip)) {
            const [a, b] = ip.split('.').map(Number);
            if (a === 10) return true;
            if (a === 127) return true;
            if (a === 0) return true;
            if (a === 169 && b === 254) return true;
            if (a === 172 && b >= 16 && b <= 31) return true;
            if (a === 192 && b === 168) return true;
            if (a >= 224) return true;
            return false;
        }
        if (net.isIPv6(ip)) {
            const low = ip.toLowerCase();
            if (low === '::1' || low.startsWith('fc') || low.startsWith('fd') || low.startsWith('fe80')) return true;
            return false;
        }
        return true;
    };
    try {
        const recs = await dns.lookup(h, { all: true, verbatim: true });
        for (const r of recs) if (ipFamilyBlocked(r.address)) return false;
        return recs.length > 0;
    } catch {
        return false;
    }
}

app.post('/api/import-recipe', verifyToken, uploadLimiter, async (req, res) => {
    const { url } = req.body || {};
    if (!url || typeof url !== 'string') return res.status(400).json({ error: 'No URL' });
    let parsed;
    try {
        parsed = new URL(url);
        if (!['http:', 'https:'].includes(parsed.protocol)) return res.status(400).json({ error: 'Only HTTP(S)' });
    } catch { return res.status(400).json({ error: 'Invalid URL' }); }
    if (!(await isPublicHostname(parsed.hostname))) {
        return res.status(400).json({ error: 'Internal or unresolved URLs are not allowed' });
    }

    try {
        const response = await axios.get(parsed.toString(), {
            headers: { 'User-Agent': 'Mozilla/5.0 LaDiosaBot/1.0' },
            maxRedirects: 3, timeout: 12000, maxContentLength: 8 * 1024 * 1024, responseType: 'text'
        });
        const $ = cheerio.load(response.data);
        let recipeData = null;
        $('script[type="application/ld+json"]').each((i, el) => {
            try {
                const json = JSON.parse($(el).contents().text());
                const arr = json['@graph'] || (Array.isArray(json) ? json : [json]);
                const recipe = arr.find(item => item && (item['@type'] === 'Recipe' || (Array.isArray(item['@type']) && item['@type'].includes('Recipe'))));
                if (recipe) { recipeData = recipe; return false; }
            } catch {}
        });
        if (!recipeData) return res.status(404).json({ error: 'No structured recipe data' });

        const decodeHtml = s => {
            if (!s) return '';
            let d = String(s);
            for (let i = 0; i < 3; i++) {
                const $d = cheerio.load(`<div>${d}</div>`);
                const nd = $d('div').text();
                if (nd === d) break;
                d = nd;
            }
            return d;
        };

        const extracted = {
            title: decodeHtml(recipeData.name || 'Untitled'),
            description: decodeHtml(recipeData.description || ''),
            ingredients: [], instructions: '', imageUrl: '',
            servings: recipeData.recipeYield ? parseInt(recipeData.recipeYield, 10) || 4 : 4,
            prepTime: recipeData.prepTime || '',
            cookTime: recipeData.cookTime || '',
            sourceUrl: url
        };
        if (Array.isArray(recipeData.recipeIngredient)) extracted.ingredients = recipeData.recipeIngredient.map(decodeHtml);
        if (Array.isArray(recipeData.recipeInstructions)) {
            extracted.instructions = recipeData.recipeInstructions
                .map(step => typeof step === 'string' ? decodeHtml(step) : decodeHtml(step.text || step.name || ''))
                .join('\n\n');
        } else if (typeof recipeData.recipeInstructions === 'string') {
            extracted.instructions = decodeHtml(recipeData.recipeInstructions);
        }

        let imgUrl = recipeData.image;
        if (Array.isArray(imgUrl)) imgUrl = imgUrl[0];
        if (imgUrl && typeof imgUrl === 'object') imgUrl = imgUrl.url;
        if (typeof imgUrl === 'string' && imgUrl) {
            try {
                const i = new URL(imgUrl);
                if (['http:', 'https:'].includes(i.protocol) && await isPublicHostname(i.hostname)) {
                    const imgResp = await axios.get(i.toString(), {
                        responseType: 'arraybuffer', timeout: 10000, maxContentLength: 15 * 1024 * 1024
                    });
                    const ct = (imgResp.headers['content-type'] || '').toLowerCase();
                    if (ct.startsWith('image/') && !ct.includes('svg')) {
                        const extMap = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp', 'image/gif': '.gif', 'image/avif': '.avif' };
                        const ext = extMap[ct.split(';')[0].trim()] || '.jpg';
                        const filename = 'import-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex') + ext;
                        fs.writeFileSync(path.join(MEDIA_DIR, filename), imgResp.data);
                        extracted.imageUrl = '/recipes/medias/' + filename;
                    }
                }
            } catch {}
        }
        res.json(extracted);
    } catch (e) {
        console.error('[import]', e.message);
        res.status(502).json({ error: 'Failed to fetch recipe' });
    }
});

// ── ARTICLE ROUTES ───────────────────────────────────────────────────────────
app.get('/api/articles', optionalAuth, (req, res) => {
    let articles = loadArticles();
    if (!req.user) articles = articles.filter(a => a.status === 'published');
    articles.sort((a, b) => (b.publishedAt || b.updatedAt || 0) - (a.publishedAt || a.updatedAt || 0));
    res.json(articles);
});

app.get('/api/articles/:slug', optionalAuth, (req, res) => {
    const article = loadArticles().find(a => a.slug === req.params.slug);
    if (!article) return res.status(404).json({ error: 'Article not found' });
    if (!req.user && article.status !== 'published') return res.status(404).json({ error: 'Article not found' });
    res.json(article);
});

app.get('/api/admin/articles', verifyToken, (req, res) => {
    const articles = loadArticles();
    articles.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
    res.json(articles);
});

function ensureUniqueSlug(articles, article, excludeIdx = -1) {
    let base = article.slug || sanitizeSlug(article.title || 'article');
    article.slug = base;
    let c = 1;
    while (articles.some((x, i) => i !== excludeIdx && x.slug === article.slug)) {
        article.slug = base + '-' + c++;
    }
}

app.post('/api/admin/articles', verifyToken, (req, res) => {
    const articles = loadArticles();
    const { title, content, excerpt, coverImage, tags, linkedRecipes, videos, status } = req.body || {};
    if (!title) return res.status(400).json({ error: 'Title required' });
    const article = {
        id: crypto.randomUUID(),
        title: String(title).slice(0, 300),
        slug: sanitizeSlug(title),
        content: content || '',
        excerpt: (excerpt || '').slice(0, 500),
        coverImage: coverImage || '',
        author: config.site.author,
        tags: Array.isArray(tags) ? tags.slice(0, 50) : [],
        linkedRecipes: Array.isArray(linkedRecipes) ? linkedRecipes.slice(0, 100) : [],
        videos: Array.isArray(videos) ? videos.slice(0, 20) : [],
        images: [],
        status: status === 'published' ? 'published' : 'draft',
        publishedAt: status === 'published' ? Date.now() : null,
        createdAt: Date.now(),
        updatedAt: Date.now()
    };
    ensureUniqueSlug(articles, article);
    articles.push(article);
    saveArticles(articles);
    res.json(article);
});

app.put('/api/admin/articles/:id', verifyToken, (req, res) => {
    const articles = loadArticles();
    const idx = articles.findIndex(a => a.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Article not found' });
    const a = articles[idx];
    const wasPublished = a.status === 'published';
    const u = req.body || {};
    if (u.title !== undefined) { a.title = String(u.title).slice(0, 300); a.slug = sanitizeSlug(a.title); ensureUniqueSlug(articles, a, idx); }
    if (u.content !== undefined) a.content = u.content;
    if (u.excerpt !== undefined) a.excerpt = String(u.excerpt).slice(0, 500);
    if (u.coverImage !== undefined) a.coverImage = u.coverImage;
    if (u.tags !== undefined) a.tags = Array.isArray(u.tags) ? u.tags.slice(0, 50) : [];
    if (u.linkedRecipes !== undefined) a.linkedRecipes = Array.isArray(u.linkedRecipes) ? u.linkedRecipes : [];
    if (u.videos !== undefined) a.videos = Array.isArray(u.videos) ? u.videos.slice(0, 20) : [];
    if (u.status !== undefined) {
        a.status = u.status === 'published' ? 'published' : 'draft';
        if (a.status === 'published' && !wasPublished) a.publishedAt = Date.now();
    }
    a.updatedAt = Date.now();
    articles[idx] = a;
    saveArticles(articles);
    res.json(a);
});

app.delete('/api/admin/articles/:id', verifyToken, (req, res) => {
    let articles = loadArticles();
    const idx = articles.findIndex(a => a.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Article not found' });
    articles.splice(idx, 1);
    saveArticles(articles);
    saveComments(loadComments().filter(c => c.articleId !== req.params.id));
    res.json({ success: true });
});

// ── COMMENT ROUTES ───────────────────────────────────────────────────────────
app.get('/api/articles/:id/comments', (req, res) => {
    const comments = loadComments()
        .filter(c => c.articleId === req.params.id && c.approved === true)
        .map(c => ({ id: c.id, author: c.author, content: c.content, createdAt: c.createdAt }))
        .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    res.json(comments);
});

app.post('/api/articles/:id/comments', commentPostLimiter, (req, res) => {
    const ip = req.ip || 'unknown';
    if (!checkCommentRate(ip)) return res.status(429).json({ error: 'Too many comments. Please wait.' });
    const { author, content, website } = req.body || {};
    // honeypot field: bots often fill every input
    if (website) return res.json({ success: true, message: 'Comment submitted for moderation' });
    if (!author || !content) return res.status(400).json({ error: 'Author and content required' });
    const cleanAuthor = String(author).trim();
    const cleanContent = String(content).trim();
    if (cleanAuthor.length === 0 || cleanAuthor.length > 100) return res.status(400).json({ error: 'Author 1-100 chars' });
    if (cleanContent.length === 0 || cleanContent.length > 2000) return res.status(400).json({ error: 'Content 1-2000 chars' });
    const articles = loadArticles();
    if (!articles.find(a => a.id === req.params.id && a.status === 'published')) {
        return res.status(404).json({ error: 'Article not found' });
    }
    const comments = loadComments();
    comments.push({
        id: crypto.randomUUID(),
        articleId: req.params.id,
        author: cleanAuthor,
        content: cleanContent,
        approved: false,
        ip: crypto.createHash('sha256').update(ip + (config.auth.jwtSecret || '')).digest('hex').slice(0, 16),
        createdAt: Date.now()
    });
    saveComments(comments);
    res.json({ success: true, message: 'Comment submitted for moderation' });
});

app.get('/api/admin/comments', verifyToken, (req, res) => {
    const c = loadComments().sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    res.json(c);
});

app.put('/api/admin/comments/:id/approve', verifyToken, (req, res) => {
    const comments = loadComments();
    const c = comments.find(x => x.id === req.params.id);
    if (!c) return res.status(404).json({ error: 'Comment not found' });
    c.approved = true;
    saveComments(comments);
    res.json({ success: true });
});

app.delete('/api/admin/comments/:id', verifyToken, (req, res) => {
    let comments = loadComments();
    const idx = comments.findIndex(c => c.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Comment not found' });
    comments.splice(idx, 1);
    saveComments(comments);
    res.json({ success: true });
});

// ── RSS / SITEMAP ────────────────────────────────────────────────────────────
function baseUrlOf(req) {
    if (PUBLIC_ORIGIN) return PUBLIC_ORIGIN.replace(/\/$/, '');
    const proto = req.headers['x-forwarded-proto'] || req.protocol;
    return `${proto}://${req.get('host')}`;
}

function rssHeader(title, description, link, selfLink) {
    return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom" xmlns:media="http://search.yahoo.com/mrss/">
  <channel>
    <title>${escapeXml(title)}</title>
    <description>${escapeXml(description)}</description>
    <link>${escapeXml(link)}</link>
    <language>${escapeXml(config.site.language || 'fr')}</language>
    <atom:link href="${escapeXml(selfLink)}" rel="self" type="application/rss+xml"/>
    <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>`;
}

function rssItem(item) {
    let xml = `
    <item>
      <title>${escapeXml(item.title)}</title>
      <link>${escapeXml(item.link)}</link>
      <guid isPermaLink="false">${escapeXml(item.guid)}</guid>
      <pubDate>${new Date(item.pubDate).toUTCString()}</pubDate>
      <description>${escapeXml(item.description)}</description>`;
    if (item.image) xml += `\n      <media:content url="${escapeXml(item.image)}" medium="image"/>`;
    (item.categories || []).forEach(cat => { xml += `\n      <category>${escapeXml(cat)}</category>`; });
    xml += `\n    </item>`;
    return xml;
}

app.get('/rss/recipes', (req, res) => {
    config = loadConfig();
    const base = baseUrlOf(req);
    const recipes = loadRecipes().filter(r => r.status !== 'draft').sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    const lim = config.rss.itemsPerFeed || 20;
    let xml = rssHeader(config.site.name + ' - Recettes', 'Les dernières recettes', base + '/#/recipes', base + '/rss/recipes');
    recipes.slice(0, lim).forEach(r => {
        const img = r.images && r.images[0] ? (r.images[0].startsWith('http') ? r.images[0] : base + r.images[0]) : '';
        xml += rssItem({ title: r.title, link: base + '/#/recipe/' + r.id, guid: 'recipe-' + r.id, pubDate: r.createdAt || Date.now(), description: `Préparation: ${r.prepTime || 'N/A'} | Cuisson: ${r.cookTime || 'N/A'}`, image: img, categories: r.tags || [] });
    });
    xml += '\n  </channel>\n</rss>';
    res.type('application/rss+xml').send(xml);
});

app.get('/rss/articles', (req, res) => {
    config = loadConfig();
    const base = baseUrlOf(req);
    const articles = loadArticles().filter(a => a.status === 'published').sort((a, b) => (b.publishedAt || 0) - (a.publishedAt || 0));
    const lim = config.rss.itemsPerFeed || 20;
    let xml = rssHeader(config.site.name + ' - Blog', 'Les derniers articles', base + '/#/blog', base + '/rss/articles');
    articles.slice(0, lim).forEach(a => {
        const img = a.coverImage ? (a.coverImage.startsWith('http') ? a.coverImage : base + a.coverImage) : '';
        xml += rssItem({ title: a.title, link: base + '/#/article/' + a.slug, guid: 'article-' + a.id, pubDate: a.publishedAt || a.createdAt || Date.now(), description: a.excerpt || '', image: img, categories: a.tags || [] });
    });
    xml += '\n  </channel>\n</rss>';
    res.type('application/rss+xml').send(xml);
});

app.get('/rss', (req, res) => {
    config = loadConfig();
    const base = baseUrlOf(req);
    const recipes = loadRecipes().filter(r => r.status !== 'draft');
    const articles = loadArticles().filter(a => a.status === 'published');
    const lim = config.rss.itemsPerFeed || 20;
    let xml = rssHeader(config.site.name, config.site.description, base, base + '/rss');
    const items = [];
    recipes.forEach(r => {
        const img = r.images && r.images[0] ? (r.images[0].startsWith('http') ? r.images[0] : base + r.images[0]) : '';
        items.push({ title: '[Recette] ' + r.title, link: base + '/#/recipe/' + r.id, guid: 'recipe-' + r.id, pubDate: r.createdAt || Date.now(), description: `Préparation: ${r.prepTime || 'N/A'}`, image: img, categories: r.tags || [] });
    });
    articles.forEach(a => {
        const img = a.coverImage ? (a.coverImage.startsWith('http') ? a.coverImage : base + a.coverImage) : '';
        items.push({ title: '[Blog] ' + a.title, link: base + '/#/article/' + a.slug, guid: 'article-' + a.id, pubDate: a.publishedAt || a.createdAt || Date.now(), description: a.excerpt || '', image: img, categories: a.tags || [] });
    });
    items.sort((a, b) => b.pubDate - a.pubDate).slice(0, lim).forEach(i => { xml += rssItem(i); });
    xml += '\n  </channel>\n</rss>';
    res.type('application/rss+xml').send(xml);
});

app.get('/sitemap.xml', (req, res) => {
    const base = baseUrlOf(req);
    const recipes = loadRecipes().filter(r => r.status !== 'draft');
    const articles = loadArticles().filter(a => a.status === 'published');
    const urls = [
        { loc: base + '/', changefreq: 'daily', priority: '1.0' },
        { loc: base + '/#/recipes', changefreq: 'daily', priority: '0.9' },
        { loc: base + '/#/blog', changefreq: 'daily', priority: '0.9' },
        { loc: base + '/#/contact', changefreq: 'monthly', priority: '0.3' },
        ...recipes.map(r => ({ loc: base + '/#/recipe/' + r.id, lastmod: new Date(r.updatedAt || r.createdAt || Date.now()).toISOString(), changefreq: 'weekly', priority: '0.7' })),
        ...articles.map(a => ({ loc: base + '/#/article/' + a.slug, lastmod: new Date(a.updatedAt || a.publishedAt || Date.now()).toISOString(), changefreq: 'weekly', priority: '0.7' }))
    ];
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">';
    urls.forEach(u => {
        xml += `\n  <url><loc>${escapeXml(u.loc)}</loc>${u.lastmod ? `<lastmod>${u.lastmod}</lastmod>` : ''}<changefreq>${u.changefreq}</changefreq><priority>${u.priority}</priority></url>`;
    });
    xml += '\n</urlset>';
    res.type('application/xml').send(xml);
});

// ── OG SHARE PAGES (sanitized) ───────────────────────────────────────────────
app.get('/share/recipe/:id', (req, res) => {
    config = loadConfig();
    const base = baseUrlOf(req);
    const recipe = loadRecipes().find(r => r.id === req.params.id);
    if (!recipe || recipe.status === 'draft') return res.redirect(base);
    const img = recipe.images && recipe.images[0] ? (recipe.images[0].startsWith('http') ? recipe.images[0] : base + recipe.images[0]) : '';
    const desc = `Préparation: ${recipe.prepTime || 'N/A'} | Cuisson: ${recipe.cookTime || 'N/A'}`;
    const target = `${base}/#/recipe/${encodeURIComponent(recipe.id)}`;
    res.send(`<!DOCTYPE html><html><head>
<meta charset="UTF-8">
<title>${escapeXml(recipe.title)} - ${escapeXml(config.site.name)}</title>
<meta property="og:title" content="${escapeXml(recipe.title)}">
<meta property="og:description" content="${escapeXml(desc)}">
<meta property="og:image" content="${escapeXml(img)}">
<meta property="og:url" content="${escapeXml(target)}">
<meta property="og:type" content="article">
<meta name="twitter:card" content="summary_large_image">
<meta http-equiv="refresh" content="0;url=${escapeXml(target)}">
</head><body><p>Redirecting...</p></body></html>`);
});

app.get('/share/article/:slug', (req, res) => {
    config = loadConfig();
    const base = baseUrlOf(req);
    const article = loadArticles().find(a => a.slug === req.params.slug && a.status === 'published');
    if (!article) return res.redirect(base);
    const img = article.coverImage ? (article.coverImage.startsWith('http') ? article.coverImage : base + article.coverImage) : '';
    const target = `${base}/#/article/${encodeURIComponent(article.slug)}`;
    res.send(`<!DOCTYPE html><html><head>
<meta charset="UTF-8">
<title>${escapeXml(article.title)} - ${escapeXml(config.site.name)}</title>
<meta property="og:title" content="${escapeXml(article.title)}">
<meta property="og:description" content="${escapeXml(article.excerpt || '')}">
<meta property="og:image" content="${escapeXml(img)}">
<meta property="og:url" content="${escapeXml(target)}">
<meta property="og:type" content="article">
<meta name="twitter:card" content="summary_large_image">
<meta http-equiv="refresh" content="0;url=${escapeXml(target)}">
</head><body><p>Redirecting...</p></body></html>`);
});

// ── Healthcheck ──────────────────────────────────────────────────────────────
app.get('/healthz', (req, res) => res.json({ ok: true, ts: Date.now() }));

// ── Error handler ────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
    if (err && err.message) {
        const msg = err.message.slice(0, 200);
        return res.status(400).json({ error: msg });
    }
    res.status(500).json({ error: 'Internal error' });
});

// ── Start ────────────────────────────────────────────────────────────────────
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`
╭─────────────────────────────────────────────╮
│   LA DIOSA SERVER                           │
├─────────────────────────────────────────────┤
│  env:  ${NODE_ENV.padEnd(37)}│
│  port: ${String(PORT).padEnd(37)}│
│  data: ${DATA_DIR.slice(-37).padEnd(37)}│
│  auth: ${(config.auth.passwordHash ? 'configured' : 'NOT SET — /api/auth/setup').padEnd(37)}│
╰─────────────────────────────────────────────╯`);
});

function shutdown(sig) {
    console.log(`\n[${sig}] shutting down…`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
