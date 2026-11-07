import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// ───────────────────────── Configuration (échec immédiat si mal configuré) ─────────────────────────
const env = process.env;
const stripSlash = (s) => String(s || '').trim().replace(/\/+$/, '');
const DISCORD_CLIENT_ID = String(env.DISCORD_CLIENT_ID || '').trim();
const DISCORD_CLIENT_SECRET = String(env.DISCORD_CLIENT_SECRET || '').trim();
const BACKEND_URL = stripSlash(env.BACKEND_URL);     // ex: https://mon-backend.onrender.com
const FRONTEND_URL = stripSlash(env.FRONTEND_URL);   // ex: https://mon-frontend.onrender.com
const JWT_SECRET = String(env.JWT_SECRET || '').trim();
const SYNC_SECRET = String(env.SYNC_SECRET || '').trim();   // même valeur que SITE_SYNC_SECRET côté bot
const PORT = env.PORT || 3000;

const problems = [];
if (!DISCORD_CLIENT_ID) problems.push('DISCORD_CLIENT_ID manquant');
if (!DISCORD_CLIENT_SECRET) problems.push('DISCORD_CLIENT_SECRET manquant');
if (!/^https?:\/\/[^/]+$/.test(BACKEND_URL)) problems.push('BACKEND_URL invalide (ex: https://mon-backend.onrender.com)');
if (!/^https?:\/\/[^/]+$/.test(FRONTEND_URL)) problems.push('FRONTEND_URL invalide (ex: https://mon-frontend.onrender.com)');
if (JWT_SECRET.length < 32) problems.push('JWT_SECRET trop court (32 caractères minimum, aléatoires)');
if (SYNC_SECRET.length < 16) problems.push('SYNC_SECRET trop court (16 caractères minimum, aléatoires)');
if (problems.length) {
  console.error('Configuration invalide :\n - ' + problems.join('\n - '));
  process.exit(1);
}

const REDIRECT_URI = `${BACKEND_URL}/auth/discord/callback`;
const FRONT_ORIGIN = new URL(FRONTEND_URL).origin;
const IS_HTTPS = BACKEND_URL.startsWith('https://');

// Limites métier (à ajuster)
const MAX_PROMO_CREDITS = 100_000;
const MAX_PROMO_USES = 10_000;
const MAX_PROMO_EXPIRY_DAYS = 365;
const MAX_CREDIT_ADJUST = 1_000_000;
const ACTION_TTL_MS = 10 * 60 * 1000;
const MAX_ACTIONS_TOTAL = 2000;
const MAX_ACTIVE_PER_USER = 5;
const MAX_ACTIONS_PER_MINUTE = 15;

const SNOWFLAKE = /^\d{15,25}$/;
const NONCE_RE = /^[a-f0-9]{16,64}$/;
const CODE_RE = /^[\p{L}\p{N}_.-]{1,40}$/u;
const PRESENCES = ['online', 'idle', 'dnd', 'invisible'];
const ACTIVITIES = ['playing', 'watching', 'listening', 'competing', 'streaming', 'custom'];
const BOT_TYPES = ['renew', 'settings', 'groups'];
const ADMIN_TYPES = ['promo_create', 'credits'];
const USER_TYPES = ['renew', 'settings', 'groups', 'promo'];

// ───────────────────────── Utilitaires ─────────────────────────
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));   // temps constant, même si longueurs différentes
const secretOk = (req) => safeEq(String(req.headers['x-sync-secret'] || '').trim(), SYNC_SECRET);
const int = (v, min, max) => { const x = Number(v); return Number.isSafeInteger(x) && x >= min && x <= max ? x : null; };
const clean = (s, max) => String(s ?? '').replace(/[\u0000-\u001f\u007f]/g, '').slice(0, max);

const userOf = (req) => {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  if (!m) return null;
  try {
    const p = jwt.verify(m[1], JWT_SECRET, { algorithms: ['HS256'] });
    return p && typeof p.id === 'string' && SNOWFLAKE.test(p.id) ? p : null;
  } catch { return null; }
};
const requireUser = (req, res, next) => {
  const me = userOf(req);
  if (!me) return res.status(401).json({ error: 'Non connecté' });
  req.user = me;
  next();
};
const requireSync = (req, res, next) => (secretOk(req) ? next() : res.status(401).json({ error: 'Non autorisé' }));

const limiter = (windowMs, limit, extra = {}) => rateLimit({
  windowMs, limit, standardHeaders: 'draft-7', legacyHeaders: false,
  message: { error: 'Trop de requêtes, réessaie plus tard.' }, ...extra,
});
const apiLimiter = limiter(60 * 1000, 240);
const authLimiter = limiter(10 * 60 * 1000, 30);
// Ne compte que les échecs (401) : bloque le brute-force du secret sans gêner le bot
const internalFailLimiter = limiter(15 * 60 * 1000, 30, { skipSuccessfulRequests: true });

// ───────────────────────── État en mémoire ─────────────────────────
// Le bot renvoie le snapshot toutes les minutes : rien à perdre si le service redémarre.
let snapshot = { users: {}, admin: null, adminIds: [], plans: [], groups: [], invitePerms: '8' };
let creditsUpdatedAt = null;
const actions = new Map();   // id -> { id, uid, at, payload, status: 'pending'|'sent'|'done', result }
const hits = new Map();      // uid -> timestamps des dernières demandes

setInterval(() => {
  const now = Date.now();
  for (const [k, a] of actions) if (now - a.at > ACTION_TTL_MS) actions.delete(k);
  for (const [k, arr] of hits) { const f = arr.filter((t) => now - t < 60_000); f.length ? hits.set(k, f) : hits.delete(k); }
}, 30_000).unref();

const tooFast = (uid) => {
  const now = Date.now();
  const arr = (hits.get(uid) || []).filter((t) => now - t < 60_000);
  arr.push(now);
  hits.set(uid, arr);
  return arr.length > MAX_ACTIONS_PER_MINUTE;
};

// ───────────────────────── App ─────────────────────────
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: FRONT_ORIGIN, methods: ['GET', 'POST'], allowedHeaders: ['Content-Type', 'Authorization'], maxAge: 600 }));
app.use(cookieParser());
app.use('/api', apiLimiter, (_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

app.get('/', (_req, res) => res.send('API OK'));

// ───────────────────────── Appels du bot (protégés par le secret partagé) ─────────────────────────
// Le secret est vérifié AVANT de parser le corps : un inconnu ne peut plus envoyer 20 Mo.
app.post('/internal/credits', internalFailLimiter, requireSync, express.json({ limit: '20mb' }), (req, res) => {
  const b = req.body;
  if (!b || typeof b.users !== 'object' || b.users === null || Array.isArray(b.users)) {
    return res.status(400).json({ error: 'Corps invalide' });
  }
  const { users, admin = null, adminIds = [], plans = [], groups = [], invitePerms = '8' } = b;
  snapshot = {
    users,
    admin,
    adminIds: Array.isArray(adminIds) ? adminIds.map(String) : [],
    plans: Array.isArray(plans) ? plans : [],
    groups: Array.isArray(groups) ? groups.map(String) : [],
    invitePerms: /^\d{1,20}$/.test(String(invitePerms)) ? String(invitePerms) : '8',
  };
  creditsUpdatedAt = Date.now();
  res.json({ ok: true });
});

app.get('/internal/actions', internalFailLimiter, requireSync, (_req, res) => {
  const out = [...actions.values()].filter((a) => a.status === 'pending');
  out.forEach((a) => { a.status = 'sent'; });
  res.json({ actions: out.map(({ id, uid, payload }) => ({ id, uid, payload })) });
});

app.post('/internal/actions/:id/result', internalFailLimiter, requireSync, express.json({ limit: '50kb' }), (req, res) => {
  const a = actions.get(req.params.id);
  if (a && a.status === 'sent') {
    const r = req.body && typeof req.body === 'object' ? req.body : {};
    a.result = { ok: r.ok === true, message: clean(r.message, 300), error: clean(r.error, 300) };
    a.status = 'done';
  }
  res.json({ ok: true });
});

// ───────────────────────── Connexion Discord ─────────────────────────
const cookieOpts = { httpOnly: true, secure: IS_HTTPS, sameSite: 'lax', maxAge: 10 * 60 * 1000, path: '/auth' };

// 1) Redirige vers Discord. Le front fournit un nonce (?n=...) qu'il retrouvera au retour :
//    cela empêche qu'on connecte une victime à un compte choisi par l'attaquant (login CSRF).
app.get('/auth/discord', authLimiter, (req, res) => {
  const n = req.query.n;
  if (typeof n !== 'string' || !NONCE_RE.test(n)) return res.status(400).send('Requête invalide');
  const state = crypto.randomBytes(16).toString('hex');
  res.cookie('oauth_state', state, cookieOpts);
  res.cookie('oauth_nonce', n, cookieOpts);
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    response_type: 'code',
    redirect_uri: REDIRECT_URI,
    scope: 'identify',
    state,
  });
  res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

// 2) Discord renvoie ici avec ?code=...
app.get('/auth/discord/callback', authLimiter, async (req, res) => {
  const { code, state } = req.query;
  const savedState = req.cookies.oauth_state;
  const nonce = req.cookies.oauth_nonce;
  res.clearCookie('oauth_state', { path: '/auth' });
  res.clearCookie('oauth_nonce', { path: '/auth' });
  if (
    typeof code !== 'string' || code.length > 512 ||
    typeof state !== 'string' || typeof savedState !== 'string' || !safeEq(state, savedState) ||
    typeof nonce !== 'string' || !NONCE_RE.test(nonce)
  ) return res.status(400).send('State invalide');

  try {
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!tokenRes.ok) throw new Error('Échange du code impossible');
    const { access_token } = await tokenRes.json();

    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${access_token}` },
      signal: AbortSignal.timeout(10_000),
    });
    if (!userRes.ok) throw new Error('Récupération du profil impossible');
    const u = await userRes.json();
    if (typeof u.id !== 'string' || !SNOWFLAKE.test(u.id)) throw new Error('Profil invalide');

    const avatarUrl = u.avatar
      ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png?size=256`
      : `https://cdn.discordapp.com/embed/avatars/${Number((BigInt(u.id) >> 22n) % 6n)}.png`;

    const token = jwt.sign(
      { id: u.id, username: clean(u.global_name || u.username, 64), avatar: avatarUrl },
      JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '7d' }
    );

    // Token + nonce dans le fragment (#) : jamais envoyés à un serveur
    res.redirect(`${FRONTEND_URL}/#${new URLSearchParams({ token, n: nonce })}`);
  } catch (err) {
    console.error('[auth]', err.message);
    res.redirect(`${FRONTEND_URL}/#error=login_failed`);
  }
});

// ───────────────────────── Actions du membre (exécutées par le bot) ─────────────────────────
// Valide, normalise et autorise une demande. Retourne { payload } ou { status, error }.
function buildPayload(me, b) {
  const type = b.type;
  if (![...USER_TYPES, ...ADMIN_TYPES].includes(type)) return { status: 400, error: 'Action invalide' };
  if (ADMIN_TYPES.includes(type) && !snapshot.adminIds.includes(me.id)) return { status: 403, error: 'Interdit' };

  const p = {
    type, key: '', code: '', credits: 0, maxUses: 0, expiresDays: 0, targetId: '', amount: 0,
    groups: [], days: 0, presence: '', activityType: '', activityText: '',
  };

  if (BOT_TYPES.includes(type)) {
    if (typeof b.key !== 'string' || !b.key || b.key.length > 200) return { status: 400, error: 'Action invalide' };
    const mine = snapshot.users[me.id];
    const owns = Array.isArray(mine?.bots) && mine.bots.some((x) => x && x.key === b.key);
    if (!owns) return { status: 403, error: 'Interdit' };
    p.key = b.key;
  }

  switch (type) {
    case 'renew': {
      const plan = snapshot.plans.find((x) => x && Number(x.days) === Number(b.days));
      if (!plan) return { status: 400, error: 'Durée invalide' };
      p.days = Number(plan.days);
      break;
    }
    case 'settings': {
      if (!PRESENCES.includes(b.presence) || !ACTIVITIES.includes(b.activityType)) return { status: 400, error: 'Paramètres invalides' };
      p.presence = b.presence;
      p.activityType = b.activityType;
      p.activityText = clean(b.activityText, 128);
      break;
    }
    case 'groups': {
      if (!Array.isArray(b.groups) || b.groups.length > 40 || !b.groups.every((g) => typeof g === 'string' && snapshot.groups.includes(g))) {
        return { status: 400, error: 'Catégories invalides' };
      }
      p.groups = [...new Set(b.groups)];
      break;
    }
    case 'promo': {
      const code = String(b.code ?? '').trim();
      if (!CODE_RE.test(code)) return { status: 400, error: 'Code invalide' };
      p.code = code;
      break;
    }
    case 'promo_create': {
      const code = String(b.code ?? '').trim();
      if (code && !CODE_RE.test(code)) return { status: 400, error: 'Code invalide' };
      const credits = int(b.credits, 1, MAX_PROMO_CREDITS);
      const maxUses = int(b.maxUses, 1, MAX_PROMO_USES);
      const expiresDays = int(b.expiresDays ?? 0, 0, MAX_PROMO_EXPIRY_DAYS);
      if (credits === null || maxUses === null || expiresDays === null) return { status: 400, error: 'Valeurs invalides' };
      Object.assign(p, { code, credits, maxUses, expiresDays });
      break;
    }
    case 'credits': {
      const amount = int(b.amount, -MAX_CREDIT_ADJUST, MAX_CREDIT_ADJUST);
      if (amount === null || amount === 0 || typeof b.targetId !== 'string' || !SNOWFLAKE.test(b.targetId.trim())) {
        return { status: 400, error: 'Valeurs invalides' };
      }
      p.targetId = b.targetId.trim();
      p.amount = amount;
      break;
    }
  }
  return { payload: p };
}

app.post('/api/actions', requireUser, express.json({ limit: '10kb' }), (req, res) => {
  const me = req.user;
  if (tooFast(me.id)) return res.status(429).json({ error: 'Trop de demandes, ralentis un peu.' });

  const r = buildPayload(me, req.body && typeof req.body === 'object' ? req.body : {});
  if (!r.payload) return res.status(r.status).json({ error: r.error });

  if (actions.size >= MAX_ACTIONS_TOTAL) return res.status(503).json({ error: 'Service surchargé, réessaie.' });
  let active = 0;
  for (const a of actions.values()) if (a.uid === me.id && a.status !== 'done') active++;
  if (active >= MAX_ACTIVE_PER_USER) return res.status(429).json({ error: 'Trop de demandes en attente.' });

  const id = crypto.randomBytes(8).toString('hex');
  actions.set(id, { id, uid: me.id, at: Date.now(), status: 'pending', result: null, payload: r.payload });
  res.json({ id });
});

app.get('/api/actions/:id', requireUser, (req, res) => {
  const a = actions.get(req.params.id);
  if (!a || a.uid !== req.user.id) return res.status(404).json({ error: 'Introuvable' });
  res.json({ status: a.status, result: a.result });
});

app.get('/api/me', requireUser, (req, res) => {
  const { id, username, avatar } = req.user;
  const isAdmin = snapshot.adminIds.includes(id);
  const mine = snapshot.users[id] || {};
  res.json({
    id, username, avatar, isAdmin,
    synced: Boolean(creditsUpdatedAt),   // false = le bot n'a pas encore envoyé ses données
    updatedAt: creditsUpdatedAt,
    data: creditsUpdatedAt ? { credits: 0, bots: [], redeemed: [], referral: { count: 0, paid: 0, earned: 0 }, vouches: { count: 0, last: [] }, economy: null, ...mine } : null,
    admin: isAdmin ? snapshot.admin : null,
    plans: snapshot.plans, groups: snapshot.groups, invitePerms: snapshot.invitePerms,
  });
});

// ───────────────────────── Erreurs ─────────────────────────
app.use((err, _req, res, _next) => {
  const status = err.status && err.status >= 400 && err.status < 600 ? err.status : 500;
  if (status >= 500) console.error('[error]', err.message);
  res.status(status).json({ error: status === 413 ? 'Corps trop volumineux' : status === 400 ? 'Requête invalide' : 'Erreur serveur' });
});

app.listen(PORT, () => console.log(`API sur le port ${PORT}`));
