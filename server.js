import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  BACKEND_URL,   // ex: https://mon-backend.onrender.com
  FRONTEND_URL,  // ex: https://mon-frontend.onrender.com (sans / final)
  JWT_SECRET,
  SYNC_SECRET: RAW_SYNC_SECRET,   // secret partagé avec le bot (même valeur que SITE_SYNC_SECRET côté bot)
  PORT = 3000,
} = process.env;
const SYNC_SECRET = (RAW_SYNC_SECRET || '').trim();   // enlève les espaces invisibles éventuels

const REDIRECT_URI = `${BACKEND_URL}/auth/discord/callback`;

const app = express();
app.set('trust proxy', 1);
app.use(cors({ origin: FRONTEND_URL }));
app.use(cookieParser());

// Soldes de crédits envoyés par le bot : { userId: nombre }. Gardés en mémoire,
// le bot les renvoie toutes les minutes (donc rien à perdre si Render redémarre).
let snapshot = { users: {}, admin: null, adminIds: [] };
let creditsUpdatedAt = null;

app.get('/', (_req, res) => res.send('API OK'));

// Appelé uniquement par le bot (pas par le navigateur) : protégé par le secret partagé.
app.post('/internal/credits', express.json({ limit: '20mb' }), (req, res) => {
  if (!SYNC_SECRET) {
    console.warn('[sync] SYNC_SECRET est vide ou absent sur ce service : ajoute-la dans Environment puis redéploie.');
    return res.status(503).json({ error: 'SYNC_SECRET non configurée sur le backend' });
  }
  const given = Buffer.from(String(req.headers['x-sync-secret'] || '').trim());
  const expected = Buffer.from(SYNC_SECRET);
  const ok = given.length === expected.length && crypto.timingSafeEqual(given, expected);
  if (!ok) {
    console.warn(`[sync] Secret refusé (reçu : ${given.length} caractères, attendu : ${expected.length}).`);
    return res.status(401).json({ error: 'Non autorisé' });
  }
  if (!req.body || typeof req.body.users !== 'object' || req.body.users === null) {
    return res.status(400).json({ error: 'Corps invalide' });
  }
  const { users, admin = null, adminIds = [] } = req.body;
  snapshot = { users, admin, adminIds };
  creditsUpdatedAt = Date.now();
  res.json({ ok: true });
});

// 1) Redirige vers Discord
app.get('/auth/discord', (_req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  res.cookie('oauth_state', state, {
    httpOnly: true, secure: true, sameSite: 'lax', maxAge: 10 * 60 * 1000,
  });
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
app.get('/auth/discord/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state || state !== req.cookies.oauth_state) {
      return res.status(400).send('State invalide');
    }
    res.clearCookie('oauth_state');

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
    });
    if (!tokenRes.ok) throw new Error('Échange du code impossible');
    const { access_token } = await tokenRes.json();

    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    if (!userRes.ok) throw new Error('Récupération du profil impossible');
    const u = await userRes.json();

    const avatarUrl = u.avatar
      ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png?size=256`
      : `https://cdn.discordapp.com/embed/avatars/${Number((BigInt(u.id) >> 22n) % 6n)}.png`;

    const token = jwt.sign(
      { id: u.id, username: u.global_name || u.username, avatar: avatarUrl },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // On renvoie le token au frontend via le fragment (#) : il n'est jamais envoyé aux serveurs
    res.redirect(`${FRONTEND_URL}/#token=${token}`);
  } catch (err) {
    console.error(err);
    res.redirect(`${FRONTEND_URL}/#error=login_failed`);
  }
});

// 3) API protégée
app.get('/api/me', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    const { id, username, avatar } = jwt.verify(token, JWT_SECRET);
    const isAdmin = snapshot.adminIds.includes(id);
    const mine = snapshot.users[id] || {};
    res.json({
      id, username, avatar, isAdmin,
      synced: Boolean(creditsUpdatedAt),   // false = le bot n'a pas encore envoyé ses données
      updatedAt: creditsUpdatedAt,
      data: creditsUpdatedAt ? { credits: 0, bots: [], redeemed: [], referral: { count: 0, paid: 0, earned: 0 }, vouches: { count: 0, last: [] }, economy: null, ...mine } : null,
      admin: isAdmin ? snapshot.admin : null,
    });

  } catch {
    res.status(401).json({ error: 'Non connecté' });
  }
});

app.listen(PORT, () => console.log(`API sur le port ${PORT}`));
