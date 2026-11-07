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
  PORT = 3000,
} = process.env;

const REDIRECT_URI = `${BACKEND_URL}/auth/discord/callback`;

const app = express();
app.set('trust proxy', 1);
app.use(cors({ origin: FRONTEND_URL }));
app.use(cookieParser());

app.get('/', (_req, res) => res.send('API OK'));

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
    res.json({ id, username, avatar });
  } catch {
    res.status(401).json({ error: 'Non connecté' });
  }
});

app.listen(PORT, () => console.log(`API sur le port ${PORT}`));
