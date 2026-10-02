import express from 'express';
import cors from 'cors';
import { Readable } from 'node:stream';

const app = express();
app.use(cors({ origin: '*' }));

const PORT = process.env.PORT || 3001;

// Запрещаем локальные адреса (защита от SSRF)
const BLOCK_HOSTS =
  /^(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1$|fe80:)/i;

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'transfer-encoding', 'upgrade',
  'proxy-authenticate', 'proxy-authorization', 'te', 'trailer',
]);

app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send('Missing ?url=');

  let targetUrl;
  try { targetUrl = new URL(target); }
  catch { return res.status(400).send('Invalid URL'); }

  if (!['http:', 'https:'].includes(targetUrl.protocol))
    return res.status(400).send('Only http/https');
  if (BLOCK_HOSTS.test(targetUrl.hostname))
    return res.status(403).send('Private hosts not allowed');

  try {
    const upstream = await fetch(targetUrl, {
      method: req.method,
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
          '(KHTML, like Gecko) Chrome/122.0 Safari/537.36',
        'Accept': '*/*',
        ...(req.headers.range ? { Range: req.headers.range } : {}),
      },
      redirect: 'follow',
    });

    res.status(upstream.status);
    upstream.headers.forEach((value, key) => {
      const k = key.toLowerCase();
      if (HOP_BY_HOP.has(k)) return;
      if (k === 'set-cookie') return;
      if ([
        'content-security-policy',
        'x-frame-options',
        'cross-origin-embedder-policy',
        'cross-origin-opener-policy',
        'cross-origin-resource-policy',
      ].includes(k)) return;
      res.setHeader(key, value);
    });

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Expose-Headers',
      'Content-Length, Content-Type, Content-Range, Accept-Ranges');

    if (!upstream.body) return res.end();
    Readable.fromWeb(upstream.body).pipe(res);
  } catch (e) {
    res.status(502).send('Fetch failed: ' + e.message);
  }
});

app.get('/', (_, res) => res.send('OK — use /proxy?url=...'));

app.listen(PORT, () => {
  console.log(`✅ Proxy: http://localhost:${PORT}/proxy?url=...`);
});