import { getStore } from '@netlify/blobs';

/* Limonapp: guarda y devuelve la base de datos de UN usuario.
   La identidad se valida preguntándole a Netlify Identity quién es el dueño del token. */
const MAX = 4 * 1024 * 1024; // 4 MB (el límite de una función es ~6 MB)

export default async (req) => {
  const auth = req.headers.get('authorization') || '';
  if (!/^Bearer\s+\S+/.test(auth)) return new Response('Sin sesión', { status: 401 });

  const origin = new URL(req.url).origin;
  let user;
  try {
    const r = await fetch(origin + '/.netlify/identity/user', { headers: { Authorization: auth } });
    if (!r.ok) return new Response('Sesión inválida', { status: 401 });
    user = await r.json();
  } catch (e) {
    return new Response('No pude validar la sesión', { status: 502 });
  }
  if (!user || !user.id) return new Response('Sesión inválida', { status: 401 });

  const store = getStore({ name: 'limonapp', consistency: 'strong' });
  const key = 'u_' + String(user.id).replace(/[^a-zA-Z0-9-]/g, '');

  if (req.method === 'GET') {
    const v = await store.get(key, { type: 'text' });
    if (v == null) return new Response('Sin datos', { status: 404 });
    return new Response(v, { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
  }

  if (req.method === 'PUT') {
    const body = await req.text();
    if (body.length > MAX) return new Response('Demasiado grande', { status: 413 });
    let d;
    try { d = JSON.parse(body); } catch (e) { return new Response('JSON inválido', { status: 400 }); }
    if (!d || d.v !== 1 || !Array.isArray(d.patients) || !Array.isArray(d.entries)) return new Response('Formato inválido', { status: 400 });
    await store.set(key, body);
    return new Response('ok', { headers: { 'cache-control': 'no-store' } });
  }

  return new Response('Método no permitido', { status: 405 });
};

export const config = { path: '/api/sync' };
