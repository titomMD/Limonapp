import { getStore } from '@netlify/blobs';

/* Limonapp: imágenes JPEG de los estudios de UN usuario (v35). Cada imagen se guarda bajo el ID del usuario,
   así que solo su dueño puede leerla o borrarla. Dos versiones por imagen: f (reducida a 2000 px) y t (miniatura).
   GET /api/img?id=ID&k=f|t  ·  PUT (cuerpo = JPEG)  ·  DELETE ?id=ID  ·  DELETE ?all=1 (todas las del usuario). */
const MAX = 4 * 1024 * 1024;   // el límite de una función es ~6 MB
const MAX_N = 2000;            // tope de archivos por usuario (cada imagen son 2)

/* ===== AUTH-BEGIN: idéntico en sync.mjs y social.mjs (si lo cambias, cámbialo en los dos) =====
   Verifica la sesión de Supabase Auth (Google) sin librerías: firma ES256 con la clave pública del proyecto
   (JWKS), emisor, audiencia y vencimiento. Devuelve el ID con el que se guardan los datos del usuario. */
const SUPABASE_URL = 'https://lwfsydrtxukbbviocrvv.supabase.co';
const ISS = SUPABASE_URL + '/auth/v1';
/* Personas que ya usaban Limonapp con Netlify Identity: huella SHA-256 de su correo de Google VERIFICADO (en minusculas)
   -> ID bajo el que ya estan guardados sus datos. Asi conservan pacientes, equipos, mensajes y roles.
   Se guarda la huella y no el correo porque este repositorio es publico. Todos los demas usan su ID de Supabase.
   Para obtener la huella de un correo (Mac, Terminal):  printf '%s' "correo@gmail.com" | shasum -a 256 */
const LEGACY = {
  '76e21e5b52a74bffcb13cdf1cc78578dcfb9a45a67259480eebb174748359a73': 'be0a9bec-7f40-4b80-a0e4-5b474fe36106',
  '883bcbd76c4ed2632953f9cdde627d5acf710e2bcfecd04d1005fe9c44f20220': 'e1603fa0-0193-4770-9663-ec6d6f9e6f54',
  'ae0cb6014a392bfcd1733bd85609791c93a9daed96d67587dff1ff5c7297ff60': 'd3d52a34-043f-42d1-87f5-7df340aebf36',
};
const sha256 = async (t) => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t)))).map((b) => b.toString(16).padStart(2, '0')).join('');
const b64u = (s) => Uint8Array.from(atob(String(s).replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(String(s).length / 4) * 4, '=')), (c) => c.charCodeAt(0));
const txt = (u8) => new TextDecoder().decode(u8);
let JWKS = { at: 0, keys: [] };
const KEYC = new Map();
async function jwks(force) {
  const age = Date.now() - JWKS.at;
  if (JWKS.keys.length && (force ? age < 30000 : age < 600000)) return JWKS.keys;
  try {
    const r = await fetch(ISS + '/.well-known/jwks.json', { headers: { accept: 'application/json' } });
    if (!r.ok) throw new Error('jwks ' + r.status);
    const j = await r.json();
    JWKS = { at: Date.now(), keys: Array.isArray(j.keys) ? j.keys : [] };
  } catch (e) {
    if (!JWKS.keys.length) throw e; /* si falla la consulta pero hay claves guardadas, sigo con ellas */
  }
  return JWKS.keys;
}
async function keyFor(kid) {
  let jwk = (await jwks(false)).find((k) => k.kid === kid);
  if (!jwk) jwk = (await jwks(true)).find((k) => k.kid === kid);
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256') return null;
  const id = kid + '|' + jwk.x + '|' + jwk.y;
  if (!KEYC.has(id)) KEYC.set(id, await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']));
  return KEYC.get(id);
}
/* Devuelve { user } o { status, msg }. user.id = ID de datos; user.sub = ID de Supabase. */
async function authenticate(req) {
  const m = /^Bearer\s+([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(req.headers.get('authorization') || '');
  if (!m) return { status: 401, msg: 'Sin sesión' };
  let h, p, sig;
  try { h = JSON.parse(txt(b64u(m[1]))); p = JSON.parse(txt(b64u(m[2]))); sig = b64u(m[3]); } catch (e) { return { status: 401, msg: 'Sesión inválida' }; }
  if (!h || h.alg !== 'ES256' || typeof h.kid !== 'string' || !p || typeof p !== 'object' || sig.length !== 64) return { status: 401, msg: 'Sesión inválida' };
  let ok = false;
  try {
    const key = await keyFor(h.kid);
    if (!key) return { status: 401, msg: 'Sesión inválida' };
    ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, new TextEncoder().encode(m[1] + '.' + m[2]));
  } catch (e) { return { status: 502, msg: 'No pude validar la sesión' }; }
  const now = Date.now() / 1000;
  const aud = Array.isArray(p.aud) ? p.aud : [p.aud];
  if (!ok || p.iss !== ISS || !aud.includes('authenticated') || p.role !== 'authenticated' || p.is_anonymous === true || typeof p.exp !== 'number' || p.exp < now - 30 || (typeof p.nbf === 'number' && p.nbf > now + 30) || typeof p.sub !== 'string' || !/^[0-9a-fA-F-]{36}$/.test(p.sub)) return { status: 401, msg: 'Sesión inválida' };
  const um = p.user_metadata && typeof p.user_metadata === 'object' ? p.user_metadata : {};
  const email = String(p.email || um.email || '').toLowerCase();
  const verified = !!email && ((p.app_metadata && p.app_metadata.provider) === 'google') && (um.email_verified === true || um.email_verified === 'true');
  const h256 = verified ? await sha256(email) : '';
  const legacy = verified && Object.prototype.hasOwnProperty.call(LEGACY, h256) ? LEGACY[h256] : '';
  return { user: { id: legacy || p.sub, sub: p.sub, legacy: !!legacy, email, user_metadata: um } };
}
/* ===== AUTH-END ===== */

export default async (req) => {
  const a = await authenticate(req);
  if (!a.user) return new Response(a.msg, { status: a.status });
  const uid = String(a.user.id).replace(/[^a-zA-Z0-9-]/g, '');
  const store = getStore({ name: 'limonapp-img', consistency: 'strong' });
  const q = new URL(req.url).searchParams;
  const id = String(q.get('id') || ''), k = String(q.get('k') || '');
  const okId = /^[a-z0-9]{8,40}$/i.test(id);
  const key = (kk) => 'i_' + uid + '_' + id + '_' + kk;
  const H = { 'cache-control': 'no-store' };

  if (req.method === 'GET') {
    if (!okId || (k !== 'f' && k !== 't')) return new Response('Parámetros inválidos', { status: 400 });
    const b = await store.get(key(k), { type: 'arrayBuffer' });
    if (b == null) return new Response('No existe', { status: 404 });
    return new Response(b, { headers: { ...H, 'content-type': 'image/jpeg', 'content-length': String(b.byteLength) } });
  }

  if (req.method === 'PUT') {
    if (!okId || (k !== 'f' && k !== 't')) return new Response('Parámetros inválidos', { status: 400 });
    const ab = await req.arrayBuffer();
    const buf = new Uint8Array(ab);
    if (!buf.length || buf.length > MAX) return new Response(buf.length ? 'Demasiado grande' : 'Vacío', { status: buf.length ? 413 : 400 });
    if (buf[0] !== 0xff || buf[1] !== 0xd8) return new Response('Solo JPEG', { status: 415 });
    const exists = (await store.getMetadata(key(k))) != null;
    if (!exists) {
      const l = await store.list({ prefix: 'i_' + uid + '_' });
      if (l.blobs.length >= MAX_N) return new Response('Llegaste al tope de imágenes de tu cuenta', { status: 507 });
    }
    await store.set(key(k), ab);
    return new Response('ok', { headers: H });
  }

  if (req.method === 'DELETE') {
    if (q.get('all')) {
      const l = await store.list({ prefix: 'i_' + uid + '_' });
      await Promise.all(l.blobs.map((x) => store.delete(x.key)));
      return new Response('ok', { headers: H });
    }
    if (!okId) return new Response('Parámetros inválidos', { status: 400 });
    await Promise.all([store.delete(key('f')), store.delete(key('t'))]);
    return new Response('ok', { headers: H });
  }

  return new Response('Método no permitido', { status: 405 });
};

export const config = { path: '/api/img' };
