import { getStore } from '@netlify/blobs';

/* Limonapp v63: buzon de sugerencias, errores e ideas. Solo reciben personas con sesion de Google verificada (las demas usan
   el correo desde la app). No se guarda nada de pacientes: el texto pasa por un filtro que tapa numeros largos (cedulas,
   telefonos) y la app avisa que no se escriban datos de pacientes. Solo el administrador (AI_ADMIN_EMAIL, la misma variable
   de /api/ai) puede leer, marcar como resuelto o borrar.
   POST /api/feedback {tipo, texto, vista, v, plat}        -> {ok:true}   (tope de 6 envios por persona al dia)
   GET  /api/feedback?admin=list    (solo administrador)    -> {items:[{id,t,tipo,texto,vista,v,plat,e,hecho}], total}
   POST /api/feedback {action:'done'|'del', id}  (solo administrador) */

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

const TIPOS = ['error', 'idea', 'dato', 'otro'];
const DAY_MAX = 6, MAX_TXT = 1500, MIN_TXT = 5, KEEP = 150;
const H = { 'cache-control': 'no-store', 'content-type': 'application/json; charset=utf-8' };
const J = (o, s) => new Response(JSON.stringify(o), { status: s || 200, headers: H });
const redact = (t) => String(t).replace(/\b\d{7,}\b|\b3\d{2}[ -]?\d{3}[ -]?\d{4}\b/g, '[número]');
const clean = (t, n) => String(t == null ? '' : t).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').trim().slice(0, n);
const getJ = async (store, k, d) => { try { const v = await store.get(k, { type: 'json' }); return v == null ? d : v; } catch (e) { return d; } };

export default async (req) => {
  const a = await authenticate(req);
  if (!a.user) return new Response(a.msg, { status: a.status });
  const um = a.user.user_metadata || {};
  const email = String(a.user.email || '').toLowerCase();
  const verified = !!email && (um.email_verified === true || um.email_verified === 'true');
  const adminEmail = String(process.env.AI_ADMIN_EMAIL || '').trim().toLowerCase();
  const isAdmin = verified && !!adminEmail && email === adminEmail;
  const store = getStore({ name: 'limonapp-feedback', consistency: 'strong' });
  const q = new URL(req.url).searchParams;
  const uid = String(a.user.id).replace(/[^a-zA-Z0-9-]/g, '');

  /* ---- lectura (solo administrador) ---- */
  if (req.method === 'GET') {
    if (!isAdmin) return J({ error: 'No autorizado' }, 403);
    if (q.get('admin') !== 'list') return J({ error: 'Acción no válida' }, 400);
    const l = await store.list({ prefix: 'f_' });
    const keys = (l.blobs || []).map((b) => b.key).sort().reverse();
    const items = [];
    for (const k of keys.slice(0, KEEP)) { const v = await getJ(store, k, null); if (v) items.push(Object.assign({ id: k }, v)); }
    return J({ items, total: keys.length });
  }
  if (req.method !== 'POST') return J({ error: 'Método no permitido' }, 405);

  let body;
  try { body = await req.json(); } catch (e) { return J({ error: 'Datos inválidos' }, 400); }
  body = body && typeof body === 'object' ? body : {};

  /* ---- acciones del administrador ---- */
  if (body.action === 'done' || body.action === 'del') {
    if (!isAdmin) return J({ error: 'No autorizado' }, 403);
    const id = String(body.id || '');
    if (!/^f_[0-9]{13}_[a-z0-9]{1,8}$/.test(id)) return J({ error: 'Identificador inválido' }, 400);
    if (body.action === 'del') { await store.delete(id); return J({ ok: true }); }
    const v = await getJ(store, id, null);
    if (!v) return J({ error: 'No existe' }, 404);
    v.hecho = !v.hecho;
    await store.setJSON(id, v);
    return J({ ok: true, hecho: v.hecho });
  }

  /* ---- envio ---- */
  const tipo = TIPOS.includes(body.tipo) ? body.tipo : 'otro';
  const texto = redact(clean(body.texto, MAX_TXT));
  if (texto.length < MIN_TXT) return J({ error: 'Escribe al menos unas palabras.' }, 400);
  const dy = new Date().toISOString().slice(0, 10);
  const rk = 'rl_' + uid + '_' + dy;
  const n = await getJ(store, rk, 0);
  if (n >= DAY_MAX) return J({ error: 'Llegaste al tope de ' + DAY_MAX + ' envíos de hoy. Gracias por tanto aporte; vuelve mañana.' }, 429);
  const now = Date.now();
  const id = 'f_' + String(now).padStart(13, '0') + '_' + Math.random().toString(36).slice(2, 7);
  await store.setJSON(id, { t: new Date(now).toISOString(), tipo, texto, vista: clean(body.vista, 30), v: clean(body.v, 12), plat: clean(body.plat, 30), e: verified ? email : '', hecho: false });
  await store.setJSON(rk, n + 1);
  return J({ ok: true });
};

export const config = { path: '/api/feedback' };
