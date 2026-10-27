import { getStore } from '@netlify/blobs';

/* Limonapp: IA compartida (v44). La clave de Gemini vive SOLO aquí, en las variables de entorno de Netlify
   (GEMINI_API_KEY). El navegador nunca la ve. El servidor pone los topes y las instrucciones; nada de lo que se
   escribe se guarda ni se registra.
   Variables de entorno (Netlify > Site configuration > Environment variables):
     GEMINI_API_KEY   obligatoria. Clave de Google AI Studio.
     AI_ADMIN_EMAIL   obligatoria para aprobar usuarios: tu correo de Google (en minúsculas).
     AI_OFF           opcional. Ponla en 1 para apagar la IA para todos (interruptor).
     AI_BUDGET_USD    opcional. Tope mensual estimado de esta función (por defecto 6).
     AI_MODEL         opcional. Modelo (por defecto gemini-2.5-flash-lite).
     AI_DAY, AI_MONTH opcionales. Usos por persona al día y al mes (por defecto 15 y 200).
     AI_PRICE_IN, AI_PRICE_OUT  opcionales. Dólares por millón de tokens (por defecto 0.30 y 2.50: cálculo prudente).
   GET  /api/ai?whoami=1            -> estado: permitido, administrador, restantes, IA en pausa
   POST /api/ai {pre,text,cust?,extra?} -> {text, left}
   GET  /api/ai?admin=list · POST /api/ai?admin=add|remove {email}  (solo el administrador) */

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

const MONTH_BUDGET = () => Number(process.env.AI_BUDGET_USD || 6);
const DAY_MAX = () => Number(process.env.AI_DAY || 15);
const MONTH_MAX = () => Number(process.env.AI_MONTH || 200);
const MODEL = () => process.env.AI_MODEL || 'gemini-2.5-flash-lite';
const PIN = () => Number(process.env.AI_PRICE_IN || 0.30);
const POUT = () => Number(process.env.AI_PRICE_OUT || 2.50);
const MAX_TEXT = 4000, MAX_OUT = 700, COOLDOWN_MS = 15000;

const AIBASE = 'Eres un asistente para un estudiante de medicina en Colombia que escribe notas de rotación e historia clínica. Responde en español clínico claro y conciso. No inventes datos que no estén en el texto: si falta información, márcalo como [FALTA: ...]. No pidas ni repitas nombres, cédulas o teléfonos. Tus respuestas son sugerencias que el estudiante debe verificar con el médico tratante; no des órdenes definitivas. Solo ayudas con notas clínicas y de estudio de medicina; si el texto no tiene relación con eso, responde únicamente: "Solo puedo ayudar con notas clínicas y de estudio."';
const PRE = {
  corregir: 'Corrige ortografía, puntuación y redacción del texto conservando exactamente su contenido clínico y las abreviaturas estándar. No añadas información. Devuelve solo el texto corregido.',
  soap: 'Reorganiza el texto como evolución con las secciones S (subjetivo), O (objetivo), A (análisis) y P (plan), usando solo lo que está escrito. Lo que no aparezca, márcalo como [FALTA]. Devuelve solo la nota reorganizada.',
  revisar: 'Revisa el texto sin reescribirlo. Haz una lista breve de: incoherencias (fechas, dosis, lateralidad, diagnóstico contra plan), datos que faltan y preguntas que haría un docente. Si todo es coherente, dilo.',
  plan: 'A partir de la evolución o el plan, sugiere pendientes, controles o paraclínicos de seguimiento y signos de alarma a vigilar. Presenta cada punto como una sugerencia a verificar con el médico tratante y justifícala en una línea.',
  entrega: 'Resume el texto en máximo 6 líneas para entrega de turno: diagnóstico, evolución, pendientes y qué hacer si ocurre un cambio (si pasa X, hacer Y). Solo con datos presentes en el texto.',
  de: 'Traduce el texto al alemán médico (estilo de informe clínico), conservando abreviaturas y estructura. No añadas ni quites contenido. Devuelve solo la traducción.',
  explicar: 'Explica el razonamiento clínico detrás del texto: primero la fisiopatología y la intuición, luego el detalle. Distingue qué proviene de guías o evidencia y qué es interpretación. Señala qué debería aprender el estudiante de este caso.',
};
const H = { 'cache-control': 'no-store', 'content-type': 'application/json; charset=utf-8' };
const J = (o, s) => new Response(JSON.stringify(o), { status: s || 200, headers: H });
const redact = (t) => String(t).replace(/\b\d{7,}\b|\b3\d{2}[ -]?\d{3}[ -]?\d{4}\b/g, '[número]');
const ymd = (d) => d.toISOString().slice(0, 10);
const getJ = async (store, k, d) => { try { const v = await store.get(k, { type: 'json' }); return v == null ? d : v; } catch (e) { return d; } };

export default async (req) => {
  const a = await authenticate(req);
  if (!a.user) return new Response(a.msg, { status: a.status });
  const um = a.user.user_metadata || {};
  const email = String(a.user.email || '').toLowerCase();
  const verified = !!email && (um.email_verified === true || um.email_verified === 'true');
  const adminEmail = String(process.env.AI_ADMIN_EMAIL || '').trim().toLowerCase();
  const isAdmin = verified && !!adminEmail && email === adminEmail;
  const store = getStore({ name: 'limonapp-ai', consistency: 'strong' });
  const q = new URL(req.url).searchParams;
  const now = new Date(), mo = ymd(now).slice(0, 7), dy = ymd(now);
  const uid = String(a.user.id).replace(/[^a-zA-Z0-9-]/g, '');

  /* ---- administración de usuarios aprobados ---- */
  const adm = q.get('admin');
  if (adm) {
    if (!isAdmin) return J({ error: 'No autorizado' }, 403);
    const allow = await getJ(store, 'allow', {});
    if (adm === 'list') return J({ users: Object.keys(allow).map((h) => ({ h, e: allow[h].e })).sort((x, y) => x.e.localeCompare(y.e)) });
    if (req.method !== 'POST') return J({ error: 'Método no permitido' }, 405);
    let b = {}; try { b = await req.json(); } catch (e) {}
    const em = String(b.email || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em) || em.length > 120) return J({ error: 'Correo no válido' }, 400);
    const h = await sha256(em);
    if (adm === 'add') { if (Object.keys(allow).length >= 200) return J({ error: 'Demasiados usuarios' }, 400); allow[h] = { e: em, at: now.toISOString() }; }
    else if (adm === 'remove') delete allow[h];
    else return J({ error: 'Acción no válida' }, 400);
    await store.setJSON('allow', allow);
    return J({ ok: true, users: Object.keys(allow).map((x) => ({ h: x, e: allow[x].e })).sort((x, y) => x.e.localeCompare(y.e)) });
  }

  const off = process.env.AI_OFF === '1' || !process.env.GEMINI_API_KEY;
  let allowed = isAdmin;
  if (!allowed && verified) { const allow = await getJ(store, 'allow', {}); allowed = Object.prototype.hasOwnProperty.call(allow, await sha256(email)); }
  const g = await getJ(store, 'm_' + mo, { usd: 0, n: 0 });
  const paused = off || g.usd >= MONTH_BUDGET();
  const ud = await getJ(store, 'u_' + uid + '_' + dy, { n: 0, last: 0 });
  const um2 = await getJ(store, 'u_' + uid + '_' + mo, { n: 0 });
  const left = { day: Math.max(0, DAY_MAX() - ud.n), month: Math.max(0, MONTH_MAX() - um2.n) };

  if (req.method === 'GET') return J({ allowed, admin: isAdmin, paused, left });
  if (req.method !== 'POST') return J({ error: 'Método no permitido' }, 405);

  /* ---- uso ---- */
  if (!allowed) return J({ error: 'Tu cuenta aún no tiene acceso a la IA de Limonapp.', code: 'noaccess' }, 403);
  if (paused) return J({ error: 'La IA de Limonapp está en pausa este mes.', code: 'paused' }, 503);
  if (left.day <= 0) return J({ error: 'Llegaste al límite de hoy. Mañana vuelve a empezar.', code: 'day', left }, 429);
  if (left.month <= 0) return J({ error: 'Llegaste al límite de este mes.', code: 'month', left }, 429);
  const wait = COOLDOWN_MS - (Date.now() - (ud.last || 0));
  if (wait > 0) return J({ error: 'Espera ' + Math.ceil(wait / 1000) + ' s antes de enviar otra vez.', code: 'cool' }, 429);

  let b = {}; try { b = await req.json(); } catch (e) { return J({ error: 'Cuerpo no válido' }, 400); }
  const pre = String(b.pre || '');
  let inst = PRE[pre];
  if (pre === 'custom') inst = String(b.cust || '').trim().slice(0, 300);
  if (!inst) return J({ error: 'Instrucción no válida' }, 400);
  const text = redact(String(b.text || '').trim());
  if (!text) return J({ error: 'No hay texto' }, 400);
  if (text.length > MAX_TEXT) return J({ error: 'El texto es demasiado largo (máximo ' + MAX_TEXT + ' caracteres).' }, 413);
  const extra = String(b.extra || '').trim().slice(0, 200);
  const sys = AIBASE + '\n\nTarea: ' + inst + (extra ? '\n\nInstrucción adicional del usuario: ' + extra : '');

  /* se anota el intento ANTES de llamar (si la llamada falla o se corta, igual cuenta) */
  ud.n += 1; ud.last = Date.now(); um2.n += 1;
  await store.setJSON('u_' + uid + '_' + dy, ud);
  await store.setJSON('u_' + uid + '_' + mo, um2);

  const model = MODEL();
  const gen = { maxOutputTokens: MAX_OUT, temperature: 0.3 };
  if (/2\.5/.test(model)) gen.thinkingConfig = { thinkingBudget: 0 };
  let r, j = null;
  try {
    r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/' + encodeURIComponent(model) + ':generateContent', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-goog-api-key': process.env.GEMINI_API_KEY },
      body: JSON.stringify({ systemInstruction: { parts: [{ text: sys }] }, contents: [{ role: 'user', parts: [{ text }] }], generationConfig: gen }),
    });
    const tx = await r.text();
    try { j = JSON.parse(tx); } catch (e) {}
  } catch (e) { return J({ error: 'No pude conectar con la IA. Intenta de nuevo.' }, 502); }
  if (!r.ok) return J({ error: 'La IA no respondió (' + r.status + '). Intenta más tarde.' }, 502);
  const um3 = j && j.usageMetadata || {};
  const usd = ((um3.promptTokenCount || Math.ceil((sys.length + text.length) / 3)) * PIN() + ((um3.candidatesTokenCount || 0) + (um3.thoughtsTokenCount || 0) || MAX_OUT) * POUT()) / 1e6;
  g.usd = Math.round((g.usd + usd) * 1e6) / 1e6; g.n += 1;
  await store.setJSON('m_' + mo, g);
  const out = ((j && j.candidates && j.candidates[0] && j.candidates[0].content && j.candidates[0].content.parts) || []).map((p) => p.text || '').join('').trim();
  if (!out) return J({ error: 'La IA no devolvió texto. Prueba con otro fragmento.' }, 502);
  return J({ text: out, left: { day: Math.max(0, DAY_MAX() - ud.n), month: Math.max(0, MONTH_MAX() - um2.n) } });
};

export const config = { path: '/api/ai' };
