/* Limonapp v55: Gemini como LECTOR de historias clinicas (PDF). La clave de Gemini vive SOLO aqui, en las variables de
   entorno de Netlify (GEMINI_API_KEY). El navegador nunca la ve. Cualquier persona con sesion de Google verificada puede
   usarla al importar un PDF (sin aprobacion), con topes por persona. No se guarda el texto de las historias: solo se
   cuenta el uso (cuantas HC, tokens y gasto estimado) por usuario, visible unicamente para el administrador.
   Variables de entorno (Netlify > Site configuration > Environment variables):
     GEMINI_API_KEY   obligatoria. Clave de Google AI Studio.
     AI_ADMIN_EMAIL   tu correo de Google en minusculas (para ver el panel de uso).
     AI_OFF           opcional. 1 = apagar para todos (la app usa el lector basico).
     AI_BUDGET_USD    opcional. Tope mensual ESTIMADO de la funcion (por defecto 6; con plan gratuito pon 1000).
     AI_MODEL         opcional. Modelo (por defecto gemini-3.5-flash-lite).
     AI_DAY, AI_MONTH opcionales. HC por persona al dia y al mes (por defecto 10 y 200).
     AI_THINK         opcional. Nivel de razonamiento en modelos 3.x (por defecto minimal).
     AI_PRICE_IN, AI_PRICE_OUT  opcionales. Dolares por millon de tokens para el gasto ESTIMADO (por defecto 0.50 y 3.00).
   GET  /api/ai?whoami=1   -> {admin, paused, left}
   POST /api/ai?hc=1 {docs}-> {data, left}   (Gemini lee la HC y devuelve diagnostico actual, contexto, egreso, motivo)
   GET  /api/ai?admin=usage (solo administrador) -> uso por persona */

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
const DAY_MAX = () => Number(process.env.AI_DAY || 10);
const MONTH_MAX = () => Number(process.env.AI_MONTH || 200);
const MODEL = () => process.env.AI_MODEL || 'gemini-3.5-flash-lite';
const PIN = () => Number(process.env.AI_PRICE_IN || 0.50);
const POUT = () => Number(process.env.AI_PRICE_OUT || 3.00);
const MAX_DOCS_CHARS = 60000, MAX_OUT = 1500, COOLDOWN_MS = 4000;

/* Instrucciones fijas del lector de HC. El texto de la HC llega ya sin nombre ni cedula (se quitan en el dispositivo). */
const SYS_HC = `Eres el lector de historias clínicas (HC) de Limonapp, una app de apuntes para estudiantes de medicina en Colombia (Hospital Universitario de Santander, HUS). Recibes los documentos de un PDF de HC, ordenados cronológicamente, cada uno con su número, título y fecha. Tu trabajo es SOLO identificar la situación actual del paciente. Los textos clínicos los copia la app tal cual; tú no los reescribes.

REGLAS
1. No inventes nada. Cada dato que devuelvas debe estar escrito en el texto. Para cada dato incluye "cita": una frase LITERAL (copiada exacta, máx. 140 caracteres) del documento de donde lo sacaste, y "doc": el número del documento. Si no encuentras el dato, devuelve null. Es mejor null que adivinar.
2. "Actual" significa lo más reciente por FECHA del documento (no por su posición en el PDF). Un PDF puede juntar varios episodios (hospitalizaciones, urgencias, consultas externas); manda el episodio más reciente.
3. El diagnóstico actual es el diagnóstico principal del documento clínico más reciente que lo contenga (evolución, consulta externa, junta médica, egreso). Escríbelo corto, en español, sin código CIE-10. Un diagnóstico de una consulta externa anterior NO reemplaza a uno más reciente de una hospitalización, ni al revés.
4. Contexto actual: "hospitalizado" (aún internado), "urgencias" (en observación de urgencias), "consulta_externa" (se sigue de forma ambulatoria, o el último documento es una consulta externa posterior a cualquier hospitalización) o "egresado" (el último evento es un egreso/salida y no hay actividad hospitalaria posterior).
5. Un ingreso a UCI o a otro servicio es un INGRESO a ese servicio, no una evolución.
6. El motivo de ingreso actual es por qué ingresó al episodio actual (por ejemplo, remitido de otra institución por X, o ingreso por urgencias por Y). Búscalo en el documento de ingreso; si no hay uno, en la primera evolución o nota del episodio, que a veces lo cuenta en el texto.
7. Si hay dudas o el texto es ambiguo, dilo en "notas" (máx. 3, una línea cada una).

ABREVIATURAS Y FORMAS DE ESCRIBIR (los médicos abrevian; interprétalas por el contexto)
- "SS" al inicio de una línea o seguido de un examen/servicio = "se solicita" / "solicitud de" (p. ej. "SS JUNTA" = se solicita junta médica; "SS TAC" = se solicita TAC). "SS 0,9%", "SSN" o "SS" junto a un líquido o a mL = solución salina. No es "sin signos".
- IC / Ic / ICx = interconsulta; "valoración por X" y "remisión a X" también son interconsulta o remisión. CEX / CE / "cons ext" = consulta externa. EV / Evol = evolución. ING = ingreso. HC = historia clínica. EPS = aseguradora. APP / AP = antecedentes patológicos; AQx / APQ = quirúrgicos; AF = familiares; EA = enfermedad actual; MC = motivo de consulta; RS = revisión por sistemas; EF = examen físico; Dx = diagnóstico; Tx = tratamiento; Px = pronóstico o paraclínicos según contexto; Rx = radiografía; Qx / CX = cirugía; PO / POP / POD = postoperatorio / día postoperatorio; TQ = toracostomía o tubo según contexto.
- Imágenes y exámenes: TAC / TC = tomografía; RMN / RM = resonancia; US / ECO = ecografía; EKG / ECG = electrocardiograma; Hb, Hto, Leu, Plaq, Cr, BUN, PCR (proteína C reactiva; también reacción en cadena de la polimerasa según contexto), Na, K, Cl, Gases ART, Lactato, TP / TPT / INR.
- Servicios: UCI / UCIA (cuidado intensivo adultos), UCE / UCIN, URG (urgencias), HOSP, CX (cirugía), ORTO, NCX (neurocirugía), URO, MI (medicina interna), GINECO, PEDIA, ORL, OFT, UROG.
- Vías y esquemas: VO, IV / EV, SC, IM, SL; QD, BID, TID, QID, c/8h, c/12h; PRN (si necesita); NVO / NPO (nada por vía oral); LEV (líquidos endovenosos); AINES, ATB (antibióticos).
- Diagnósticos frecuentes: HTA, DM2, ERC, EPOC, ITU / IVU, HDA / HDB, TVP, TEP, SCA, FA, ICC, ACV / AVC, TCE, CA = cáncer según contexto, HBP = hiperplasia benigna de próstata, TU = tumor, "Ca" seguido de un órgano = cáncer de ese órgano.
- Un documento "JUNTA" o "JUNTA MÉDICA" es una reunión de especialistas que decide la conducta: su diagnóstico y motivo cuentan como los más recientes si su fecha lo es.
- Si una sigla tiene varios significados, elige el que encaje con el contexto; si no puedes decidir, no la uses como fundamento del dato y avisa en "notas".

SALIDA: responde SOLO un JSON válido, sin texto adicional ni markdown, con exactamente estas claves:
{"contexto_actual":"hospitalizado|urgencias|consulta_externa|egresado|null",
 "diagnostico_actual":{"texto":"...","doc":0,"cita":"..."}|null,
 "motivo_ingreso_actual":{"texto":"...","doc":0,"cita":"..."}|null,
 "fecha_ingreso_actual":"AAAA-MM-DD"|null,
 "egreso":{"fecha":"AAAA-MM-DD"|null,"destino":"...","doc":0,"cita":"..."}|null,
 "notas":["..."]}
"egreso" solo si el paciente fue egresado y no hay actividad hospitalaria posterior; si no, null.`;

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
  const empty = () => ({ n: 0, f: 0, tin: 0, tout: 0, usd: 0 });

  /* ---- panel de uso (solo administrador) ---- */
  if (q.get('admin')) {
    if (!isAdmin) return J({ error: 'No autorizado' }, 403);
    if (q.get('admin') !== 'usage') return J({ error: 'Acción no válida' }, 400);
    const use = await getJ(store, 'usage', {});
    const g = await getJ(store, 'm_' + mo, { usd: 0, n: 0 });
    const rows = Object.keys(use).map((k) => { const u = use[k]; const m = (u.m && u.m[mo]) || empty(); return { e: u.e || '(sin correo)', first: u.first || '', last: u.last || '', today: (u.d && u.d[dy]) || 0, month: m, total: u.t || empty() }; })
      .sort((x, y) => (y.month.usd - x.month.usd) || (y.total.n - x.total.n));
    return J({ rows, month: mo, global: g, budget: MONTH_BUDGET(), dayMax: DAY_MAX(), monthMax: MONTH_MAX(), price: { in: PIN(), out: POUT() }, model: MODEL() });
  }

  const off = process.env.AI_OFF === '1' || !process.env.GEMINI_API_KEY;
  const g = await getJ(store, 'm_' + mo, { usd: 0, n: 0 });
  const paused = off || g.usd >= MONTH_BUDGET();
  const ud = await getJ(store, 'u_' + uid + '_' + dy, { n: 0, last: 0 });
  const um2 = await getJ(store, 'u_' + uid + '_' + mo, { n: 0 });
  const left = { day: Math.max(0, DAY_MAX() - ud.n), month: Math.max(0, MONTH_MAX() - um2.n) };
  if (req.method === 'GET') return J({ allowed: verified, admin: isAdmin, paused, left });
  if (req.method !== 'POST' || !q.get('hc')) return J({ error: 'Método no permitido' }, 405);

  /* ---- lectura de una HC ---- */
  if (!verified) return J({ error: 'Tu cuenta de Google no tiene el correo verificado.', code: 'noverif' }, 403);
  if (paused) return J({ error: 'El lector con IA está en pausa. Uso el lector básico.', code: 'paused' }, 503);
  if (left.day <= 0) return J({ error: 'Llegaste al límite de HC con IA de hoy. Uso el lector básico.', code: 'day', left }, 429);
  if (left.month <= 0) return J({ error: 'Llegaste al límite de este mes. Uso el lector básico.', code: 'month', left }, 429);
  const wait = COOLDOWN_MS - (Date.now() - (ud.last || 0));
  if (wait > 0) return J({ error: 'Espera ' + Math.ceil(wait / 1000) + ' s antes de leer otra HC.', code: 'cool' }, 429);

  let b = {}; try { b = await req.json(); } catch (e) { return J({ error: 'Cuerpo no válido' }, 400); }
  const docs = Array.isArray(b.docs) ? b.docs.slice(0, 400) : [];
  let body = docs.map((d, i) => '### DOC ' + (Number.isFinite(+d.i) ? +d.i : i) + ' | ' + String(d.t || '').slice(0, 120) + (d.s ? ' | ' + String(d.s).slice(0, 80) : '') + ' | ' + String(d.at || '').slice(0, 16) + '\n' + redact(String(d.x || '').slice(0, 4000))).join('\n\n');
  if (body.replace(/\s/g, '').length < 40) return J({ error: 'No hay texto que leer.' }, 400);
  if (body.length > MAX_DOCS_CHARS) body = body.slice(0, MAX_DOCS_CHARS);

  /* se anota el intento ANTES de llamar (si la llamada falla o se corta, igual cuenta) */
  ud.n += 1; ud.last = Date.now(); um2.n += 1;
  await store.setJSON('u_' + uid + '_' + dy, ud);
  await store.setJSON('u_' + uid + '_' + mo, um2);

  const model = MODEL();
  const gen = { maxOutputTokens: MAX_OUT * 2, temperature: 0.1, responseMimeType: 'application/json' };
  if (/2\.5/.test(model)) gen.thinkingConfig = { thinkingBudget: 0 };
  else gen.thinkingConfig = { thinkingLevel: String(process.env.AI_THINK || 'minimal').toLowerCase() };
  const call = async (cfg) => {
    const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/' + encodeURIComponent(model) + ':generateContent', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-goog-api-key': process.env.GEMINI_API_KEY },
      body: JSON.stringify({ systemInstruction: { parts: [{ text: SYS_HC }] }, contents: [{ role: 'user', parts: [{ text: body }] }], generationConfig: cfg }),
      signal: AbortSignal.timeout(8000), /* Netlify corta las funciones a los 10 s: mejor responder un error legible que un 502 */
    });
    const tx = await r.text(); let j = null; try { j = JSON.parse(tx); } catch (e) {}
    return { r, j };
  };
  let res, fail = '';
  try {
    res = await call(gen);
    if (!res.r.ok && res.r.status === 400) { const g2 = Object.assign({}, gen); delete g2.thinkingConfig; res = await call(g2); }
  } catch (e) { fail = (e && (e.name === 'TimeoutError' || e.name === 'AbortError')) ? 'La IA tardó demasiado.' : 'No pude conectar con la IA.'; }
  if (!fail && !res.r.ok) fail = 'La IA no respondió (' + res.r.status + ').';
  const um3 = (res && res.j && res.j.usageMetadata) || {};
  const tin = um3.promptTokenCount || Math.ceil(body.length / 3), tout = (um3.candidatesTokenCount || 0) + (um3.thoughtsTokenCount || 0);
  const usd = (tin * PIN() + (tout || (fail ? 0 : MAX_OUT)) * POUT()) / 1e6;
  let data = null;
  if (!fail) {
    const out = ((res.j && res.j.candidates && res.j.candidates[0] && res.j.candidates[0].content && res.j.candidates[0].content.parts) || []).map((p) => p.text || '').join('').trim();
    const mm = /\{[\s\S]*\}/.exec(out);
    try { data = JSON.parse(mm ? mm[0] : out); } catch (e) { data = null; }
    if (!data || typeof data !== 'object') fail = 'La IA no devolvió un resultado legible.';
  }
  /* contabilidad: global del mes y por persona (solo conteos, nunca el texto) */
  g.usd = Math.round((g.usd + usd) * 1e6) / 1e6; g.n += 1;
  await store.setJSON('m_' + mo, g);
  try {
    const use = await getJ(store, 'usage', {});
    const u = use[uid] || { e: email, first: now.toISOString(), m: {}, d: {}, t: empty() };
    u.e = email; u.last = now.toISOString();
    const add = (o) => { o.n += 1; if (fail) o.f += 1; o.tin += tin; o.tout += tout; o.usd = Math.round((o.usd + usd) * 1e6) / 1e6; };
    u.m[mo] = u.m[mo] || empty(); add(u.m[mo]); u.t = u.t || empty(); add(u.t);
    u.d = u.d || {}; u.d[dy] = (u.d[dy] || 0) + 1;
    Object.keys(u.d).sort().slice(0, -35).forEach((k) => delete u.d[k]);
    use[uid] = u;
    await store.setJSON('usage', use);
  } catch (e) {}
  if (fail) return J({ error: fail + ' Uso el lector básico.', code: 'ai' }, 502);
  return J({ data, left: { day: Math.max(0, DAY_MAX() - ud.n), month: Math.max(0, MONTH_MAX() - um2.n) } });
};

export const config = { path: '/api/ai' };
