import { getStore } from '@netlify/blobs';

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

/* Limonapp: perfiles, equipos por invitación, chat y envío de resúmenes sin identificar. Sesión: Supabase Auth (Google).
   Todo se valida en el servidor: solo ves a quienes comparten tu equipo.
   Cada mensaje es un blob propio (no hay carreras al escribir al mismo tiempo). */
const MAXTXT = 1500, MAXPT = 5000, MAXPHOTO = 45000, MAXMEMBERS = 40, KEEPDAYS = 60;
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const E = (m, s = 400) => J({ error: m }, s);
const cl = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').trim().slice(0, n);
const clean = (s) => String(s || '').replace(/[^a-zA-Z0-9-]/g, '');

const nrm = (v) => String(v || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/\s+/g, ' ').trim();
const TYL = { evolucion: 'Evolución', ingreso: 'Ingreso', interconsulta: 'Interconsulta', lab: 'Paraclínico', img: 'Imagen', epicrisis: 'Epicrisis', nota: 'Nota', plan: 'Plan' };
const PFL = { ini: 'iniciales', age: 'edad', sex: 'sexo', bed: 'cama', adm: 'fecha de ingreso', dx: 'diagnóstico', sev: 'gravedad', cont: 'si pasa X', hx: 'historia clínica' };
const HXL = { motivo: 'motivo de consulta', ea: 'enfermedad actual', ant: 'antecedentes', rs: 'revisión por sistemas', ef: 'examen físico', dx: 'diagnóstico', plan: 'plan', otros: 'otros' };
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
function logLabel(k, ex, v) {
  const old = ex && ex.v;
  if (k === 'p') {
    if (!old || !v) return { op: 'edit', label: 'Datos del paciente' };
    const f = [];
    for (const x of Object.keys(PFL)) {
      if (x === 'hx') { const a = old.hx || {}, c = v.hx || {}; for (const y of new Set([...Object.keys(a), ...Object.keys(c)])) if (!same(a[y], c[y])) f.push(HXL[y] || y); }
      else if (!same(old[x], v[x])) f.push(PFL[x]);
    }
    return f.length ? { op: 'edit', label: 'Datos del paciente: ' + f.join(', ') } : null;
  }
  if (k.startsWith('e:')) {
    const d = v || old || {}, ty = TYL[d.type] || 'Registro', est = d.data && (d.data.est || d.data.serv || '');
    const lab = ty + (est ? ': ' + cl(est, 60) : '');
    if (v === null) return { op: 'del', label: lab };
    return { op: !old ? 'add' : 'edit', label: lab };
  }
  const d = v || old || {}, tx = cl(d.text, 80);
  if (v === null) return { op: 'del', label: 'Pendiente: ' + tx };
  if (!old) return { op: 'add', label: 'Pendiente: ' + tx };
  if (old.done !== v.done) return { op: 'done', label: (v.done ? 'Completó el pendiente: ' : 'Reabrió el pendiente: ') + tx };
  return { op: 'edit', label: 'Pendiente: ' + tx };
}
let USC = { at: 0, list: null };

export default async (req) => {
  if (req.method !== 'POST') return E('Método no permitido', 405);
  const a = await authenticate(req);
  if (!a.user) return E(a.msg, a.status);
  const user = a.user;
  let b;
  try { b = await req.json(); } catch (e) { return E('JSON inválido'); }
  if (!b || typeof b !== 'object') return E('Petición inválida');

  const store = getStore({ name: 'limonapp-social', consistency: 'strong' });
  const uid = clean(user.id);
  const pk = (id) => 'p_' + clean(id);
  const getJ = async (k) => { const v = await store.get(k, { type: 'text' }); if (v == null) return null; try { return JSON.parse(v); } catch (e) { return null; } };
  const putJ = (k, o) => store.set(k, JSON.stringify(o));

  let me = (await getJ(pk(uid))) || { id: uid, name: cl((user.user_metadata && (user.user_metadata.full_name || user.user_metadata.name)) || '', 80), username: '', rank: '', cargo: '', servicio: '', onShift: false, status: 'off', pv: 0, team: null, discoverable: true, invites: [] };
  const ST = ['on', 'rest', 'off'];
  const stOf = (v, fb) => (ST.includes(v) ? v : fb);
  const setSt = (p, v) => { p.status = v; p.onShift = v === 'on'; };
  if (!me.status) me.status = me.onShift ? 'on' : 'off';
  const pub = (p) => ({ id: p.id, name: p.name, username: p.username, rank: p.rank || '', cargo: p.cargo, servicio: p.servicio, onShift: p.status ? p.status === 'on' : !!p.onShift, status: p.status || (p.onShift ? 'on' : 'off'), pv: p.pv || 0 });
  if (!Array.isArray(me.teams)) me.teams = me.team ? [me.team] : [];
  delete me.team;
  if (!Array.isArray(me.invites)) me.invites = [];
  const who = () => cl(((me.rank || '') + ' ' + (me.name || '')).trim(), 90), cargoOf = () => cl(me.cargo || '', 60);
  const sameName = (pp) => cl(((pp.rank || '') + ' ' + (pp.username || pp.name || '')).trim(), 90);
  const act = b.action;

  if (act === 'me') {
    const teams = [];
    for (const c of me.teams) {
      const t = await getJ('t_' + c); if (!t || !t.members.includes(uid)) continue;
      const e = { code: t.code, name: t.name, owner: t.owner === uid, admin: t.owner === uid || (t.admins || []).includes(uid), last: t.last || '', lastFrom: t.lastFrom || '' };
      if (t.dm) { const oid = t.members.find((x) => x !== uid), op = oid && (await getJ(pk(oid))); e.dm = true; e.peer = oid || ''; e.name = op ? sameName(op) : 'Excolega'; e.owner = false; e.admin = false; }
      teams.push(e);
    }
    me.teams = teams.map((x) => x.code);
    const inv = [];
    for (const i of me.invites) { const t = await getJ('t_' + i.code); if (t && !t.members.includes(uid)) inv.push(i); }
    if (inv.length !== me.invites.length) { me.invites = inv; await putJ(pk(uid), me); }
    return J({ me: pub(me), email: user.email || '', teams, photo: me.photo || '', invites: inv, discoverable: me.discoverable !== false });
  }

  if (act === 'saveProfile') {
    me.name = cl(b.name, 80); me.rank = cl(b.rank, 24); me.username = cl(b.username, 60); me.cargo = cl(b.cargo, 60); me.servicio = cl(b.servicio, 80);
    if (b.status !== undefined) setSt(me, stOf(b.status, me.status)); else if (b.onShift !== undefined) setSt(me, b.onShift ? 'on' : 'off');
    if (b.photo !== undefined) {
      if (b.photo === '') { me.photo = ''; me.pv = (me.pv || 0) + 1; }
      else if (typeof b.photo === 'string' && /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(b.photo) && b.photo.length <= MAXPHOTO) { me.photo = b.photo; me.pv = (me.pv || 0) + 1; }
      else return E('Foto inválida o demasiado pesada');
    }
    if (b.discoverable !== undefined) me.discoverable = !!b.discoverable;
    if (!me.name) return E('Escribe tu nombre');
    if (!me.rank) return E('Escribe tu especialidad o rango (p. ej. Est., Int., Res., MG, Urología)');
    await putJ(pk(uid), me);
    return J({ me: pub(me) });
  }

  if (act === 'shift') { if (b.servicio !== undefined) me.servicio = cl(b.servicio, 80); setSt(me, b.status !== undefined ? stOf(b.status, me.status) : (b.onShift ? 'on' : 'off')); await putJ(pk(uid), me); return J({ me: pub(me) }); }

  if (act === 'createTeam') {
    if (me.teams.filter((c) => !c.startsWith('D')).length >= 10) return E('Máximo 10 equipos');
    if (!me.name) return E('Completa tu perfil primero');
    let code = '';
    for (let tries = 0; tries < 5; tries++) {
      code = Array.from({ length: 8 }, () => ALPHA[Math.floor(Math.random() * ALPHA.length)]).join('');
      if (!(await getJ('t_' + code))) break;
    }
    const t = { code, name: cl(b.name, 60) || 'Mi equipo', owner: uid, admins: [], members: [uid], created: Date.now() };
    await putJ('t_' + code, t); me.teams.push(code); await putJ(pk(uid), me);
    return J({ team: { code, name: t.name, owner: true } });
  }

  if (act === 'join') {
    if (me.teams.filter((c) => !c.startsWith('D')).length >= 10) return E('Máximo 10 equipos');
    if (!me.name) return E('Completa tu perfil primero');
    const code = cl(b.code, 12).toUpperCase().replace(/[^A-Z0-9]/g, '');
    const t = code && (await getJ('t_' + code));
    if (!t || t.dm) return E('Ese código no existe', 404);
    if (t.members.length >= MAXMEMBERS) return E('El equipo está lleno');
    if (!t.members.includes(uid)) { t.members.push(uid); await putJ('t_' + code, t); }
    if (!me.teams.includes(code)) me.teams.push(code); await putJ(pk(uid), me);
    me.invites = me.invites.filter((i) => i.code !== code); await putJ(pk(uid), me);
    return J({ team: { code, name: t.name, owner: t.owner === uid, admin: t.owner === uid || (t.admins || []).includes(uid) } });
  }

  if (act === 'leave') {
    const code = cl(b.team, 12).toUpperCase();
    if (me.teams.includes(code)) {
      const t = await getJ('t_' + code);
      if (t && !t.dm) { t.members = t.members.filter((m) => m !== uid); t.admins = (t.admins || []).filter((m) => m !== uid); if (t.owner === uid && t.members.length) { t.owner = t.admins[0] || t.members[0]; t.admins = t.admins.filter((m) => m !== t.owner); } await putJ('t_' + t.code, t); }
      me.teams = me.teams.filter((c) => c !== code);
      if (!me.teams.length) setSt(me, 'off');
      await putJ(pk(uid), me);
    }
    return J({ ok: true });
  }

  /* ---- buscar personas, mensajes directos e invitaciones ---- */
  if (act === 'searchUsers') {
    const q = nrm(b.q); if (q.length < 3) return E('Escribe al menos 3 letras');
    if (!USC.list || Date.now() - USC.at > 60000) {
      const ks = (await store.list({ prefix: 'p_' })).blobs.map((x) => x.key).slice(0, 600), l = [];
      for (const k of ks) { const p = await getJ(k); if (p && p.name && p.rank && p.discoverable !== false) l.push({ id: p.id, name: p.name, username: p.username || '', rank: p.rank || '', cargo: p.cargo || '', servicio: p.servicio || '', st: p.status || (p.onShift ? 'on' : 'off'), k: nrm(p.name + ' ' + (p.username || '') + ' ' + (p.cargo || '') + ' ' + (p.servicio || '')) }); }
      USC = { at: Date.now(), list: l };
    }
    const out = USC.list.filter((p) => p.id !== uid && p.k.includes(q)).slice(0, 12).map(({ k, ...p }) => p);
    return J({ users: out });
  }
  if (act === 'openDm') {
    const oid = clean(b.user); if (!oid || oid === uid) return E('Usuario inválido');
    if (!me.name || !me.rank) return E('Completa tu perfil primero');
    const o = await getJ(pk(oid)); if (!o || !o.name || o.discoverable === false) return E('No encontré a esa persona', 404);
    const hh = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode([uid, oid].sort().join('|'))));
    const code = 'D' + Array.from(hh.slice(0, 10)).map((x) => ALPHA[x % 32]).join('');
    let t0 = await getJ('t_' + code);
    if (!t0) { t0 = { code, name: '', dm: true, owner: null, admins: [], members: [uid, oid].sort(), created: Date.now() }; await putJ('t_' + code, t0); }
    if (!me.teams.includes(code)) { me.teams.push(code); await putJ(pk(uid), me); }
    if (!(o.teams || []).includes(code)) { o.teams = [...(o.teams || []), code]; await putJ(pk(oid), o); }
    return J({ team: { code, name: sameName(o), dm: true, peer: oid, owner: false, admin: false } });
  }
  if (act === 'invAccept' || act === 'invDecline') {
    const code = cl(b.code, 12).toUpperCase();
    me.invites = me.invites.filter((i) => i.code !== code);
    if (act === 'invDecline') { await putJ(pk(uid), me); return J({ ok: true }); }
    const t0 = await getJ('t_' + code); if (!t0 || t0.dm) return E('La invitación ya no es válida', 404);
    if (me.teams.filter((c) => !c.startsWith('D')).length >= 10) return E('Máximo 10 equipos');
    if (t0.members.length >= MAXMEMBERS) return E('El equipo está lleno');
    if (!t0.members.includes(uid)) { t0.members.push(uid); await putJ('t_' + code, t0); }
    if (!me.teams.includes(code)) me.teams.push(code);
    await putJ(pk(uid), me);
    return J({ team: { code, name: t0.name, owner: false, admin: (t0.admins || []).includes(uid) } });
  }

  /* ---- pacientes compartidos: cada elemento (paciente, nota, pendiente) se fusiona por fecha de modificación ---- */
  const MAXSP = 4.5 * 1024 * 1024;
  if (act === 'spCreate') {
    const items = b.items && typeof b.items === 'object' ? b.items : null;
    if (!items || JSON.stringify(items).length > MAXSP) return E('Paciente demasiado grande');
    const id = Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
    const bn = cl(me.username || me.name, 60), now = Date.now(), out = {};
    for (const k of Object.keys(items)) out[k] = { v: items[k], m: now, r: 1, bn };
    await putJ('sp_' + id, { id, owner: uid, access: [uid], rev: 1, items: out, logn: 1, log: [{ id: 'init', n: 1, at: now, by: uid, who: who(), cargo: cargoOf(), op: 'share', label: 'Compartió el paciente' }] });
    return J({ id, rev: 1 });
  }
  if (act === 'spSync') {
    const res = [];
    for (const sh of (Array.isArray(b.shares) ? b.shares.slice(0, 40) : [])) {
      const id = clean(sh.id), d = id && (await getJ('sp_' + id));
      if (!d || !d.access.includes(uid)) { res.push({ id, gone: true }); continue; }
      const ch = sh.changes && typeof sh.changes === 'object' ? sh.changes : {};
      let changed = false; const bn = cl(me.username || me.name, 60);
      const nrev = d.rev + 1;
      if (!Array.isArray(d.log)) { d.log = []; d.logn = 0; }
      for (const k of Object.keys(ch)) {
        const c = ch[k], m = Number(c && c.m) || 0, ex = d.items[k];
        if (!/^(p|e:[\w-]+|t:[\w-]+)$/.test(k)) continue;
        if (!ex || m > ex.m) {
          const nv = c.v === null ? null : c.v;
          if (!(ex && ex.v === null && nv === null)) {
            const lb = logLabel(k, ex, nv);
            if (lb) {
              const last = d.log[d.log.length - 1], now2 = Date.now();
              if (last && last.by === uid && last.k === k && last.op === 'edit' && lb.op === 'edit' && now2 - last.at < 600000) { last.at = now2; last.label = lb.label; last.n = ++d.logn; }
              else { d.logn += 1; d.log.push({ id: Math.random().toString(36).slice(2, 9), n: d.logn, at: now2, by: uid, who: who(), cargo: cargoOf(), k, op: lb.op, label: lb.label }); if (d.log.length > 250) d.log.splice(0, d.log.length - 250); }
            }
          }
          d.items[k] = { v: nv, m, r: nrev, bn }; changed = true;
        }
      }
      if (changed) {
        if (JSON.stringify(d.items).length > MAXSP) return E('Paciente demasiado grande');
        d.rev = nrev; await putJ('sp_' + id, d);
      }
      const since = Number(sh.since) || 0, out = {};
      for (const k of Object.keys(d.items)) if (d.items[k].r > since) out[k] = d.items[k];
      const ls = Number(sh.lsince) || 0;
      res.push({ id, rev: d.rev, items: out, logn: d.logn || 0, log: (d.log || []).filter((x) => x.n > ls) });
    }
    return J({ shares: res });
  }

  /* desde aquí hace falta equipo */
  const tc = cl(b.team, 12).toUpperCase();
  const t = me.teams.includes(tc) ? await getJ('t_' + tc) : null;
  if (!t || !t.members.includes(uid)) { if (me.teams.includes(tc)) { me.teams = me.teams.filter((c) => c !== tc); await putJ(pk(uid), me); } return E('No estás en ese equipo', 403); }
  const isOwn = t.owner === uid, isAdm = isOwn || (t.admins || []).includes(uid), roleOf = (id) => (t.owner === id ? 'owner' : (t.admins || []).includes(id) ? 'admin' : 'member');
  const tinfo = () => ({ code: t.code, name: t.name, owner: isOwn, admin: isAdm, dm: !!t.dm, last: t.last || '', lastFrom: t.lastFrom || '' });
  const mp = 'm_' + t.code + '_', ep = 'e_' + t.code + '_', fp = 'f_' + t.code + '_';
  const stamp = () => String(Date.now()).padStart(13, '0') + '_' + Math.random().toString(36).slice(2, 7);
  const emit = (id, patch, only) => putJ(ep + stamp(), only ? { id, patch, only } : { id, patch });
  const touch = async (mid) => { t.last = mid.slice(mp.length); t.lastFrom = uid; await putJ('t_' + t.code, t); if (t.dm) { const oid = t.members.find((x) => x !== uid), o = oid && (await getJ(pk(oid))); if (o && !(o.teams || []).includes(t.code)) { o.teams = [...(o.teams || []), t.code]; await putJ(pk(oid), o); } } };
  const sys = async (text) => { const id = stamp(); const m = { id: mp + id, from: uid, to: null, kind: 'sys', text: cl(text, 200), at: Date.now() }; await putJ(m.id, m); await touch(m.id); return m; };
  const seeMsg = (m) => m && (!m.to || m.to === uid || m.from === uid) && !(m.hid || []).includes(uid);
  const getMsg = async (id) => { id = String(id || ''); return id.startsWith(mp) ? await getJ(id) : null; };

  if (act === 'poll') {
    const members = [];
    for (const id of t.members) { const p = id === uid ? me : await getJ(pk(id)); if (p) members.push({ ...pub(p), role: roleOf(id) }); }
    const after = cl(b.after, 80);
    let keys = (await store.list({ prefix: mp })).blobs.map((x) => x.key).sort();
    if (after) keys = keys.filter((k) => k > after); else keys = keys.slice(-100);
    keys = keys.slice(-150);
    const msgs = [];
    for (const k of keys) {
      const m = await getJ(k); if (!m) continue;
      if (m.to && m.to !== uid && m.from !== uid) continue;
      if ((m.hid || []).includes(uid)) continue;
      const { hid, ...pubm } = m; msgs.push(pubm);
    }
    const eafter = cl(b.eafter, 90);
    const ekeys = (await store.list({ prefix: ep })).blobs.map((x) => x.key).sort();
    let events = [], ecursor = ekeys.length ? ekeys[ekeys.length - 1] : (eafter || '0');
    if (eafter) {
      for (const k of ekeys.filter((x) => x > eafter).slice(0, 200)) { const ev = await getJ(k); if (ev && (!ev.only || ev.only === uid)) events.push(ev); }
      if (events.length || ekeys.some((x) => x > eafter)) ecursor = ekeys.filter((x) => x > eafter).slice(0, 200).pop() || eafter;
    }
    return J({ team: tinfo(), members, msgs, cursor: keys.length ? keys[keys.length - 1] : after, events, ecursor });
  }


  if (act === 'renameTeam') {
    if (!isAdm || t.dm) return E('Solo los administradores pueden cambiarle el nombre al equipo', 403);
    const nm = cl(b.name, 60); if (!nm) return E('Escribe un nombre');
    t.name = nm; await putJ('t_' + t.code, t);
    return J({ team: tinfo() });
  }

  if (act === 'editMsg') {
    const m = await getMsg(b.id); if (!m || m.from !== uid || m.kind !== 'text' || m.deleted) return E('No puedes editar este mensaje', 403);
    const tx = cl(b.text, MAXTXT); if (!tx) return E('Mensaje vacío');
    m.text = tx; m.edited = true; await putJ(m.id, m); await emit(m.id, { text: tx, edited: true });
    return J({ ok: true });
  }
  if (act === 'delMsg') {
    const m = await getMsg(b.id); if (!m || !seeMsg(m)) return E('Mensaje no encontrado', 404);
    if (b.all) {
      if (m.from !== uid && !isAdm) return E('Solo puedes eliminar para todos tus propios mensajes (los administradores pueden eliminar cualquiera)', 403);
      if (m.file) { try { await store.delete(m.file.id); } catch (e) {} }
      const keep = { id: m.id, from: m.from, to: m.to, kind: 'text', text: '', at: m.at, deleted: true };
      await putJ(m.id, keep); await emit(m.id, { deleted: true, text: '', pin: false, kind: 'text', file: null, pt: null, reply: null });
    } else {
      m.hid = [...(m.hid || []), uid]; await putJ(m.id, m); await emit(m.id, { hide: true }, uid);
    }
    return J({ ok: true });
  }

  if (act === 'setAdmin') {
    if (t.dm || !isOwn) return E('Solo quien creó el equipo puede nombrar o quitar administradores', 403);
    const id = clean(b.user); if (!t.members.includes(id) || id === uid) return E('Miembro inválido');
    t.admins = (t.admins || []).filter((x) => x !== id); if (b.admin) t.admins.push(id);
    await putJ('t_' + t.code, t);
    const tp = await getJ(pk(id)); await sys((b.admin ? 'Nuevo administrador: ' : 'Ya no es administrador: ') + (tp ? sameName(tp) : 'un miembro'));
    return J({ ok: true });
  }
  if (act === 'removeMember') {
    if (t.dm || !isAdm) return E('Solo los administradores pueden retirar miembros', 403);
    const id = clean(b.user); if (!t.members.includes(id) || id === uid) return E('Miembro inválido');
    if (id === t.owner) return E('No se puede retirar a quien creó el equipo', 403);
    if ((t.admins || []).includes(id) && !isOwn) return E('Solo quien creó el equipo puede retirar a un administrador', 403);
    const tp = await getJ(pk(id));
    t.members = t.members.filter((x) => x !== id); t.admins = (t.admins || []).filter((x) => x !== id);
    await putJ('t_' + t.code, t);
    if (tp) { tp.teams = (tp.teams || []).filter((c) => c !== t.code); await putJ(pk(id), tp); }
    await sys((tp ? sameName(tp) : 'Un miembro') + ' fue retirado del equipo');
    return J({ ok: true });
  }
  if (act === 'invite') {
    if (t.dm || !isAdm) return E('Solo los administradores pueden invitar', 403);
    const id = clean(b.user); if (!id || t.members.includes(id)) return E('Esa persona ya está en el equipo');
    if (t.members.length >= MAXMEMBERS) return E('El equipo está lleno');
    const tp = await getJ(pk(id)); if (!tp || !tp.name || tp.discoverable === false) return E('No encontré a esa persona', 404);
    tp.invites = (tp.invites || []).filter((i) => i.code !== t.code);
    if (tp.invites.length >= 20) return E('Esa persona tiene demasiadas invitaciones pendientes');
    tp.invites.push({ code: t.code, team: t.name, by: sameName(me), at: Date.now() });
    await putJ(pk(id), tp);
    return J({ ok: true });
  }
  if (act === 'pinMsg') {
    const m = await getMsg(b.id); if (!m || !seeMsg(m) || m.deleted) return E('Mensaje no encontrado', 404);
    m.pin = !!b.pin; m.pinBy = b.pin ? uid : null; await putJ(m.id, m); await emit(m.id, { pin: m.pin, pinBy: m.pinBy });
    return J({ ok: true });
  }
  if (act === 'sendFile') {
    const name = cl(b.name, 80) || 'documento.pdf', data = String(b.data || '');
    if (!data.startsWith('JVBER') || data.length > 3 * 1024 * 1024 || !/^[A-Za-z0-9+/=]+$/.test(data)) return E('Solo se aceptan PDF de hasta 2 MB');
    let to = b.to ? clean(b.to) : null;
    if (to && (!t.members.includes(to) || to === uid)) return E('Destinatario inválido');
    const id = stamp();
    await store.set(fp + id, data);
    const m = { id: mp + id, from: uid, to, kind: 'file', text: name, file: { id: fp + id, name, size: Math.round(data.length * 0.75) }, at: Date.now() };
    await putJ(m.id, m); await touch(m.id);
    return J({ msg: m });
  }
  if (act === 'getFile') {
    const fid = String(b.id || ''); if (!fid.startsWith(fp)) return E('Archivo no encontrado', 404);
    const m = await getMsg(mp + fid.slice(fp.length));
    if (!seeMsg(m) || m.deleted || !m.file) return E('Archivo no disponible', 404);
    const data = await store.get(fid, { type: 'text' }); if (!data) return E('Archivo no disponible', 404);
    return J({ name: m.file.name, data });
  }

  if (act === 'photos') {
    const out = {};
    for (const id of (Array.isArray(b.ids) ? b.ids.slice(0, MAXMEMBERS) : [])) {
      if (!t.members.includes(clean(id))) continue;
      const p = clean(id) === uid ? me : await getJ(pk(id));
      if (p && p.photo) out[p.id] = p.photo;
    }
    return J({ photos: out });
  }

  if (act === 'send') {
    const kind = b.kind === 'patient' ? 'patient' : 'text';
    const text = cl(b.text, kind === 'patient' ? MAXPT : MAXTXT);
    if (!text) return E('Mensaje vacío');
    let to = b.to ? clean(b.to) : null;
    if (kind === 'patient' && !to) return E('Elige a quién enviar el paciente');
    if (to && (!t.members.includes(to) || to === uid)) return E('Destinatario inválido');
    let share = null;
    if (kind === 'patient' && b.share) {
      share = clean(b.share);
      const d = await getJ('sp_' + share);
      if (!d || !d.access.includes(uid)) return E('Paciente compartido no encontrado');
      if (!d.access.includes(to)) { d.access.push(to); await putJ('sp_' + share, d); }
    }
    const id = stamp();
    const m = { id: mp + id, from: uid, to, kind, text, at: Date.now() };
    if (b.reply) { const o = await getMsg(b.reply); if (seeMsg(o) && !!o.to === !!to) m.reply = { id: o.id, from: o.from, text: cl(o.deleted ? 'Mensaje eliminado' : (o.kind === 'file' ? 'Documento: ' + o.text : o.text), 90) }; }
    if (share) m.share = share;
    if (kind === 'patient' && b.pt && typeof b.pt === 'object') m.pt = { ini: cl(b.pt.ini, 6), age: cl(b.pt.age, 3), sex: cl(b.pt.sex, 2), bed: cl(b.pt.bed, 10), dx: cl(b.pt.dx, 300), sev: cl(b.pt.sev, 12), tasks: (Array.isArray(b.pt.tasks) ? b.pt.tasks : []).slice(0, 15).map((x) => cl(x, 200)).filter(Boolean) };
    await putJ(m.id, m); await touch(m.id);
    if (Math.random() < 0.04) { /* limpieza de mensajes viejos */
      const lim = Date.now() - KEEPDAYS * 864e5;
      const all = (await store.list({ prefix: mp })).blobs.map((x) => x.key);
      for (const k of all) { const ts = parseInt(k.slice(mp.length, mp.length + 13), 10); if (ts && ts < lim) await store.delete(k); }
      for (const pre of [ep, fp]) for (const x of (await store.list({ prefix: pre })).blobs) { const ts = parseInt(x.key.slice(pre.length, pre.length + 13), 10); if (ts && ts < lim) await store.delete(x.key); }
    }
    return J({ msg: m });
  }

  return E('Acción desconocida');
};

export const config = { path: '/api/social' };
