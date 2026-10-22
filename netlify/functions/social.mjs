import { getStore } from '@netlify/blobs';

/* Limonapp: perfiles, equipos por invitación, chat y envío de resúmenes sin identificar.
   Todo se valida en el servidor: solo ves a quienes comparten tu equipo.
   Cada mensaje es un blob propio (no hay carreras al escribir al mismo tiempo). */
const MAXTXT = 1500, MAXPT = 5000, MAXPHOTO = 45000, MAXMEMBERS = 40, KEEPDAYS = 60;
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const E = (m, s = 400) => J({ error: m }, s);
const cl = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').trim().slice(0, n);
const clean = (s) => String(s || '').replace(/[^a-zA-Z0-9-]/g, '');

export default async (req) => {
  if (req.method !== 'POST') return E('Método no permitido', 405);
  const auth = req.headers.get('authorization') || '';
  if (!/^Bearer\s+\S+/.test(auth)) return E('Sin sesión', 401);
  let user;
  try {
    const r = await fetch(new URL(req.url).origin + '/.netlify/identity/user', { headers: { Authorization: auth } });
    if (!r.ok) return E('Sesión inválida', 401);
    user = await r.json();
  } catch (e) { return E('No pude validar la sesión', 502); }
  if (!user || !user.id) return E('Sesión inválida', 401);
  let b;
  try { b = await req.json(); } catch (e) { return E('JSON inválido'); }
  if (!b || typeof b !== 'object') return E('Petición inválida');

  const store = getStore({ name: 'limonapp-social', consistency: 'strong' });
  const uid = clean(user.id);
  const pk = (id) => 'p_' + clean(id);
  const getJ = async (k) => { const v = await store.get(k, { type: 'text' }); if (v == null) return null; try { return JSON.parse(v); } catch (e) { return null; } };
  const putJ = (k, o) => store.set(k, JSON.stringify(o));

  let me = (await getJ(pk(uid))) || { id: uid, name: cl((user.user_metadata && (user.user_metadata.full_name || user.user_metadata.name)) || '', 80), username: '', cargo: '', servicio: '', onShift: false, pv: 0, team: null };
  const pub = (p) => ({ id: p.id, name: p.name, username: p.username, cargo: p.cargo, servicio: p.servicio, onShift: !!p.onShift, pv: p.pv || 0 });
  const act = b.action;

  if (act === 'me') {
    let team = null;
    if (me.team) { const t = await getJ('t_' + me.team); if (t && t.members.includes(uid)) team = { code: t.code, name: t.name, owner: t.owner === uid }; }
    return J({ me: pub(me), email: user.email || '', team, photo: me.photo || '' });
  }

  if (act === 'saveProfile') {
    me.name = cl(b.name, 80); me.username = cl(b.username, 60); me.cargo = cl(b.cargo, 60); me.servicio = cl(b.servicio, 80);
    if (b.onShift !== undefined) me.onShift = !!b.onShift;
    if (b.photo !== undefined) {
      if (b.photo === '') { me.photo = ''; me.pv = (me.pv || 0) + 1; }
      else if (typeof b.photo === 'string' && /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(b.photo) && b.photo.length <= MAXPHOTO) { me.photo = b.photo; me.pv = (me.pv || 0) + 1; }
      else return E('Foto inválida o demasiado pesada');
    }
    if (!me.name) return E('Escribe tu nombre');
    await putJ(pk(uid), me);
    return J({ me: pub(me) });
  }

  if (act === 'shift') { me.onShift = !!b.onShift; await putJ(pk(uid), me); return J({ me: pub(me) }); }

  if (act === 'createTeam') {
    if (me.team) return E('Ya estás en un equipo. Sal primero para crear otro.');
    if (!me.name) return E('Completa tu perfil primero');
    let code = '';
    for (let tries = 0; tries < 5; tries++) {
      code = Array.from({ length: 8 }, () => ALPHA[Math.floor(Math.random() * ALPHA.length)]).join('');
      if (!(await getJ('t_' + code))) break;
    }
    const t = { code, name: cl(b.name, 60) || 'Mi equipo', owner: uid, members: [uid], created: Date.now() };
    await putJ('t_' + code, t); me.team = code; await putJ(pk(uid), me);
    return J({ team: { code, name: t.name, owner: true } });
  }

  if (act === 'join') {
    if (me.team) return E('Ya estás en un equipo. Sal primero para unirte a otro.');
    if (!me.name) return E('Completa tu perfil primero');
    const code = cl(b.code, 12).toUpperCase().replace(/[^A-Z0-9]/g, '');
    const t = code && (await getJ('t_' + code));
    if (!t) return E('Ese código no existe', 404);
    if (t.members.length >= MAXMEMBERS) return E('El equipo está lleno');
    if (!t.members.includes(uid)) { t.members.push(uid); await putJ('t_' + code, t); }
    me.team = code; await putJ(pk(uid), me);
    return J({ team: { code, name: t.name, owner: t.owner === uid } });
  }

  if (act === 'leave') {
    if (me.team) {
      const t = await getJ('t_' + me.team);
      if (t) { t.members = t.members.filter((m) => m !== uid); if (t.owner === uid && t.members.length) t.owner = t.members[0]; await putJ('t_' + t.code, t); }
      me.team = null; me.onShift = false; await putJ(pk(uid), me);
    }
    return J({ ok: true });
  }

  /* desde aquí hace falta equipo */
  const t = me.team ? await getJ('t_' + me.team) : null;
  if (!t || !t.members.includes(uid)) { if (me.team) { me.team = null; await putJ(pk(uid), me); } return E('No estás en un equipo', 403); }
  const mp = 'm_' + t.code + '_';

  if (act === 'poll') {
    const members = [];
    for (const id of t.members) { const p = id === uid ? me : await getJ(pk(id)); if (p) members.push(pub(p)); }
    const after = cl(b.after, 80);
    let keys = (await store.list({ prefix: mp })).blobs.map((x) => x.key).sort();
    if (after) keys = keys.filter((k) => k > after); else keys = keys.slice(-100);
    keys = keys.slice(-150);
    const msgs = [];
    for (const k of keys) {
      const m = await getJ(k); if (!m) continue;
      if (m.to && m.to !== uid && m.from !== uid) continue;
      msgs.push(m);
    }
    return J({ team: { code: t.code, name: t.name, owner: t.owner === uid }, members, msgs, cursor: keys.length ? keys[keys.length - 1] : after });
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
    const id = String(Date.now()).padStart(13, '0') + '_' + Math.random().toString(36).slice(2, 7);
    const m = { id: mp + id, from: uid, to, kind, text, at: Date.now() };
    if (kind === 'patient' && b.pt && typeof b.pt === 'object') m.pt = { ini: cl(b.pt.ini, 6), age: cl(b.pt.age, 3), sex: cl(b.pt.sex, 2), bed: cl(b.pt.bed, 10), dx: cl(b.pt.dx, 300), sev: cl(b.pt.sev, 12), tasks: (Array.isArray(b.pt.tasks) ? b.pt.tasks : []).slice(0, 15).map((x) => cl(x, 200)).filter(Boolean) };
    await putJ(m.id, m);
    if (Math.random() < 0.04) { /* limpieza de mensajes viejos */
      const lim = Date.now() - KEEPDAYS * 864e5;
      const all = (await store.list({ prefix: mp })).blobs.map((x) => x.key);
      for (const k of all) { const ts = parseInt(k.slice(mp.length, mp.length + 13), 10); if (ts && ts < lim) await store.delete(k); }
    }
    return J({ msg: m });
  }

  return E('Acción desconocida');
};

export const config = { path: '/api/social' };
