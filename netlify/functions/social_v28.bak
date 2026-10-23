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

  let me = (await getJ(pk(uid))) || { id: uid, name: cl((user.user_metadata && (user.user_metadata.full_name || user.user_metadata.name)) || '', 80), username: '', rank: '', cargo: '', servicio: '', onShift: false, status: 'off', pv: 0, team: null };
  const ST = ['on', 'rest', 'off'];
  const stOf = (v, fb) => (ST.includes(v) ? v : fb);
  const setSt = (p, v) => { p.status = v; p.onShift = v === 'on'; };
  if (!me.status) me.status = me.onShift ? 'on' : 'off';
  const pub = (p) => ({ id: p.id, name: p.name, username: p.username, rank: p.rank || '', cargo: p.cargo, servicio: p.servicio, onShift: p.status ? p.status === 'on' : !!p.onShift, status: p.status || (p.onShift ? 'on' : 'off'), pv: p.pv || 0 });
  if (!Array.isArray(me.teams)) me.teams = me.team ? [me.team] : [];
  delete me.team;
  const act = b.action;

  if (act === 'me') {
    const teams = [];
    for (const c of me.teams) { const t = await getJ('t_' + c); if (t && t.members.includes(uid)) teams.push({ code: t.code, name: t.name, owner: t.owner === uid }); }
    me.teams = teams.map((x) => x.code);
    return J({ me: pub(me), email: user.email || '', teams, photo: me.photo || '' });
  }

  if (act === 'saveProfile') {
    me.name = cl(b.name, 80); me.rank = cl(b.rank, 24); me.username = cl(b.username, 60); me.cargo = cl(b.cargo, 60); me.servicio = cl(b.servicio, 80);
    if (b.status !== undefined) setSt(me, stOf(b.status, me.status)); else if (b.onShift !== undefined) setSt(me, b.onShift ? 'on' : 'off');
    if (b.photo !== undefined) {
      if (b.photo === '') { me.photo = ''; me.pv = (me.pv || 0) + 1; }
      else if (typeof b.photo === 'string' && /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(b.photo) && b.photo.length <= MAXPHOTO) { me.photo = b.photo; me.pv = (me.pv || 0) + 1; }
      else return E('Foto inválida o demasiado pesada');
    }
    if (!me.name) return E('Escribe tu nombre');
    if (!me.rank) return E('Escribe tu especialidad o rango (p. ej. Est., Int., Res., MG, Urología)');
    await putJ(pk(uid), me);
    return J({ me: pub(me) });
  }

  if (act === 'shift') { if (b.servicio !== undefined) me.servicio = cl(b.servicio, 80); setSt(me, b.status !== undefined ? stOf(b.status, me.status) : (b.onShift ? 'on' : 'off')); await putJ(pk(uid), me); return J({ me: pub(me) }); }

  if (act === 'createTeam') {
    if (me.teams.length >= 10) return E('Máximo 10 equipos');
    if (!me.name) return E('Completa tu perfil primero');
    let code = '';
    for (let tries = 0; tries < 5; tries++) {
      code = Array.from({ length: 8 }, () => ALPHA[Math.floor(Math.random() * ALPHA.length)]).join('');
      if (!(await getJ('t_' + code))) break;
    }
    const t = { code, name: cl(b.name, 60) || 'Mi equipo', owner: uid, members: [uid], created: Date.now() };
    await putJ('t_' + code, t); me.teams.push(code); await putJ(pk(uid), me);
    return J({ team: { code, name: t.name, owner: true } });
  }

  if (act === 'join') {
    if (me.teams.length >= 10) return E('Máximo 10 equipos');
    if (!me.name) return E('Completa tu perfil primero');
    const code = cl(b.code, 12).toUpperCase().replace(/[^A-Z0-9]/g, '');
    const t = code && (await getJ('t_' + code));
    if (!t) return E('Ese código no existe', 404);
    if (t.members.length >= MAXMEMBERS) return E('El equipo está lleno');
    if (!t.members.includes(uid)) { t.members.push(uid); await putJ('t_' + code, t); }
    if (!me.teams.includes(code)) me.teams.push(code); await putJ(pk(uid), me);
    return J({ team: { code, name: t.name, owner: t.owner === uid } });
  }

  if (act === 'leave') {
    const code = cl(b.team, 12).toUpperCase();
    if (me.teams.includes(code)) {
      const t = await getJ('t_' + code);
      if (t) { t.members = t.members.filter((m) => m !== uid); if (t.owner === uid && t.members.length) t.owner = t.members[0]; await putJ('t_' + t.code, t); }
      me.teams = me.teams.filter((c) => c !== code);
      if (!me.teams.length) setSt(me, 'off');
      await putJ(pk(uid), me);
    }
    return J({ ok: true });
  }


  /* ---- pacientes compartidos: cada elemento (paciente, nota, pendiente) se fusiona por fecha de modificación ---- */
  const MAXSP = 4.5 * 1024 * 1024;
  if (act === 'spCreate') {
    const items = b.items && typeof b.items === 'object' ? b.items : null;
    if (!items || JSON.stringify(items).length > MAXSP) return E('Paciente demasiado grande');
    const id = Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
    const bn = cl(me.username || me.name, 60), now = Date.now(), out = {};
    for (const k of Object.keys(items)) out[k] = { v: items[k], m: now, r: 1, bn };
    await putJ('sp_' + id, { id, owner: uid, access: [uid], rev: 1, items: out });
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
      for (const k of Object.keys(ch)) {
        const c = ch[k], m = Number(c && c.m) || 0, ex = d.items[k];
        if (!/^(p|e:[\w-]+|t:[\w-]+)$/.test(k)) continue;
        if (!ex || m > ex.m) { d.items[k] = { v: c.v === null ? null : c.v, m, r: nrev, bn }; changed = true; }
      }
      if (changed) {
        if (JSON.stringify(d.items).length > MAXSP) return E('Paciente demasiado grande');
        d.rev = nrev; await putJ('sp_' + id, d);
      }
      const since = Number(sh.since) || 0, out = {};
      for (const k of Object.keys(d.items)) if (d.items[k].r > since) out[k] = d.items[k];
      res.push({ id, rev: d.rev, items: out });
    }
    return J({ shares: res });
  }

  /* desde aquí hace falta equipo */
  const tc = cl(b.team, 12).toUpperCase();
  const t = me.teams.includes(tc) ? await getJ('t_' + tc) : null;
  if (!t || !t.members.includes(uid)) { if (me.teams.includes(tc)) { me.teams = me.teams.filter((c) => c !== tc); await putJ(pk(uid), me); } return E('No estás en ese equipo', 403); }
  const mp = 'm_' + t.code + '_', ep = 'e_' + t.code + '_', fp = 'f_' + t.code + '_';
  const stamp = () => String(Date.now()).padStart(13, '0') + '_' + Math.random().toString(36).slice(2, 7);
  const emit = (id, patch, only) => putJ(ep + stamp(), only ? { id, patch, only } : { id, patch });
  const seeMsg = (m) => m && (!m.to || m.to === uid || m.from === uid) && !(m.hid || []).includes(uid);
  const getMsg = async (id) => { id = String(id || ''); return id.startsWith(mp) ? await getJ(id) : null; };

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
    return J({ team: { code: t.code, name: t.name, owner: t.owner === uid }, members, msgs, cursor: keys.length ? keys[keys.length - 1] : after, events, ecursor });
  }


  if (act === 'renameTeam') {
    if (t.owner !== uid) return E('Solo quien creó el equipo puede cambiarle el nombre', 403);
    const nm = cl(b.name, 60); if (!nm) return E('Escribe un nombre');
    t.name = nm; await putJ('t_' + t.code, t);
    return J({ team: { code: t.code, name: t.name, owner: true } });
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
      if (m.from !== uid && t.owner !== uid) return E('Solo puedes eliminar para todos tus propios mensajes', 403);
      if (m.file) { try { await store.delete(m.file.id); } catch (e) {} }
      const keep = { id: m.id, from: m.from, to: m.to, kind: 'text', text: '', at: m.at, deleted: true };
      await putJ(m.id, keep); await emit(m.id, { deleted: true, text: '', pin: false, kind: 'text', file: null, pt: null, reply: null });
    } else {
      m.hid = [...(m.hid || []), uid]; await putJ(m.id, m); await emit(m.id, { hide: true }, uid);
    }
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
    await putJ(m.id, m);
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
    await putJ(m.id, m);
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
