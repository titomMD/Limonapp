import { getStore } from '@netlify/blobs';

/* Limonapp v55: Gemini como LECTOR de historias clinicas (PDF). La clave de Gemini vive SOLO aqui, en las variables de
   entorno de Netlify (GEMINI_API_KEY). El navegador nunca la ve. Cualquier persona con sesion de Google verificada puede
   usarla al importar un PDF (sin aprobacion), con topes por persona. No se guarda el texto de las historias: solo se
   cuenta el uso (cuantas HC, tokens y gasto estimado) por usuario, visible unicamente para el administrador.
   Variables de entorno (Netlify > Site configuration > Environment variables):
     GEMINI_API_KEY   obligatoria. Clave de Google AI Studio.
     AI_ADMIN_EMAIL   tu correo de Google en minusculas (para ver el panel de uso).
     AI_OFF           opcional. 1 = apagar para todos (la app usa el lector basico).
     AI_BUDGET_USD    opcional. Tope mensual ESTIMADO de la funcion (por defecto 6; con plan gratuito pon 1000).
     AI_MODEL         opcional. Modelo principal (por defecto gemini-3.6-flash).
     AI_MODEL2        opcional. Modelo de respaldo si el principal se queda sin cuota o falla (por defecto gemini-3.5-flash-lite).
     AI_DAY, AI_MONTH opcionales. HC por persona al dia y al mes (por defecto 10 y 200).
     AI_THINK         opcional. Nivel de razonamiento en modelos 3.x (por defecto minimal).
     AI_ESP           opcional. 1 = añadir al lector una pista breve según el servicio del paciente (esp=<clave>). Apagado por defecto.
     AI_PRICE_IN, AI_PRICE_OUT  opcionales. Dolares por millon de tokens para el gasto ESTIMADO (por defecto, segun el modelo: 3.6/3.8 Flash 0.75 y 3.75; Flash Lite 0.30 y 2.50).
   GET  /api/ai?whoami=1   -> {admin, paused, left}
   POST /api/ai?hc=1[&esp=clave] {docs}-> {data, left}   (Gemini lee la HC y devuelve diagnostico actual, contexto, egreso, motivo)
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
const MODEL = () => process.env.AI_MODEL || 'gemini-3.6-flash';
const MODEL2 = () => (process.env.AI_MODEL2 === undefined ? 'gemini-3.5-flash-lite' : process.env.AI_MODEL2);
const PIN = (m) => Number(process.env.AI_PRICE_IN || (/lite/.test(m || '') ? 0.30 : 0.75));
const POUT = (m) => Number(process.env.AI_PRICE_OUT || (/lite/.test(m || '') ? 2.50 : 3.75));
const MAX_DOCS_CHARS = 60000, MAX_OUT = 1500, COOLDOWN_MS = 4000;

/* Instrucciones fijas del lector de HC. El texto de la HC llega ya sin nombre ni cedula (se quitan en el dispositivo). */
const SYS_HC = `Eres el lector de historias clínicas (HC) de Limonapp, una app de apuntes para estudiantes de medicina en Colombia (Hospital Universitario de Santander, HUS). Recibes los documentos de un PDF de HC, ordenados cronológicamente, cada uno con su número, título y fecha. Tu trabajo es SOLO identificar la situación actual del paciente. Los textos clínicos los copia la app tal cual; tú no los reescribes.

REGLAS
1. No inventes nada. Cada dato que devuelvas debe estar escrito en el texto. Para cada dato incluye "cita": una frase LITERAL (copiada exacta, máx. 140 caracteres) del documento de donde lo sacaste, y "doc": el número del documento. Si no encuentras el dato, devuelve null. Es mejor null que adivinar.
2. "Actual" significa lo más reciente por FECHA del documento (no por su posición en el PDF). Un PDF puede juntar varios episodios (hospitalizaciones, urgencias, consultas externas); manda el episodio más reciente.
3. DIAGNÓSTICO PRINCIPAL ACTUAL. Es la enfermedad que motiva la atención en curso: por la que el paciente está ingresado, será operado, se discute en junta o se sigue con el especialista. Decídelo con estos pasos:
   a) Primero llena "candidatos": hasta 4 diagnósticos distintos que veas en los documentos más recientes, cada uno con "dx" (corto), "doc", "fuente" y "rol".
      "fuente" = el servicio que lo escribe (urología, cirugía, oncología, nefrología, anestesiología, medicina interna...).
      "rol" = "motivo" (la enfermedad por la que se atiende, se opera o se discute en junta), "comorbilidad" (HTA, DM2, cardiopatía, EPOC, ERC, hipotiroidismo, obesidad... que acompañan), "consecuencia" (una complicación de la enfermedad principal, p. ej. ERC por litiasis, anemia por sangrado) u "otro_proceso" (un procedimiento programado por otro motivo, p. ej. una endoscopia).
   b) Elige como diagnóstico_actual un candidato con rol "motivo". NUNCA elijas "comorbilidad" ni "consecuencia", aunque su código CIE-10 aparezca en el documento más reciente.
   c) Las valoraciones preanestésicas, preoperatorias y de cardiología o medicina interna casi siempre listan comorbilidades y sus códigos CIE-10 no definen el diagnóstico principal. El código CIE-10 de la última línea del PDF no es automáticamente el principal.
   d) Si hay varios con rol "motivo", elige el del servicio que ha pedido la junta o el procedimiento, o el más repetido en los documentos de ese servicio.
   e) Si el diagnóstico solo está como sospecha, probable, posible, "en estudio" o "a descartar" en el servicio tratante, devuélvelo con "certeza":"sospecha". Si hay una confirmación posterior (patología, imagen, cirugía), "certeza":"confirmado" y el diagnóstico más reciente reemplaza al anterior (p. ej. un "tumor de comportamiento incierto" antes de la biopsia se reemplaza por "cáncer de próstata" cuando sale la patología).
   f) Escríbelo corto, en español, sin código CIE-10. En "cita" copia una línea literal donde aparezca ese diagnóstico, de preferencia del servicio tratante.
   Ejemplos (casos inventados):
   - Paciente que ingresó por colecistitis aguda; el último documento es una valoración preanestésica que lista HTA y fibrilación auricular. candidatos: colecistitis aguda (motivo), HTA (comorbilidad), fibrilación auricular (comorbilidad). Respuesta: colecistitis aguda.
   - Paciente con tumor de colon en seguimiento por oncología; el último documento es de cardiología con "I255 cardiomiopatía isquémica". Respuesta: tumor de colon (el diagnóstico de cardiología es comorbilidad).
   - Paciente con obstrucción ureteral por cálculo, ERC estadio 2 en control con nefrología, junta de urología pedida por el cálculo. Respuesta: cálculo ureteral con obstrucción (la ERC es consecuencia).
   - Paciente referido por sospecha de masa pulmonar, estudio en curso, sin patología. Respuesta: "masa pulmonar en estudio" con certeza "sospecha".
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
{"candidatos":[{"dx":"...","doc":0,"fuente":"...","rol":"motivo|comorbilidad|consecuencia|otro_proceso"}],
 "contexto_actual":"hospitalizado|urgencias|consulta_externa|egresado|null",
 "diagnostico_actual":{"texto":"...","doc":0,"cita":"...","certeza":"confirmado|sospecha"}|null,
 "motivo_ingreso_actual":{"texto":"...","doc":0,"cita":"..."}|null,
 "fecha_ingreso_actual":"AAAA-MM-DD"|null,
 "egreso":{"fecha":"AAAA-MM-DD"|null,"destino":"...","doc":0,"cita":"..."}|null,
 "notas":["..."]}
"egreso" solo si el paciente fue egresado y no hay actividad hospitalaria posterior; si no, null.
"fecha_ingreso_actual" solo si el paciente está hospitalizado o en urgencias ahora; en consulta_externa va null. En consulta_externa, "motivo_ingreso_actual" es el motivo de consulta de la última consulta. Cierra bien todos los corchetes y llaves: cada objeto se cierra antes de pasar a la siguiente clave.`;

/* Pistas por especialidad (v63). Cambios sutiles: no tocan las reglas, la salida ni la exigencia de citas; solo ayudan a decidir
   cuál diagnóstico es el "motivo" en cada servicio y a interpretar siglas ambiguas. Solo se usan si AI_ESP=1 y la app manda esp=<clave>.
   Las claves son las de la lista ESP de index.html. */
const ESPH = {
  cirugia: 'Cirugía general. El diagnóstico es la enfermedad que se opera o se vigila (apendicitis, colecistitis, hernia, obstrucción intestinal, abdomen agudo), no la operación: "colecistectomía" es el procedimiento y el diagnóstico es "colecistitis". Si ya fue operado, conserva el diagnóstico que motivó la cirugía y, si ya salió la patología, el hallazgo confirmado. POP / POD = día postoperatorio.',
  medint: 'Medicina interna: los pacientes suelen tener varias enfermedades a la vez. El motivo es la enfermedad aguda o la descompensación que causa la hospitalización actual (neumonía, falla cardíaca descompensada, HDA, exacerbación de EPOC...), no las crónicas estables de base (HTA, DM2, hipotiroidismo) aunque se repitan más en los documentos.',
  pediatria: 'Paciente pediátrico. IRA suele ser infección respiratoria aguda (no insuficiencia renal aguda) salvo que el contexto sea renal; EDA = enfermedad diarreica aguda; SDR = síndrome de dificultad respiratoria; RN = recién nacido. Las edades pueden venir en días o meses: no las conviertas. Los antecedentes perinatales (prematurez, bajo peso al nacer) son comorbilidad salvo que sean lo que motiva la atención.',
  gineco: 'Ginecología y obstetricia. G, P, C, A, V (gestaciones, partos, cesáreas, abortos, vivos), FUM, EG (edad gestacional) y FPP no son diagnósticos. En obstetricia el motivo es la condición que motiva la atención (preeclampsia, trabajo de parto pretérmino, amenaza de aborto, ruptura de membranas...); la cesárea o el parto son procedimientos y el diagnóstico es su indicación ("cesárea por preeclampsia severa" -> preeclampsia severa). La preeclampsia o la HTA gestacional no son la HTA crónica. En ginecología oncológica manda la patología confirmada.',
  ortopedia: 'Ortopedia y trauma. El diagnóstico es la lesión o enfermedad con su segmento y lateralidad (fractura de fémur izquierdo, luxación de hombro derecho), no el procedimiento (osteosíntesis, RAFI, reducción cerrada, artroplastia). Conserva la lateralidad (D / I) tal como está escrita. Fx = fractura; RAFI / RAFE = reducción abierta con fijación interna / externa; PTC / PTR = prótesis total de cadera / rodilla.',
  uci: 'Cuidados intensivos. El diagnóstico principal es la causa del ingreso a UCI (choque séptico de foco pulmonar, TCE grave, falla respiratoria por X), no las complicaciones que aparecen durante la estancia (neumonía asociada a ventilador, delirium, lesión renal aguda), que son consecuencia salvo que ahora sean la razón principal de seguir en UCI. VM = ventilación mecánica; NAV = neumonía asociada a ventilador; DVA = vasoactivos; TRRC = terapia de reemplazo renal continuo.',
  neurocx: 'Neurocirugía. El diagnóstico es la lesión (hematoma subdural, tumor cerebral, hidrocefalia, TCE, estenosis de canal), no el procedimiento (craneotomía, derivación ventrículo-peritoneal / DVP, drenaje). Glasgow y pupilas son hallazgos, no diagnósticos. HSD = hematoma subdural; HIC puede ser hemorragia intracerebral o hipertensión intracraneal según contexto; LCR = líquido cefalorraquídeo.',
  urologia: 'Urología. El motivo suele ser litiasis renal o ureteral, hiperplasia prostática (HBP), tumor de próstata, vejiga o riñón, estenosis uretral u obstrucción de la vía urinaria. La ERC, la infección urinaria o la hidronefrosis asociadas a una litiasis u obstrucción son consecuencia, no motivo; la sonda vesical, la nefrostomía y el catéter doble J son dispositivos, no diagnósticos. RTU-P = resección transuretral de próstata; CDJ = catéter doble J; NLP = nefrolitotomía percutánea; URS = ureteroscopia; LEOC = litotricia extracorpórea; APE / PSA = antígeno prostático. Tumor con PSA elevado y sin patología: "sospecha".',
  cxped: 'Cirugía pediátrica. El diagnóstico es la patología quirúrgica (apendicitis, hernia inguinal, invaginación, malformación), no la operación. IRA = infección respiratoria aguda salvo contexto renal. Las edades pueden venir en días o meses: no las conviertas.',
  plastica: 'Cirugía plástica y quemados. En quemados, un solo diagnóstico: agente, grado y superficie corporal quemada si están escritos ("quemadura de segundo grado 15 % SCQ"). Los procedimientos (injerto, desbridamiento, colgajo) no son el diagnóstico. SCQ / SCT = superficie corporal quemada / total.',
  cxvasc: 'Cirugía vascular. El diagnóstico es la enfermedad vascular (isquemia crítica de miembro inferior, aneurisma de aorta, enfermedad arterial periférica, insuficiencia venosa, TVP); DM2, HTA y tabaquismo son comorbilidades aunque se repitan. Conserva la lateralidad. EAP = enfermedad arterial periférica; ITB = índice tobillo-brazo. La amputación o la derivación son procedimientos, no diagnósticos.',
  cxtorax: 'Cirugía de tórax. El diagnóstico es la enfermedad pleural, pulmonar o mediastinal (empiema, neumotórax, derrame pleural, masa o nódulo pulmonar, tumor de mediastino). TQ = toracostomía (tubo de tórax); la videotoracoscopia y la lobectomía son procedimientos. La EPOC es comorbilidad. Una masa o nódulo sin patología es "sospecha".',
  cxonc: 'Cirugía oncológica. El diagnóstico es el tumor primario con su órgano y, si constan, histología y estadio (adenocarcinoma de colon). Un tumor sin patología es "sospecha". La quimioterapia o radioterapia previas son contexto, no diagnóstico. QT / RT = quimioterapia / radioterapia; mets = metástasis (consecuencia, salvo que la metástasis resecable sea el motivo de la cirugía).',
  orl: 'Otorrinolaringología. El diagnóstico es la patología (amigdalitis recurrente, sinusitis crónica, otitis media, hipoacusia, tumor de laringe, SAHOS), no el procedimiento (amigdalectomía, septoplastia, timpanoplastia, traqueostomía). SAHOS / AOS = apnea obstructiva del sueño.',
  oft: 'Oftalmología. Conserva el ojo afectado (OD = derecho, OI = izquierdo, AO = ambos). El diagnóstico es la enfermedad ocular (catarata, desprendimiento de retina, glaucoma, trauma ocular, retinopatía), no la cirugía (facoemulsificación, vitrectomía). AV = agudeza visual; PIO = presión intraocular.',
  anest: 'Anestesiología. Las valoraciones preanestésicas listan comorbilidades, ASA y vía aérea: eso no es el diagnóstico. El motivo es la enfermedad por la que se opera o el procedimiento que pide el servicio quirúrgico; si solo hay valoración de anestesia, busca el diagnóstico o procedimiento que figure como motivo de la cirugía. ASA I a V es una clasificación de riesgo, no un diagnóstico.',
  cardio: 'Cardiología. Aquí la cardiopatía que se sigue SÍ es el motivo (falla cardíaca, síndrome coronario agudo, fibrilación auricular, valvulopatía, miocardiopatía). HTA, DM2 y dislipidemia siguen siendo comorbilidad. IC / ICC = falla cardíaca; FEVI = fracción de eyección; SCA, IAMCEST, IAMSEST; FA; MCP = marcapasos; ICP = intervención coronaria percutánea; ECO TT = ecocardiograma transtorácico.',
  neuro: 'Neurología. El diagnóstico es la enfermedad neurológica que se sigue (ACV isquémico o hemorrágico, epilepsia, estado epiléptico, Guillain-Barré, esclerosis múltiple, meningitis). NIHSS y Glasgow son escalas, no diagnósticos. La FA o la HTA que causan un ACV son etiología o comorbilidad, no el motivo. PL = punción lumbar; EEG = electroencefalograma.',
  nefro: 'Nefrología. La enfermedad renal que se sigue SÍ es el motivo (ERC con su estadio, lesión renal aguda, glomerulopatía, síndrome nefrótico o nefrítico, trasplante renal, terapia de reemplazo renal). Aquí IRA suele ser insuficiencia renal aguda; LRA / AKI = lesión renal aguda. Conserva el estadio (G1 a G5, KDIGO) y la modalidad de reemplazo (HD hemodiálisis, DP diálisis peritoneal). La HTA y la DM2 son comorbilidad o etiología, salvo que la nefropatía diabética sea lo que se sigue.',
  gastro: 'Gastroenterología. El diagnóstico es la enfermedad digestiva o hepática (HDA, HDB, cirrosis, pancreatitis, enfermedad inflamatoria intestinal, hepatitis, colangitis). Si el ingreso es por una complicación de la cirrosis (ascitis, HDA variceal, peritonitis bacteriana espontánea, encefalopatía), escribe la complicación junto con la cirrosis de base ("HDA variceal por cirrosis"). EDA = endoscopia digestiva alta; CPRE; una endoscopia programada de rutina es "otro_proceso" salvo que sea el estudio del motivo.',
  neumo: 'Neumología. El diagnóstico es la enfermedad respiratoria seguida (EPOC exacerbada, neumonía, asma, enfermedad pulmonar intersticial, TEP, derrame pleural, bronquiectasias, nódulo o masa pulmonar sin patología = "sospecha"). IRA puede ser insuficiencia respiratoria aguda o infección respiratoria aguda: decide por el contexto. Oxígeno, VMNI, CPAP y cánula de alto flujo son soporte, no diagnósticos.',
  infecto: 'Infectología. El diagnóstico es la infección que se trata, con agente y foco si están escritos ("bacteriemia por S. aureus", "pielonefritis por E. coli BLEE"); el resultado de cultivo reemplaza al diagnóstico empírico previo. Los aislamientos son contexto. El VIH es el motivo si el ingreso es por VIH o sus oportunistas; si ingresa por otra cosa, es comorbilidad. ATB = antibiótico; BLEE; SAMR; TARV = antirretrovirales; CV = carga viral.',
  endo: 'Endocrinología. La enfermedad endocrina que se sigue SÍ es el motivo (DM2 descompensada, cetoacidosis diabética, hipotiroidismo, hipertiroidismo, tumor suprarrenal, hipopituitarismo). CAD = cetoacidosis diabética; EHH = estado hiperosmolar; HbA1c; TSH. La HTA y la dislipidemia siguen siendo comorbilidad.',
  reuma: 'Reumatología. El diagnóstico es la enfermedad autoinmune o reumática seguida (LES, artritis reumatoide, vasculitis, esclerosis sistémica, gota). Sus manifestaciones (nefritis lúpica, serositis) van con la enfermedad ("LES con nefritis lúpica"), no como comorbilidad aparte. LES = lupus eritematoso sistémico; AR = artritis reumatoide; FARME = fármacos modificadores de la enfermedad.',
  onco: 'Oncología. El diagnóstico es la neoplasia seguida, con órgano y, si constan, histología y estadio (adenocarcinoma de colon estadio IV). Las complicaciones del tratamiento (neutropenia febril, mucositis, anemia por quimioterapia) son consecuencia: si el ingreso es por ellas, van en el motivo de ingreso, no como diagnóstico principal. QT / RT = quimioterapia / radioterapia; C1D1 = ciclo 1 día 1; ECOG; mets = metástasis. Tumor sin patología es "sospecha".',
  hemato: 'Hematología. El diagnóstico es la enfermedad hematológica (leucemia aguda, linfoma, mieloma múltiple, anemia aplásica, PTI, hemofilia). Neutropenia, trombocitopenia o anemia son consecuencia cuando derivan de la enfermedad o del tratamiento; si la citopenia es lo que se estudia (pancitopenia en estudio), sí es el motivo, con "sospecha". TPH = trasplante de progenitores hematopoyéticos; BMO = biopsia de médula ósea; CMF = citometría de flujo.',
  psiq: 'Psiquiatría. El diagnóstico es el trastorno mental seguido (trastorno depresivo mayor, bipolar, esquizofrenia, psicosis, ansiedad, consumo de sustancias). TAB = trastorno afectivo bipolar; TDM = trastorno depresivo mayor; SPA = sustancias psicoactivas. El riesgo suicida o la agitación son estado clínico, no el diagnóstico; las enfermedades orgánicas acompañantes son comorbilidad.',
  derma: 'Dermatología. El diagnóstico es la dermatosis o la lesión en estudio (psoriasis, dermatitis atópica, carcinoma basocelular, melanoma, pénfigo, celulitis) con su localización si está escrita. Lesión con biopsia pendiente es "sospecha". CBC = carcinoma basocelular; CEC = carcinoma escamocelular.',
  geria: 'Geriatría. El motivo es el síndrome geriátrico o el evento agudo que genera la atención (delirium, caídas, deterioro funcional, neumonía, fractura, desnutrición), no la lista de enfermedades crónicas estables (HTA, DM2, demencia). La demencia es el motivo solo si es lo que se evalúa. Barthel, Lawton, MMSE y MoCA son escalas, no diagnósticos.',
  neonato: 'Neonatología. Paciente recién nacido: la edad viene en horas o días de vida, la edad gestacional en semanas y el peso al nacer. El diagnóstico es la patología neonatal (SDR, sepsis neonatal, hiperbilirrubinemia, asfixia perinatal); la prematurez y el bajo peso forman parte del diagnóstico cuando motivan el ingreso ("RN pretérmino de 32 semanas con SDR"). Los antecedentes maternos (preeclampsia, ruptura de membranas) son contexto, no diagnóstico del paciente. RNPT / RNT = pretérmino / término; AEG, PEG, GEG = adecuado, pequeño o grande para la edad gestacional; UCIN.',
  famil: 'Medicina familiar. Suele ser consulta ambulatoria (consulta_externa). El diagnóstico es el motivo de la consulta o del control de esa fecha; en un control de crónicos, la enfermedad crónica que se controla SÍ es el motivo y las demás son comorbilidad.',
};
const espHint = (k) => {
  const h = typeof k === 'string' && /^[a-z]{3,12}$/.test(k) && Object.prototype.hasOwnProperty.call(ESPH, k) ? ESPH[k] : '';
  if (!h || process.env.AI_ESP !== '1') return '';
  return '\n\nPISTA DEL SERVICIO. El paciente está en un servicio específico; esta pista solo afina cómo interpretas el texto. No cambia las reglas, el formato de salida ni la exigencia de citas literales; si choca con lo que dice el texto, manda el texto.\n' + h;
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
  const sysTxt = SYS_HC + espHint(new URL(req.url).searchParams.get('esp'));
  let body = docs.map((d, i) => '### DOC ' + (Number.isFinite(+d.i) ? +d.i : i) + ' | ' + String(d.t || '').slice(0, 120) + (d.s ? ' | ' + String(d.s).slice(0, 80) : '') + ' | ' + String(d.at || '').slice(0, 16) + '\n' + redact(String(d.x || '').slice(0, 4000))).join('\n\n');
  if (body.replace(/\s/g, '').length < 40) return J({ error: 'No hay texto que leer.' }, 400);
  if (body.length > MAX_DOCS_CHARS) body = body.slice(0, MAX_DOCS_CHARS);

  /* se anota el intento ANTES de llamar (si la llamada falla o se corta, igual cuenta) */
  ud.n += 1; ud.last = Date.now(); um2.n += 1;
  await store.setJSON('u_' + uid + '_' + dy, ud);
  await store.setJSON('u_' + uid + '_' + mo, um2);

  /* Modelo principal y, si se queda sin cuota (429), falla o se pasa de tiempo, un modelo de respaldo. Netlify corta a los 10 s:
     el principal tiene 6 s y el respaldo solo se intenta si quedan al menos 2,5 s. */
  const t0 = Date.now();
  const models = [MODEL()]; if (MODEL2() && MODEL2() !== models[0]) models.push(MODEL2());
  const mkGen = (model) => {
    const gen = { maxOutputTokens: MAX_OUT * 2, temperature: 0.1, responseMimeType: 'application/json' };
    if (/2\.5/.test(model)) gen.thinkingConfig = { thinkingBudget: 0 };
    else gen.thinkingConfig = { thinkingLevel: String(process.env.AI_THINK || 'minimal').toLowerCase() };
    return gen;
  };
  const call = async (model, cfg, ms) => {
    const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/' + encodeURIComponent(model) + ':generateContent', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-goog-api-key': process.env.GEMINI_API_KEY },
      body: JSON.stringify({ systemInstruction: { parts: [{ text: sysTxt }] }, contents: [{ role: 'user', parts: [{ text: body }] }], generationConfig: cfg }),
      signal: AbortSignal.timeout(ms),
    });
    const tx = await r.text(); let j = null; try { j = JSON.parse(tx); } catch (e) {}
    return { r, j };
  };
  const readOut = (res) => {
    const out = ((res.j && res.j.candidates && res.j.candidates[0] && res.j.candidates[0].content && res.j.candidates[0].content.parts) || []).map((p) => p.text || '').join('').trim();
    const mm = /\{[\s\S]*\}/.exec(out);
    try { const d = JSON.parse(mm ? mm[0] : out); return d && typeof d === 'object' ? d : null; } catch (e) { return null; }
  };
  let res = null, fail = '', data = null, used = '', tin = 0, tout = 0, usd = 0;
  for (let k = 0; k < models.length; k++) {
    const left_ms = (k === 0 ? 6000 : 9000 - (Date.now() - t0));
    if (k > 0 && left_ms < 2500) break;
    const model = models[k]; fail = ''; res = null; data = null;
    try {
      res = await call(model, mkGen(model), Math.min(left_ms, 6500));
      if (!res.r.ok && res.r.status === 400) { const g2 = mkGen(model); delete g2.thinkingConfig; res = await call(model, g2, Math.max(1500, Math.min(9000 - (Date.now() - t0), 6500))); }
    } catch (e) { fail = (e && (e.name === 'TimeoutError' || e.name === 'AbortError')) ? 'La IA tardó demasiado.' : 'No pude conectar con la IA.'; }
    if (!fail && !res.r.ok) fail = 'La IA no respondió (' + res.r.status + ').';
    const um3 = (res && res.j && res.j.usageMetadata) || {};
    const tin1 = um3.promptTokenCount || Math.ceil(body.length / 3), tout1 = (um3.candidatesTokenCount || 0) + (um3.thoughtsTokenCount || 0);
    if (res && (!fail || um3.promptTokenCount)) { tin += tin1; tout += tout1; usd += (tin1 * PIN(model) + (tout1 || (fail ? 0 : MAX_OUT)) * POUT(model)) / 1e6; }
    if (!fail) { data = readOut(res); if (!data) fail = 'La IA no devolvió un resultado legible.'; }
    if (!fail) { used = model; break; }
  }
  if (!fail && data) {
    /* los modelos a veces escriben "cite" o "citation" en vez de "cita": se normaliza para que la cita se pueda verificar */
    ['diagnostico_actual', 'motivo_ingreso_actual', 'egreso'].forEach((k) => {
      const o = data[k]; if (o && typeof o === 'object' && (o.cita === undefined || o.cita === null)) { const alt = o.cite || o.citation || o.cita_textual; if (typeof alt === 'string') o.cita = alt; }
    });
    delete data.candidatos;
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
  return J({ data, model: used, left: { day: Math.max(0, DAY_MAX() - ud.n), month: Math.max(0, MONTH_MAX() - um2.n) } });
};

export const config = { path: '/api/ai' };
