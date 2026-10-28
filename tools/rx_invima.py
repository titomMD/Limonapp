#!/usr/bin/env python3
"""Actualiza el bloque `co` (disponibilidad en Colombia) de cada ficha del recetario
con el Codigo Unico de Medicamentos (CUM) vigentes del INVIMA, via la API abierta de datos.gov.co:
  https://www.datos.gov.co/resource/i7cb-raxc.json   (dataset i7cb-raxc, licencia CC BY-SA 4.0)

Uso (desde la raiz del repo):   python3 tools/rx_invima.py        # reescribe co en public/vendor/rx/d/*.json
                                 python3 tools/rx_invima.py --ver   # solo muestra el resumen, sin escribir
Luego:                           python3 tools/rx_index.py          # valida

Busca por codigo ATC de la ficha (CO_ATC corrige los que INVIMA clasifica distinto) y solo cuenta
presentaciones con registro Vigente y CUM Activo. Un registro vigente NO garantiza que se venda hoy."""
import json, os, re, subprocess, sys, urllib.parse, datetime, collections
R = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
D = os.path.join(R, 'public', 'vendor', 'rx', 'd')
API = 'https://www.datos.gov.co/resource/i7cb-raxc.json'
CO_ATC = {  # codigos con los que INVIMA clasifica distinto
    'cloruro-de-potasio': ['B05XA01', 'A12BA01'],
    'sulfato-de-magnesio': ['B05XA05', 'A06AD04', 'A12CC02'],
    'sales-rehidratacion-oral': ['A07CA99'],
}
NOTAS = {
    'desmopresina': 'No hay tableta oral de 0,1 o 0,2 mg registrada: solo ampolla, spray nasal, gotas sublinguales y liofilizado oral (Minirin Melt 120 µg). La dosis de enuresis de esta ficha corresponde a la tableta; confirmar con el servicio qué presentación se usa.',
    'citrato-de-potasio': 'Solo una presentación registrada: tableta de liberación prolongada de 10 mEq (Urocit-K).',
}
FIELDS = 'expediente,consecutivocum,producto,titular,registrosanitario,formafarmaceutica,cantidad,unidadmedida,unidadreferencia,atc'

def get(url):
    r = subprocess.run(['curl', '-s', '-m', '120', url], capture_output=True, text=True)
    return json.loads(r.stdout)

def fecha_datos():
    d = get('https://www.datos.gov.co/api/views/i7cb-raxc.json')
    return datetime.datetime.fromtimestamp(d['rowsUpdatedAt'], datetime.timezone.utc).strftime('%Y-%m-%d')

def mu(s):
    return s.replace('æg', 'µg').replace('μg', 'µg')

def nombre(s):
    s = re.sub(r'\s+', ' ', s).strip()
    return s.capitalize() if s.isupper() else s

def titular(s):
    s = re.sub(r'\b(S\.?A\.?S\.?|S\.?A\.?|LTDA\.?|LIMITED|LTD\.?|S\.?R\.?L\.?|INC\.?|LLC|GMBH)\b\.?', '', s, flags=re.I)
    return re.sub(r'\s+', ' ', s).strip(' .,').title()

def num(c):
    try:
        x = float(c)
        return ('%g' % x).replace('.', ',')
    except Exception:
        return str(c)

def main():
    solo_ver = '--ver' in sys.argv
    f = fecha_datos()
    for fn in sorted(os.listdir(D)):
        p = os.path.join(D, fn)
        d = json.load(open(p, encoding='utf-8'))
        codes = CO_ATC.get(d['id'], d['atc'])
        lst = ','.join("'%s'" % c for c in codes)
        where = "atc in(%s) AND estadoregistro='Vigente' AND estadocum='Activo'" % lst
        rows = get(API + '?' + urllib.parse.urlencode({'$where': where, '$select': FIELDS, '$limit': '50000'}))
        if not isinstance(rows, list):
            print('ERROR', d['id'], rows); continue
        regs = {r['registrosanitario'] for r in rows}
        pres_n = {(r['expediente'], r['consecutivocum']) for r in rows}
        forms = collections.Counter()
        for r in rows:
            forms[(r['formafarmaceutica'].strip().lower().capitalize(), num(r.get('cantidad', '')), r.get('unidadmedida', ''))] += 1
        formas = [mu('%s %s %s' % k) for k, _ in forms.most_common(14)]
        prods = collections.OrderedDict()
        cnt = collections.Counter()
        for r in rows:
            k = r['producto'].upper().strip()
            prods.setdefault(k, (nombre(r['producto']), titular(r['titular'])))
            cnt[k] += 1
        orden = [k for k, _ in cnt.most_common()]
        prods = collections.OrderedDict((k, prods[k]) for k in orden)
        marcas = [v for k, v in prods.items() if '®' in k]
        otros = [v for k, v in prods.items() if '®' not in k]
        lista = (marcas + otros)
        m = ['%s (%s)' % v for v in lista[:12]]
        co = {'f': 'Código Único de Medicamentos vigentes (INVIMA, datos.gov.co, dataset i7cb-raxc), actualizado el %s' % f,
              'n': len(regs), 'np': len(pres_n), 'pres': formas, 'm': m, 'mas': max(0, len(lista) - 12),
              'nota': NOTAS.get(d['id'], '') + (' ' if d['id'] in NOTAS else '') + 'Un registro vigente no garantiza que el producto se esté vendiendo hoy.'}
        if not rows:
            co['nota'] = 'No hay presentaciones activas con ese código ATC en el CUM; confirmar en la consulta en línea del INVIMA. ' + co['nota']
        print('%-26s registros=%-3d presentaciones=%-5d marcas=%d' % (d['id'], co['n'], co['np'], len(lista)))
        if not solo_ver:
            d['co'] = co
            json.dump(d, open(p, 'w', encoding='utf-8'), ensure_ascii=False, separators=(',', ':'))
main()
