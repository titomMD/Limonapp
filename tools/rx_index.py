#!/usr/bin/env python3
"""Regenera public/vendor/rx/index.json a partir de public/vendor/rx/d/*.json
y valida cada ficha contra tax.json y el catálogo de especialidades de index.html.

Uso (desde la raíz del repo):  python3 tools/rx_index.py
Las fichas se editan a mano en d/<id>.json; este script solo construye el índice liviano.
Falla (exit 1) si una ficha usa una clave que no existe en tax.json."""
import json, os, re, sys, datetime
R = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
RX = os.path.join(R, 'public', 'vendor', 'rx')
tax = json.load(open(os.path.join(RX, 'tax.json'), encoding='utf-8'))
html = open(os.path.join(R, 'public', 'index.html'), encoding='utf-8').read()
blk = html[html.index('var ESP=['):]
blk = blk[:blk.index('];')]
ESP = set(re.findall(r"^\s*\['([a-z]+)'", blk, re.M))
err = []
items = []
for fn in sorted(os.listdir(os.path.join(RX, 'd'))):
    if not fn.endswith('.json'): continue
    d = json.load(open(os.path.join(RX, 'd', fn), encoding='utf-8'))
    i = d.get('id')
    if i + '.json' != fn: err.append((fn, 'id no coincide con el nombre'))
    for k in ('n', 'g', 'atc', 'cl', 'mc', 'us', 'es', 'via', 'al', 'mech', 'ind', 'v', 'src', 'rev'):
        if k not in d: err.append((i, 'falta ' + k))
    if d.get('mc') not in tax['MC']: err.append((i, 'mc ' + str(d.get('mc'))))
    for u in d.get('us', []):
        if u not in tax['US']: err.append((i, 'us ' + u))
    for u in d.get('via', []):
        if u not in tax['VIA']: err.append((i, 'via ' + u))
    for u in d.get('al', []):
        if u not in tax['AL']: err.append((i, 'al ' + u))
    for u in d.get('es', []):
        if u not in ESP: err.append((i, 'es ' + u))
    for c in d.get('atc', []):
        for p in (c[:1], c[:3], c[:4], c[:5]):
            if p not in tax['ATC']: err.append((i, 'atc ' + p))
    v = d.get('v', {})
    for b in ('d', 'f', 's'):
        if v.get(b) not in (0, 1, 2): err.append((i, 'v.' + b))
    if any(v.get(b, 0) >= 1 for b in 'dfs') and not d.get('src'): err.append((i, 'verificada sin fuentes'))
    for s in d.get('src', []):
        if not (s.get('t') and str(s.get('u', '')).startswith('https://')): err.append((i, 'fuente mal formada'))
    for x in d.get('ind', []):
        if not x.get('i'): err.append((i, 'indicación sin título'))
    items.append({'id': i, 'n': d['n'], 'g': d['g'], 'atc': d['atc'][0], 'cl': d['cl'], 'mc': d['mc'], 'us': d['us'], 'es': d['es'], 'via': d['via'], 'al': d['al'], 'v': d['v']})
if err:
    for e in err: print('ERROR', *e)
    sys.exit(1)
items.sort(key=lambda x: x['id'])
old = os.path.join(RX, 'index.json')
ver = 1
try:
    ver = int(json.load(open(old, encoding='utf-8'))['version'].split('-')[1]) + 1
except Exception: pass
json.dump({'version': 'v63-%d' % ver, 'fecha': datetime.date.today().isoformat(), 'items': items}, open(old, 'w', encoding='utf-8'), ensure_ascii=False, separators=(',', ':'))
print(len(items), 'fichas OK; índice v63-%d' % ver)
