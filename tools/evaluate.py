#!/usr/bin/env python3
"""Measure the analyzer on public datasets (see data/README.md). Standard library only.

    cd backend && make scorer && cd ..
    python3 tools/evaluate.py

Reads data/smishtank.csv (all phishing texts) and data/spaphish.csv (labeled phishing/legit emails).
"""
import csv, json, subprocess, sys, os
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCORER = os.path.join(ROOT, 'backend', 'build', 'scorer')
MEDIUM, HIGH = 25, 55

csv.field_size_limit(sys.maxsize)

def score(texts):
    payload = ''.join(json.dumps(t.replace('\r', ''), ensure_ascii=False)[1:-1] + '\n' for t in texts)
    out = subprocess.run([SCORER], input=payload, capture_output=True, text=True, check=True).stdout
    rows = out.rstrip('\n').split('\n')
    return [(int(r.split('\t')[0]), r.split('\t')[1].split(',') if r.split('\t')[1] else []) for r in rows]

def read(path, encoding):
    with open(path, newline='', encoding=encoding) as f:
        return list(csv.DictReader(f))

def pct(n, d):
    return '%.1f%%' % (100.0 * n / d) if d else 'n/a'

def smishtank():
    path = os.path.join(ROOT, 'data', 'smishtank.csv')
    if not os.path.exists(path):
        return print('skip: data/smishtank.csv not found')
    rows = read(path, 'latin-1')
    texts = [(r.get('MainText') or r.get('Fulltext') or '') for r in rows]
    res = score(texts)
    n = len(rows)
    print('SMISHTANK: %d real phishing texts (higher is better)' % n)
    print('  flagged medium or higher: %s   flagged high: %s   no warning at all: %s' % (
        pct(sum(s >= MEDIUM for s, _ in res), n), pct(sum(s >= HIGH for s, _ in res), n),
        pct(sum(s == 0 for s, _ in res), n)))
    cats = defaultdict(list)
    for r, (s, _) in zip(rows, res):
        cats[r.get('Message Categories') or 'Unknown'].append(s)
    for cat, ss in sorted(cats.items(), key=lambda kv: -len(kv[1]))[:8]:
        print('    %-28s n=%-4d medium+ %s' % (cat, len(ss), pct(sum(s >= MEDIUM for s in ss), len(ss))))

def spaphish():
    path = os.path.join(ROOT, 'data', 'spaphish.csv')
    if not os.path.exists(path):
        return print('skip: data/spaphish.csv not found')
    rows = read(path, 'utf-8')
    texts = [(r.get('subject') or '') + '\n' + (r.get('body') or '') for r in rows]
    res = score(texts)
    phish = [s for r, (s, _) in zip(rows, res) if r['Label'] == '1']
    legit = [s for r, (s, _) in zip(rows, res) if r['Label'] == '0']
    print('SPAPHISH: %d phishing and %d legitimate Spanish emails' % (len(phish), len(legit)))
    for name, th in (('medium', MEDIUM), ('high', HIGH)):
        print('  at %-6s (>=%d): catches %s of phishing, wrongly flags %s of legitimate' % (
            name, th, pct(sum(s >= th for s in phish), len(phish)), pct(sum(s >= th for s in legit), len(legit))))

if __name__ == '__main__':
    if not os.path.exists(SCORER):
        sys.exit('Build the scorer first: cd backend && make scorer')
    smishtank()
    print()
    spaphish()
