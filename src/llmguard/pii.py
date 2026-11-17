"""Deteccao e mascaramento de dados pessoais (Brasil) COM validacao de digitos verificadores.

Validar o checksum evita falso positivo: um numero de pedido de 11 digitos nao vira 'CPF'.
"""
from __future__ import annotations
import re
from dataclasses import dataclass

_CPF = re.compile(r"(?<!\d)\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?!\d)")
_CNPJ = re.compile(r"(?<!\d)\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}(?!\d)")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"(?<!\d)(?:\+?55[\s-]?)?\(?\d{2}\)?[\s-]?9\d{4}[\s-]?\d{4}(?!\d)")
LABELS = {"cpf": "[CPF]", "cnpj": "[CNPJ]", "cartao": "[CARTAO]", "email": "[EMAIL]", "telefone": "[TELEFONE]"}


def _digits(s: str) -> list[int]:
    return [int(c) for c in s if c.isdigit()]


def cpf_ok(s: str) -> bool:
    d = _digits(s)
    if len(d) != 11 or len(set(d)) == 1:
        return False
    for n in (9, 10):
        r = sum(d[i] * (n + 1 - i) for i in range(n)) * 10 % 11 % 10
        if r != d[n]:
            return False
    return True


def cnpj_ok(s: str) -> bool:
    d = _digits(s)
    if len(d) != 14 or len(set(d)) == 1:
        return False
    w1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    w2 = [6] + w1
    for w, pos in ((w1, 12), (w2, 13)):
        r = sum(a * b for a, b in zip(d[:pos], w)) % 11
        if (0 if r < 2 else 11 - r) != d[pos]:
            return False
    return True


def luhn_ok(s: str) -> bool:
    d = _digits(s)
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, x in enumerate(reversed(d)):
        if i % 2:
            x *= 2
            x -= 9 if x > 9 else 0
        total += x
    return total % 10 == 0


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int


def find_pii(text: str) -> list[Finding]:
    found: list[Finding] = []

    def free(a: int, b: int) -> bool:
        return all(b <= f.start or a >= f.end for f in found)

    for kind, rx, ok in (("cpf", _CPF, cpf_ok), ("cnpj", _CNPJ, cnpj_ok), ("cartao", _CARD, luhn_ok),
                         ("email", _EMAIL, lambda _: True), ("telefone", _PHONE, lambda _: True)):
        for m in rx.finditer(text):
            if ok(m.group(0)) and free(m.start(), m.end()):
                found.append(Finding(kind, m.start(), m.end()))
    return sorted(found, key=lambda f: f.start)


def redact(text: str) -> tuple[str, list[Finding]]:
    fs = find_pii(text)
    out, pos = [], 0
    for f in fs:
        out.append(text[pos:f.start])
        out.append(LABELS[f.kind])
        pos = f.end
    out.append(text[pos:])
    return "".join(out), fs
