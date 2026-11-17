"""Normalizacao anti-ofuscacao: acentos, leetspeak, caracteres invisiveis e letras espacadas."""
from __future__ import annotations
import base64
import re
import unicodedata

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)
_SPACED = re.compile(r"(?<![a-z])((?:[a-z][\s\.\-_*]+){3,}[a-z])(?![a-z])")
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def canon(text: str) -> str:
    """Forma canonica para casar regras: minusculas, sem acento, sem leet, sem letras espacadas."""
    t = unicodedata.normalize("NFKD", text).translate(_ZERO_WIDTH)
    t = "".join(c for c in t if not unicodedata.combining(c)).lower().translate(_LEET)
    t = _SPACED.sub(lambda m: re.sub(r"[\s\.\-_*]+", "", m.group(1)), t)
    return re.sub(r"\s+", " ", t).strip()


def decode_base64_chunks(text: str) -> list[str]:
    """Trechos base64 que decodificam para texto legivel (payloads escondidos)."""
    out = []
    for m in _B64.finditer(text):
        s = m.group(0)
        s += "=" * (-len(s) % 4)
        try:
            d = base64.b64decode(s, validate=True).decode("utf-8")
        except Exception:
            continue
        if len(d) >= 8 and all(c.isprintable() or c in "\n\t" for c in d):
            out.append(d)
    return out
