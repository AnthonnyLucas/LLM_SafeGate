"""Orquestrador: checa a ENTRADA (injection + PII) e a SAIDA (vazamento de prompt, PII)."""
from __future__ import annotations
import re
from dataclasses import dataclass, field

from . import injection, pii
from .textnorm import canon


@dataclass
class Decision:
    action: str                       # allow | review | block
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    sanitized: str = ""               # texto com PII mascarado (use este, nao o original)
    pii: list[str] = field(default_factory=list)


class Guard:
    def __init__(self, canary: str | None = None, system_prompt: str | None = None):
        self.canary = canary
        self.system_prompt = system_prompt

    def check_input(self, text: str) -> Decision:
        if text is None or not text.strip():
            raise ValueError("Texto vazio")
        inj = injection.detect(text)
        clean, found = pii.redact(text)
        return Decision(inj.action, inj.score, inj.reasons, clean, sorted({f.kind for f in found}))

    def check_output(self, text: str) -> Decision:
        reasons, action = [], "allow"
        if self.canary and self.canary in text:
            reasons.append("canary_vazado"); action = "block"
        if self.system_prompt and self._shingle_leak(text):
            reasons.append("prompt_do_sistema_vazado"); action = "block"
        clean, found = pii.redact(text)
        if found:
            reasons.append("pii_na_saida")
        return Decision(action, 1.0 if action == "block" else 0.0, reasons, clean, sorted({f.kind for f in found}))

    def _shingle_leak(self, text: str, n: int = 6) -> bool:
        sp = re.findall(r"\w+", canon(self.system_prompt or ""))
        out = " ".join(re.findall(r"\w+", canon(text)))
        return any(" ".join(sp[i:i + n]) in out for i in range(max(0, len(sp) - n + 1)))
