"""Deteccao de prompt injection por regras ponderadas (offline, explicavel).

Cada regra tem um peso. Soma >= 1.0 bloqueia, >= 0.5 marca para revisao. Regras fracas (0.4-0.6)
sozinhas nao bloqueiam: precisam de reforco, o que reduz falso positivo em perguntas legitimas.
Limitacao assumida: regras sao um filtro de primeira linha, nao uma defesa completa.
"""
from __future__ import annotations
import re
from dataclasses import dataclass

from .textnorm import canon, decode_base64_chunks

BLOCK_AT, REVIEW_AT = 1.0, 0.5
_AI = r"(?:ia|ai|assistente|voce|you|modelo|bot|chatbot|agora|now)"
_NEG = r"(?:sem|without|no|nenhum\w*|nao tem|nao possui|dont have|do not have)"
_VERB_REV = r"(?:revel\w*|mostr\w*|exib\w*|repit\w*|copi\w*|imprim\w*|print|show|reveal|repeat|display|dump|leak|diga|qual)"

RULES: list[tuple[str, float, str]] = [
    ("ignorar_instrucoes", 1.0,
     r"\b(?:ignor\w*|desconsider\w*|esquec\w*|descart\w*|disregard|forget|override|bypass)\b.{0,40}"
     r"\b(?:instruc\w*|regras?|diretrizes|politicas?|restricoes|filtros?|protecoes|prompt|rules|instructions|"
     r"guidelines|polic\w+|safeguards?|everything|tudo)\b"),
    ("nao_siga_regras", 1.0,
     r"\b(?:nao|never|stop)\b.{0,15}\b(?:siga\w*|obede\w*|follow\w*)\b.{0,40}\b(?:regras?|instruc\w*|politicas?|rules|instructions)\b"),
    ("revelar_prompt", 1.0,
     _VERB_REV + r"\b.{0,40}\b(?:system prompt|prompt (?:de|do) sistema|prompt inicial|seu prompt|your prompt|"
     r"suas? instruc\w*|your instructions|instrucoes (?:internas|do sistema|iniciais|originais))\b"),
    ("repetir_texto_acima", 1.0,
     r"\b(?:repit\w*|repeat|print|imprim\w*|copi\w*)\b.{0,30}\b(?:texto acima|text above|everything above|above this line|"
     r"acima desta linha|from the beginning|desde o inicio)\b"),
    ("persona_agora", 0.6, r"\b(?:voce agora e|you are now|a partir de agora voce|from now on you)\b"),
    ("dan", 0.6, r"\b(?:dan|do anything now)\b"),
    ("sem_restricoes_ia", 1.0,
     _AI + r"\b.{0,30}\b" + _NEG + r"\b.{0,15}\b(?:restricoes|filtros?|regras?|limites|censura|restrictions|filters|rules|limits|content policy)\b"),
    ("irrestrito", 0.8, r"\b(?:unrestricted|uncensored|sem censura|sem limites)\b"),
    ("modo_especial", 0.6, r"\bmodo (?:sem|livre|irrestrito|deus|god|desenvolvedor|developer|dev|jailbreak)\b"),
    ("desativar_protecoes", 1.0,
     r"\b(?:desativ\w*|desabilit\w*|disable|turn off|remova|remove)\b.{0,25}\b(?:protecoes|filtros?|seguranca|safety|safeguards?|guardrails|restricoes)\b"),
    ("delimitadores_de_papel", 1.0,
     r"<\|im_(?:start|end)\|>|\[/?inst\]|<<sys>>|###\s*(?:system|instruction|instrucao|sistema)|^\s*system\s*:"),
    ("novas_instrucoes", 0.7, r"\b(?:novas? instruc\w*|new instructions?|updated instructions?)\s*:"),
    ("responder_qualquer_coisa", 0.5, r"\b(?:answer|responda|reply)\b.{0,15}\b(?:anything|qualquer coisa|everything)\b"),
    ("sem_recusar", 0.5, r"\b(?:without refusing|sem recusar)\b"),
    ("roleplay", 0.4, r"\b(?:finja|pretend|simule|roleplay|rpg|act as|atue como|aja como|behave as)\b"),
    ("jailbreak", 0.6, r"\bjailbreak\b"),
    ("como_se_nao_houvesse", 1.0,
     r"como se nao (?:houvesse|existisse|tivesse)\b.{0,20}\b(?:regras?|politicas?|restricoes|limites)\b"),
    ("ignorar_o_dito", 0.8,
     r"\b(?:ignor\w*|esquec\w*|forget)\b.{0,10}\b(?:o que foi dito|tudo que (?:foi|voce) (?:dito|disse)|what (?:was|i) said)\b"),
    ("obedeca_apenas", 0.6, r"\b(?:obede\w+|obey)\b.{0,20}\b(?:apenas|somente|only)\b"),
    ("alegacao_de_autoridade", 0.5,
     r"\b(?:sou|i am|im|eu sou)\b.{0,20}\b(?:administrador|admin|desenvolvedor|developer|gerente|dono|owner)\b"),
]
_COMPILED = [(n, w, re.compile(p, re.S)) for n, w, p in RULES]


@dataclass
class InjectionResult:
    action: str          # allow | review | block
    score: float
    reasons: list[str]


def _score(text: str) -> tuple[float, list[str]]:
    c = canon(text)
    hits = [(n, w) for n, w, rx in _COMPILED if rx.search(c)]
    return sum(w for _, w in hits), [n for n, _ in hits]


def detect(text: str) -> InjectionResult:
    score, reasons = _score(text)
    for dec in decode_base64_chunks(text):          # payload escondido em base64
        s2, r2 = _score(dec)
        if r2:
            score += s2 + 0.5
            reasons += [f"base64:{n}" for n in r2]
    action = "block" if score >= BLOCK_AT else "review" if score >= REVIEW_AT else "allow"
    return InjectionResult(action, round(score, 2), reasons)
