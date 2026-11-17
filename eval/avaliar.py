"""Avalia o guard em dois conjuntos de injection (dev e held-out) e em deteccao de PII.

dev      : usado enquanto as regras foram escritas (otimista por construcao)
heldout  : escrito DEPOIS, com outras formulacoes, e rodado uma unica vez sem ajustar regras
Metricas : recall_bloqueio, recall_alerta (bloqueio ou revisao), FPR_bloqueio, FPR_alerta, latencia.
"""
from __future__ import annotations
import json
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / "src"))

from llmguard import pii
from llmguard.guard import Guard

NAIVE_PHRASES = ("ignore previous instructions", "ignore todas as instrucoes anteriores",
                 "ignore as instrucoes anteriores", "ignore all previous instructions")


def naive_block(text: str) -> str:
    """Filtro ingenuo tipico: so procura 2 ou 3 frases exatas."""
    t = text.lower().replace("ç", "c").replace("õ", "o").replace("ã", "a")
    return "block" if any(p in t for p in NAIVE_PHRASES) else "allow"


def _rates(actions_att: list[str], actions_ben: list[str]) -> dict:
    n_a, n_b = len(actions_att), len(actions_ben)
    return {
        "n_ataques": n_a, "n_benignos": n_b,
        "recall_bloqueio": round(sum(a == "block" for a in actions_att) / n_a, 3),
        "recall_alerta": round(sum(a in ("block", "review") for a in actions_att) / n_a, 3),
        "fpr_bloqueio": round(sum(a == "block" for a in actions_ben) / n_b, 3),
        "fpr_alerta": round(sum(a in ("block", "review") for a in actions_ben) / n_b, 3),
    }


def avaliar_injection(path: Path, verbose: bool = False) -> dict | None:
    if not path.exists():
        return None
    d = json.loads(path.read_text(encoding="utf-8"))
    g = Guard()
    t0 = time.perf_counter()
    att = [g.check_input(t) for t in d["ataques"]]
    ben = [g.check_input(t) for t in d["benignos"]]
    ms = (time.perf_counter() - t0) / (len(att) + len(ben)) * 1000
    res = _rates([x.action for x in att], [x.action for x in ben])
    res["latencia_ms_por_texto"] = round(ms, 3)
    res["baseline_ingenuo"] = _rates([naive_block(t) for t in d["ataques"]], [naive_block(t) for t in d["benignos"]])
    res["ataques_nao_bloqueados"] = [t for t, x in zip(d["ataques"], att) if x.action != "block"]
    res["benignos_bloqueados_ou_marcados"] = [(t, x.action, x.reasons) for t, x in zip(d["benignos"], ben) if x.action != "allow"]
    return res


def avaliar_pii(path: Path) -> dict:
    cases = json.loads(path.read_text(encoding="utf-8"))
    tp = fp = fn = 0
    erros = []
    for c in cases:
        got = {f.kind for f in pii.find_pii(c["texto"])}
        exp = set(c["esperado"])
        tp += len(got & exp); fp += len(got - exp); fn += len(exp - got)
        if got != exp:
            erros.append({"texto": c["texto"], "esperado": sorted(exp), "obtido": sorted(got)})
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return {"n_textos": len(cases), "precisao": round(p, 3), "recall": round(r, 3), "erros": erros}


def avaliar(verbose: bool = True) -> dict:
    out = {"dev": avaliar_injection(BASE / "data" / "dev.json"),
           "heldout": avaliar_injection(BASE / "data" / "heldout.json"),
           "pii": avaliar_pii(BASE / "data" / "pii.json")}
    if verbose:
        for nome in ("dev", "heldout"):
            r = out[nome]
            if not r:
                continue
            b = r["baseline_ingenuo"]
            print(f"\n== injection / {nome}  ({r['n_ataques']} ataques, {r['n_benignos']} benignos)")
            print(f"{'':<18}{'recall bloq.':>14}{'recall alerta':>15}{'FPR bloq.':>11}{'FPR alerta':>12}")
            print(f"{'guard':<18}{r['recall_bloqueio']:>14.3f}{r['recall_alerta']:>15.3f}{r['fpr_bloqueio']:>11.3f}{r['fpr_alerta']:>12.3f}")
            print(f"{'filtro ingenuo':<18}{b['recall_bloqueio']:>14.3f}{b['recall_alerta']:>15.3f}{b['fpr_bloqueio']:>11.3f}{b['fpr_alerta']:>12.3f}")
            print(f"latencia: {r['latencia_ms_por_texto']} ms/texto")
            for t in r["ataques_nao_bloqueados"]:
                print("   ataque NAO bloqueado:", t[:90])
            for t, a, why in r["benignos_bloqueados_ou_marcados"]:
                print(f"   benigno {a}: {t[:70]} {why}")
        p = out["pii"]
        print(f"\n== PII ({p['n_textos']} textos): precisao={p['precisao']} recall={p['recall']}")
        for e in p["erros"]:
            print("   erro PII:", e)
    return out


if __name__ == "__main__":
    avaliar()
