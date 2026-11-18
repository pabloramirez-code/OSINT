"""Compara los subdominios de un informe de reconmap con los de otra herramienta.

La otra herramienta se lee como texto plano, un nombre por línea (p. ej. la salida de
`amass enum -passive -o fichero`), para no depender de su formato propio.
"""

from dataclasses import dataclass

from reconmap.normalize import InvalidDomainError, normalize_domain
from reconmap.scope import in_scope


@dataclass(frozen=True)
class Comparison:
    target: str
    tool: str
    only_reconmap: list[str]
    only_other: list[str]
    both: list[str]

    def to_markdown(self) -> str:
        def section(title: str, names: list[str]) -> str:
            body = "\n".join(f"- `{name}`" for name in names) or "_(ninguno)_"
            return f"### {title} ({len(names)})\n\n{body}\n"

        return "\n".join(
            [
                f"## {self.target}: reconmap frente a {self.tool}\n",
                f"| | Subdominios |\n|---|---|\n| Solo reconmap | {len(self.only_reconmap)} |\n"
                f"| Solo {self.tool} | {len(self.only_other)} |\n| En ambas | {len(self.both)} |\n",
                section("Solo en reconmap", self.only_reconmap),
                section(f"Solo en {self.tool}", self.only_other),
                section("En ambas", self.both),
            ]
        )


def subdomains_from_report(report: dict[str, object]) -> tuple[str, set[str]]:
    scan = report.get("scan")
    target = str(scan.get("target", "")) if isinstance(scan, dict) else ""
    entities = report.get("entities")
    names = {
        str(e["value"])
        for e in (entities if isinstance(entities, list) else [])
        if isinstance(e, dict) and e.get("type") == "subdomain"
    }
    return target, names


def subdomains_from_text(text: str, target: str) -> set[str]:
    names = set()
    for line in text.splitlines():
        raw = line.strip().split()[0] if line.strip() else ""
        try:
            name = normalize_domain(raw).name
        except InvalidDomainError:
            continue
        if name != target and in_scope(name, target):
            names.add(name)
    return names


def compare(report: dict[str, object], other_text: str, tool: str) -> Comparison:
    target, ours = subdomains_from_report(report)
    theirs = subdomains_from_text(other_text, target)
    return Comparison(
        target=target,
        tool=tool,
        only_reconmap=sorted(ours - theirs),
        only_other=sorted(theirs - ours),
        both=sorted(ours & theirs),
    )
