"""Which host names are one machine, how sure that is, and what to call it.

`propose(state)` reads a case's fold (see host_identity) and groups the host
names its evidence gave into proposed machines:

- **certain**: names one artifact gives together (one SYSTEM hive's
  ComputerName, Tcpip Hostname and Hostname.Domain), and spelling-equal names
  with artifact evidence on both sides;
- **proposed**: a unit's own names that are close to each other (equal once a
  DNS suffix, a collection or date token, a Velociraptor wrapper or NetBIOS
  truncation is set aside; never by edit distance), equal short names with
  compatible domains across units, and units that share a machine id;
- **flagged**: names never grouped (generic or default names, values that
  aren't host names, unusual characters, near spellings) and groups the
  examiner should look at (conflicting domains, a unit whose folder name
  matches none of its own names, thin evidence, one id under two names, not
  on the host list).

Names from forwarded event logs and per-row host columns are their own
machines, never the collector's. A name whose only support is an argument,
a file name or a file the AI can write is never certain, and never confirms
a machine.

Every pair still waits for the examiner, except one way: a group whose
artifact-evidenced names match exactly one entry of the examiner's host
list, with no flag, confirms automatically (`apply_host_list`).
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field

from sift_common import host_identity as hi

CERTAIN = "certain"
PROPOSED = "proposed"
FLAGGED = "flagged"

AI_ORIGINS = hi.AI_ORIGINS | {"file-name"}

_GENERIC = {
    "localhost",
    "localhost.localdomain",
    "ubuntu",
    "kali",
    "debian",
    "minwinpc",
}
_GENERIC_PREFIX = re.compile(r"^(win-|desktop-|minint-|ec2amaz-|ip-)", re.I)
_NOT_HOST = {"", "-", ".", "n/a", "na", "null", "none", "unknown"}
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_IPV6 = re.compile(r"^[0-9a-f:]+$", re.I)
_COLLECTION = re.compile(r"([-_](triage|mem|memory))$")
_DATE = re.compile(r"([-_]\d{8}(t\d{6})?)$")
_VELOCIRAPTOR = re.compile(
    r"^collection-(.+?)-\d{4}-\d{2}-\d{2}t\d{2}[_:]\d{2}[_:]\d{2}z?$"
)

FLAG_GENERIC = "a generic or default name"
FLAG_NOT_HOST = "not a host name"
FLAG_CHARS = "unusual characters"
FLAG_DOMAINS = "the same short name in different domains"
FLAG_FOLDER = (
    "a possible rename or misfiled evidence: the folder name matches none of its names"
)
FLAG_THIN = "thin evidence: one source only"
FLAG_AI_ONLY = "named only by an argument, a file name or a file the AI can write"
FLAG_CLONE = "one machine id under different names: a rename or a clone?"
FLAG_NOT_LISTED = "not on the host list"
FLAG_NEAR = "a near spelling of another name"

# The host list's own names are kept under one pseudo unit.
LIST_UNIT = hi.unit_key("the examiner's host list")


# --------------------------------------------------------------------------
# Names


def code_points(name: str) -> str:
    """Each character outside printable ASCII as U+XXXX."""
    return " ".join(
        f"U+{ord(c):04X}" for c in name if not (c.isascii() and c.isprintable())
    )


def name_flags(raw: str) -> list[str]:
    """Why a name is never grouped with another."""
    s = hi.spelling(raw)
    flags = []
    if s in _NOT_HOST or _IPV4.match(s) or (":" in s and _IPV6.match(s)):
        flags.append(FLAG_NOT_HOST)
    elif "\\" in s or s.endswith("$") or "@" in s or " " in s:
        flags.append(FLAG_NOT_HOST)  # account forms, sentences
    elif s in _GENERIC or _GENERIC_PREFIX.match(s):
        flags.append(FLAG_GENERIC)
    if code_points(raw):
        flags.append(f"{FLAG_CHARS}: {code_points(raw)}")
    return flags


def core(raw: str) -> str:
    """A name with what isn't the machine set aside: its DNS suffix,
    collection and date tokens, and a Velociraptor collection wrapper."""
    s = hi.spelling(raw)
    m = _VELOCIRAPTOR.match(s)
    if m:
        s = m.group(1)
    s = s.split(".", 1)[0]
    for _ in range(2):
        s = _DATE.sub("", s)
        s = _COLLECTION.sub("", s)
    return s


def close(a: str, b: str) -> bool:
    """Two names of one machine within one unit: equal cores, or a NetBIOS
    name (15 characters) that is the start of the other."""
    ca, cb = core(a), core(b)
    if not ca or not cb:
        return False
    if ca == cb:
        return True
    short, long_ = sorted((ca, cb), key=len)
    return len(short) == 15 and long_.startswith(short)


def domains_compatible(a: str, b: str) -> bool:
    _, da = hi.split_name(a)
    _, db = hi.split_name(b)
    return not da or not db or da == db


# --------------------------------------------------------------------------
# Near spellings (once per new name)


def _similarity(a: str, b: str) -> float:
    if a == b:
        return 1.0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return 1.0 - prev[-1] / max(len(a), len(b))


def _bucket(core_name: str) -> tuple[str, int]:
    return re.sub(r"\D", "", core_name), len(core_name)


def near_hints(state: hi.HostState, new_pairs: list[tuple[str, str]]) -> list[dict]:
    """Hint records for names that are near spellings (≥ 0.85) of a name the
    case already holds. Only names with the same digits and a length within
    two are compared, so a case of thousands of names stays quick; names
    whose digits differ are different machines (WKS01, WKS02)."""
    by_bucket: dict[tuple[str, int], set[str]] = {}
    for _, raw in state.names:
        c = core(raw)
        if c:
            by_bucket.setdefault(_bucket(c), set()).add(c)
    out = []
    for unit, raw in new_pairs:
        c = core(raw)
        if not c or name_flags(raw):
            continue
        digits, length = _bucket(c)
        for n in range(length - 2, length + 3):
            for other in sorted(by_bucket.get((digits, n), ())):
                if other != c and _similarity(c, other) >= 0.85:
                    out.append({"kind": "hint", "unit": unit, "raw": raw, "near": other,
                                "score": round(_similarity(c, other), 2)})  # fmt: skip
    return out


# --------------------------------------------------------------------------
# The proposal


@dataclass
class Group:
    pairs: list[tuple[str, str]]
    tier: str
    canonical: str
    machine: str | None = None  # the confirmed or bound machine it joins, if any
    flags: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    list_entry: str | None = None
    auto_confirm: bool = False

    def to_dict(self) -> dict:
        return {
            "pairs": [list(p) for p in self.pairs],
            "tier": self.tier,
            "canonical": self.canonical,
            "machine": self.machine,
            "flags": list(self.flags),
            "conflicts": list(self.conflicts),
            "list_entry": self.list_entry,
            "auto_confirm": self.auto_confirm,
        }


@dataclass
class _Pair:
    unit: str
    raw: str
    evidence: list[str]
    origins: set[str]

    @property
    def artifact(self) -> bool:
        return hi.ARTIFACT in self.origins

    @property
    def ai_only(self) -> bool:
        return bool(self.origins) and self.origins <= AI_ORIGINS

    @property
    def hive(self) -> bool:
        return any(e.startswith("SYSTEM ") for e in self.evidence)

    @property
    def folder(self) -> bool:
        return hi.FOLDER in self.origins

    def foreign_by_evidence(self) -> bool:
        """Only from rows or forwarded logs: another machine's name."""
        return bool(self.evidence) and all(
            e.endswith("host column") or e.lower().startswith("forwardedevents")
            for e in self.evidence
        )


class _UF:
    def __init__(self):
        self.parent: dict = {}
        self.proposed: dict = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b, certain: bool) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return  # already one machine: a weaker reason changes nothing
        self.parent[rb] = ra
        self.proposed[ra] = (
            self.proposed.get(ra, False)
            or self.proposed.get(rb, False)
            or (not certain)
        )


def _list_entries(state: hi.HostState) -> list[dict]:
    entries = (state.host_list or {}).get("entries") or []
    return [e for e in entries if isinstance(e, dict) and e.get("name")]


def _entry_names(entry: dict) -> list[str]:
    return [entry["name"], *([entry["fqdn"]] if entry.get("fqdn") else []),
            *(entry.get("aliases") or [])]  # fmt: skip


def list_matches(raw: str, entries: list[dict]) -> list[dict]:
    """The list entries a name matches: spelling-equal to its name, FQDN or
    an alias, or the same short name where the domains agree (equal, or one
    side has none)."""
    s = hi.spelling(raw)
    short, domain = hi.split_name(raw)
    found = []
    for e in entries:
        for n in _entry_names(e):
            en = hi.spelling(n)
            es, ed = hi.split_name(n)
            if en == s or (es == short and (not ed or not domain or ed == domain)):
                found.append(e)
                break
    return found


def propose(state: hi.HostState) -> list[Group]:
    """The case's machines as the evidence suggests them: every machine that
    holds pairs, and every group of names still waiting for the examiner."""
    pairs = {
        p: _Pair(
            p[0], p[1], list(info.get("evidence") or []), set(info.get("origins") or [])
        )
        for p, info in state.names.items()
        if p[0] != LIST_UNIT
    }
    uf = _UF()
    for p in pairs:
        uf.find(p)
    never = {p for p in pairs if name_flags(p[1])}
    hinted = {(h.get("unit"), h.get("raw")) for h in state.hints}

    # Forwarded logs and row columns: another machine's names, unless the
    # unit also gives the name itself.
    by_unit: dict[str, list[tuple[str, str]]] = {}
    for p in pairs:
        by_unit.setdefault(p[0], []).append(p)
    foreign = set()
    for ps in by_unit.values():
        own = [p for p in ps if not pairs[p].foreign_by_evidence()]
        for p in ps:
            if pairs[p].foreign_by_evidence() and not any(
                close(p[1], o[1]) for o in own
            ):
                foreign.add(p)

    def groupable(
        p,
    ) -> bool:  # a near spelling is only a hint: no rule joins it to its match
        return p not in never

    # Within a unit: one hive's names (certain), close own names (proposed).
    for ps in by_unit.values():
        own = [p for p in ps if p not in foreign and groupable(p)]
        hive = [p for p in own if pairs[p].hive]
        for a, b in zip(hive, hive[1:], strict=False):
            uf.union(a, b, certain=True)
        for i, a in enumerate(own):
            for b in own[i + 1 :]:
                if close(a[1], b[1]) and domains_compatible(a[1], b[1]):
                    uf.union(a, b, certain=hi.spelling(a[1]) == hi.spelling(b[1]))

    # Across units: spelling-equal artifact names (certain), equal short
    # names (collection and date tokens set aside) with compatible domains
    # (proposed), a shared machine id (proposed).
    def domains_of(root) -> set[str]:
        return {hi.split_name(p[1])[1] for p in pairs if uf.find(p) == root} - {""}

    def ids_of(root) -> set[str]:
        units = {p[0] for p in pairs if uf.find(p) == root}
        return {
            str(state.units[u]["machine_guid"]).lower()
            for u in units
            if (state.units.get(u) or {}).get("machine_guid")
        }

    id_clash: set = set()

    def may_join(a, b) -> bool:
        """One machine only if the domains and machine ids agree."""
        ra, rb = uf.find(a), uf.find(b)
        if len(ids_of(ra) | ids_of(rb)) > 1:
            id_clash.update({a, b})
            return False
        return len(domains_of(ra) | domains_of(rb)) <= 1

    ordered = sorted(p for p in pairs if groupable(p))
    by_spelling: dict[str, list] = {}
    by_short: dict[str, list] = {}
    for p in ordered:
        by_spelling.setdefault(hi.spelling(p[1]), []).append(p)
        by_short.setdefault(core(p[1]), []).append(p)  # tokens and DNS suffix set aside
    for group in by_spelling.values():
        for a, b in zip(group, group[1:], strict=False):
            if pairs[a].artifact and pairs[b].artifact and a[0] != b[0]:
                if may_join(a, b):
                    uf.union(a, b, certain=True)
    for group in by_short.values():
        for a, b in zip(group, group[1:], strict=False):
            if a[0] == b[0] or uf.find(a) == uf.find(b):
                continue
            if may_join(a, b):
                uf.union(a, b, certain=False)

    clone_roots = set()
    for key in ("machine_guid", "client_id"):
        units_by_id: dict[str, list[str]] = {}
        for unit, info in state.units.items():
            if info.get(key):
                units_by_id.setdefault(str(info[key]).lower(), []).append(unit)
        for units in units_by_id.values():
            anchors = []
            for u in units:  # the unit's own name, an artifact one first
                own = [
                    p for p in by_unit.get(u, []) if p not in foreign and groupable(p)
                ]
                own.sort(key=lambda p: not pairs[p].artifact)
                anchors.append(own[0] if own else None)
            anchors = [a for a in anchors if a]
            for a, b in zip(anchors, anchors[1:], strict=False):
                if not close(a[1], b[1]):
                    clone_roots.update({uf.find(a), uf.find(b)})
                uf.union(a, b, certain=False)

    # Groups, and what each already is.
    groups: dict = {}
    for p in sorted(pairs):
        groups.setdefault(uf.find(p), []).append(p)
    clone_roots = {uf.find(r) for r in clone_roots}
    entries = _list_entries(state)
    result: list[Group] = []
    taken = {hi.spelling(m.canonical) for m in state.machines.values()}
    for root, ps in sorted(groups.items(), key=lambda kv: kv[1][0]):
        bound = sorted({state.bindings[p] for p in ps if p in state.bindings})
        machines = sorted({state.key_machine.get(k) for k in bound} - {None})
        g = Group(
            pairs=ps, tier=PROPOSED if uf.proposed.get(root) else CERTAIN, canonical=""
        )
        if len(machines) == 1:
            m = state.machines[machines[0]]
            g.machine, g.canonical = m.id, m.canonical
        elif len(machines) > 1:
            g.flags.append("names of more than one machine: confirm, or merge them")
        flags = _group_flags(g, ps, pairs, state, by_unit, foreign, never, hinted)
        g.flags.extend(f for f in flags if f not in g.flags)
        if root in clone_roots:
            g.flags.append(FLAG_CLONE)
        if g.flags:
            g.tier = FLAGGED if not g.machine else g.tier
        matched = _match_entries(g, ps, pairs, entries)
        if entries and not matched:
            g.flags.append(FLAG_NOT_LISTED)
        elif len(matched) == 1:
            g.list_entry = matched[0]["name"]
        elif len(matched) > 1:
            g.conflicts.append(
                "matches more than one host-list entry: "
                + ", ".join(sorted(e["name"] for e in matched))
            )
        if not g.canonical:
            g.canonical = _canonical(g, ps, pairs, taken)
            taken.add(hi.spelling(g.canonical))
        result.append(g)
    _list_conflicts(result, pairs, state, entries)
    for g in result:
        waiting = any(p not in state.bindings for p in g.pairs) or (
            g.machine is not None and state.machines[g.machine].state != hi.CONFIRMED
        )
        g.auto_confirm = bool(
            g.list_entry
            and not g.flags
            and not g.conflicts
            and any(pairs[p].artifact and not pairs[p].ai_only for p in g.pairs)
            and waiting
        )
    return result


def _group_flags(g, ps, pairs, state, by_unit, foreign, never, hinted) -> list[str]:
    flags: list[str] = []
    for p in ps:
        if p in never:
            flags.extend(name_flags(p[1]))
        if p in hinted:
            near = sorted(
                {
                    str(h["near"])
                    for h in state.hints
                    if (h.get("unit"), h.get("raw")) == p
                }
            )
            flags.append(f"{FLAG_NEAR}: {', '.join(near)}")
    shorts: dict[str, set] = {}
    for p in ps:
        short, domain = hi.split_name(p[1])
        if domain:
            shorts.setdefault(short, set()).add(domain)
    if any(len(ds) > 1 for ds in shorts.values()):
        flags.append(FLAG_DOMAINS)
    # a unit whose folder name matches none of its own artifact names
    for unit in {p[0] for p in ps}:
        own = [q for q in by_unit[unit] if q not in foreign]
        folder = [q for q in own if pairs[q].folder]
        artifact = [q for q in own if pairs[q].artifact and q not in never]
        if (
            folder
            and artifact
            and not any(close(f[1], a[1]) for f in folder for a in artifact)
        ):
            flags.append(FLAG_FOLDER)
    sources = {e for p in ps for e in pairs[p].evidence}
    if len(sources) <= 1 and not g.machine:
        flags.append(FLAG_THIN)
    if all(pairs[p].ai_only for p in ps):
        flags.append(FLAG_AI_ONLY)
    return list(dict.fromkeys(flags))


def _match_entries(g, ps, pairs, entries) -> list[dict]:
    found: dict[str, dict] = {}
    for p in ps:
        if not pairs[p].artifact or pairs[p].ai_only:
            continue  # only evidence the examiner put in the case names a list entry
        for e in list_matches(p[1], entries):
            found[e["name"]] = e
    return list(found.values())


def _list_conflicts(groups: list[Group], pairs, state, entries) -> None:
    """Two groups matching one list entry are a conflict when their domains
    or machine ids disagree: also against machines already confirmed for it."""
    by_entry: dict[str, list[Group]] = {}
    for g in groups:
        if g.list_entry:
            by_entry.setdefault(g.list_entry, []).append(g)
    for entry, gs in by_entry.items():
        if len(gs) < 2:
            continue
        domains = set()
        ids = set()
        for g in gs:
            domains |= {hi.split_name(p[1])[1] for p in g.pairs} - {""}
            for unit in {p[0] for p in g.pairs}:
                guid = (state.units.get(unit) or {}).get("machine_guid")
                if guid:
                    ids.add(str(guid).lower())
        if len(domains) > 1 or len(ids) > 1:
            why = "different domains" if len(domains) > 1 else "different machine ids"
            for g in gs:
                g.conflicts.append(
                    f"host-list entry {entry} is matched by evidence with {why}"
                )


def _canonical(g: Group, ps, pairs, taken: set[str]) -> str:
    """The list name; else the hive's Hostname.Domain; else the most
    frequent FQDN; else the hive's ComputerName or the folder name; else the
    first name. A second machine of a taken name gets its FQDN, or
    `<name> (<domain>)`, or `<name> (n)`."""
    hive_fqdn = [
        p[1] for p in ps if any("Hostname+Domain" in e for e in pairs[p].evidence)
    ]
    fqdns = sorted((p[1] for p in ps if "." in p[1]), key=lambda n: (-ps.count(n), n))
    hive_name = [
        p[1] for p in ps if any(e.endswith("ComputerName") for e in pairs[p].evidence)
    ]
    folder = [p[1] for p in ps if pairs[p].folder]
    first = g.list_entry or (hive_fqdn or fqdns or hive_name or folder or [ps[0][1]])[0]
    if hi.spelling(first) not in taken:
        return first
    for fq in fqdns:
        if hi.spelling(fq) not in taken:
            return fq
    short, domain = hi.split_name(first)
    if domain and hi.spelling(f"{first.split('.')[0]} ({domain})") not in taken:
        return f"{first.split('.')[0]} ({domain})"
    n = 2
    while hi.spelling(f"{first} ({n})") in taken:
        n += 1
    return f"{first} ({n})"


def listed_without_data(state: hi.HostState, groups: list[Group]) -> list[str]:
    """Host-list entries no evidence matches yet ("no data yet")."""
    named = {g.list_entry for g in groups if g.list_entry}
    for m in state.machines.values():  # and machines the list already confirmed
        for e in _list_entries(state):
            if any(
                list_matches(n, [e]) for n in (m.canonical, *(p[1] for p in m.pairs))
            ):
                named.add(e["name"])
    return [e["name"] for e in _list_entries(state) if e["name"] not in named]


# --------------------------------------------------------------------------
# The host list


def parse_host_list(text: str) -> list[dict]:
    """One machine per line: a name, and optionally its FQDN after a comma or
    whitespace. Blank lines and lines starting with # are skipped; a CSV
    header (name,fqdn) is too."""
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [x.strip() for x in re.split(r"[,\t ]+", line) if x.strip()]
        if not parts or parts[0].lower() in ("name", "host", "hostname"):
            continue
        entry = {"name": unicodedata.normalize("NFC", parts[0])}
        if len(parts) > 1:
            entry["fqdn"] = unicodedata.normalize("NFC", parts[1])
        entries.append(entry)
    return entries


def upload_host_list(case_dir, text: str, examiner: str) -> dict:
    """Record the examiner's host list, then confirm what it names."""
    if not examiner:
        raise hi.HostLogError("a host list needs the examiner who uploads it")
    entries = parse_host_list(text)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    hi.append_observations(
        case_dir,
        [{"kind": "list", "entries": entries, "sha256": digest, "examiner": examiner}],
    )
    return {"entries": len(entries), "sha256": digest, **apply_host_list(case_dir)}


def apply_host_list(case_dir) -> dict:
    """Confirm, under the log lock, every group the host list names with no
    flag and no conflict. A group that joins a machine keeps its canonical,
    and the list's spelling is recorded as one of its names."""
    from pathlib import Path

    root = Path(case_dir)
    confirmed: list[str] = []
    with hi._log_lock(root):
        state = hi.load(root)
        records: list[dict] = []
        for g in propose(state):
            if not g.auto_confirm:
                continue
            if g.machine:
                m = state.machines[g.machine]
                key, canonical = m.keys[0], m.canonical
            else:
                existing = _machine_for_entry(state, g.list_entry)
                if existing is not None:
                    key, canonical = existing.keys[0], existing.canonical
                else:
                    key, canonical = hi.new_machine_key(), g.canonical
            for p in g.pairs:  # a bound pair keeps its key: its machine is confirmed
                records.append({"kind": "bind", "unit": p[0], "raw": p[1],
                                "key": state.bindings.get(p, key), "canonical": canonical,
                                "state": hi.CONFIRMED,
                                "flags": ["confirmed by the examiner's host list"]})  # fmt: skip
            if hi.spelling(g.list_entry) != hi.spelling(
                canonical
            ):  # the list's spelling
                records.append({"kind": "name", "unit": LIST_UNIT, "raw": g.list_entry,
                                "evidence": "host list", "origin": "list"})  # fmt: skip
                records.append({"kind": "bind", "unit": LIST_UNIT, "raw": g.list_entry,
                                "key": key, "state": hi.CONFIRMED})  # fmt: skip
            confirmed.append(canonical)
        for rec in records:
            hi._append_locked(root / hi.OBSERVATIONS, {"t": hi._now(), **rec})
    return {"confirmed": sorted(set(confirmed))}


def _machine_for_entry(state: hi.HostState, entry_name: str | None):
    """The confirmed machine the list entry already names, if exactly one."""
    if not entry_name:
        return None
    entries = [e for e in _list_entries(state) if e["name"] == entry_name]
    found = []
    for m in state.machines.values():
        if m.state != hi.CONFIRMED:
            continue
        names = {m.canonical, *(p[1] for p in m.pairs)}
        if any(list_matches(n, entries) for n in names):
            found.append(m)
    return found[0] if len(found) == 1 else None
