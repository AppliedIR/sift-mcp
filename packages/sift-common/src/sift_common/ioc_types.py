"""The IOC types a record can hold: one entry per id, with its category, its
label and the other spellings that mean it. A spelling folds (trimmed, lower
case, without spaces, "_" and "-") to one id, or to none. Stdlib only."""

from __future__ import annotations

import re

# id: (category, label, the other spellings that mean it, space-separated)
IDS = {
    "url": ("network", "URL", ""),
    "url:path": ("network", "URL path", "url_path uri-path uri-stem cs-uri-stem"),
    "email-addr": (
        "network",
        "Email",
        "email email-src email-dst target-email email-address email-reply-to",
    ),
    "email-message:subject": ("network", "Email subject", "email-subject"),
    "email-message:message-id": (
        "network",
        "Message ID",
        "email-message-id message-id",
    ),
    "ipv4-addr": (
        "network",
        "IPv4",
        "ipv4 ip ip-src ip-dst ip-address ipv4-address src-ip dst-ip source-ip destination-ip dest-ip ip4",
    ),
    "ipv6-addr": ("network", "IPv6", "ipv6 ipv6-address ip6"),
    "domain-name": ("network", "Domain", "domain fqdn"),
    "hostname": (
        "network",
        "Hostname",
        "target-machine computer-name computer machine-name netbios-name workstation",
    ),
    "user-agent": ("network", "User agent", "http-user-agent"),
    "mac-addr": ("network", "MAC address", "mac mac-address"),
    "ja3": ("network", "JA3", "ja3-fingerprint ja3-fingerprint-md5"),
    "ja3s": ("network", "JA3S", "ja3s-fingerprint ja3s-fingerprint-md5"),
    "ja4": ("network", "JA4", "ja4-fingerprint"),
    "jarm": ("network", "JARM", "jarm-fingerprint"),
    "hassh": ("network", "HASSH", "hassh-md5"),
    "hassh-server": ("network", "HASSH server", "hasshserver-md5"),
    "x509-certificate:hash": (
        "network",
        "Certificate fingerprint",
        "x509-fingerprint x509-fingerprint-sha1 x509-fingerprint-sha256 x509-fingerprint-md5 certificate-fingerprint cert-thumbprint thumbprint",
    ),
    "cryptocurrency-wallet": (
        "network",
        "Crypto wallet",
        "bitcoin-address btc xmr crypto-wallet wallet",
    ),
    "file:hash:sha256": ("host", "SHA256", "sha256"),
    "file:hash:sha1": ("host", "SHA1", "sha1"),
    "file:hash:md5": ("host", "MD5", "md5"),
    "file:hash:sha512": ("host", "SHA512", "sha512"),
    "file:hash:imphash": ("host", "Imphash", "imphash import-hash"),
    "file:hash:ssdeep": ("host", "SSDEEP", "ssdeep"),
    "file:hash:tlsh": ("host", "TLSH", "tlsh"),
    "file:name": ("host", "File name", "filename process-name"),
    "file:path": ("host", "File", "file-path file unc-path directory full-path folder"),
    "registry-key": (
        "system",
        "Registry key",
        "windows-registry-key regkey registry registry-path",
    ),
    "scheduled-task": (
        "system",
        "Scheduled task",
        "windows-scheduled-task task schtask",
    ),
    "process:command-line": ("system", "Command line", "command-line cmdline command"),
    "service-name": (
        "system",
        "Service name",
        "windows-service-name svc windows-service",
    ),
    "mutex": ("system", "Mutex", "mutant mutex-name"),
    "named-pipe": ("system", "Named pipe", "pipe pipe-name"),
    "windows-sid": ("identity", "Windows SID", "security-identifier"),
    "user-account": (
        "identity",
        "Account",
        "account target-user user username logon-name",
    ),
    "unknown": ("unknown", "Unknown", "other"),
}


def _fold(t: str) -> str:
    return re.sub(r"[\s_-]", "", t.strip().lower())


CATEGORY = {i: c for i, (c, _, _) in IDS.items()}
_BY_FOLD = {_fold(s): i for i, (_, _, more) in IDS.items() for s in [i, *more.split()]}


def canonical(t) -> str | None:
    """The id a type means; None for a spelling the table doesn't hold or a
    type that is not text."""
    return _BY_FOLD.get(_fold(t)) if isinstance(t, str) else None


def label(t) -> str:
    """The label of the id a type means; otherwise the type as text."""
    i = canonical(t)
    return IDS[i][1] if i else str(t)


def untyped(t) -> bool:
    """A type read as left out: empty, false or only whitespace."""
    return not t or (isinstance(t, str) and not t.strip())


def listing() -> str:
    """The ids by category, each with what it holds."""
    groups: dict[str, list[str]] = {}
    for i, (c, lb, _) in IDS.items():
        groups.setdefault(c, []).append(f"{i} ({lb})")
    return "; ".join(f"{c}: {', '.join(ids)}" for c, ids in groups.items())


def refang(value: str) -> str:
    """Refang a defanged value as record_finding does before storing it."""
    v = value.replace("[.]", ".").replace("hxxp", "http")
    return re.sub(r"\[(\W)\]", r"\1", v)


def is_ipv4(value: str) -> bool:
    """One IPv4 address, with at most one trailing port or prefix."""
    stripped = re.sub(r"[:/]\d{1,5}$", "", value.strip())
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", stripped):
        return False
    return all(0 <= int(o) <= 255 for o in stripped.split("."))
