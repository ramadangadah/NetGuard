"""
Scope enforcement: a scan target is only allowed to run if it falls
entirely within one of the admin-configured allow-listed CIDR ranges.
This is the guardrail that keeps this tool pointed only at networks the
operator has actually authorized, instead of the open internet.
"""
import ipaddress

from sqlmodel import Session, select

from app.models import AllowlistEntry


class ScopeError(ValueError):
    pass


def get_allowlist(session: Session) -> list[str]:
    return [e.cidr for e in session.exec(select(AllowlistEntry)).all()]


def _to_network(target: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    # Accept a bare host ("192.168.1.1") or CIDR ("192.168.1.0/24")
    if "/" not in target:
        target = f"{target}/32"
    return ipaddress.ip_network(target, strict=False)


def assert_in_scope(session: Session, target: str) -> None:
    allowlist = get_allowlist(session)
    if not allowlist:
        raise ScopeError(
            "No authorized ranges are configured yet. Add the CIDR(s) you own/administer "
            "under Settings before running any scan."
        )
    try:
        target_net = _to_network(target)
    except ValueError as exc:
        raise ScopeError(f"'{target}' is not a valid IP, host, or CIDR range: {exc}") from exc

    for cidr in allowlist:
        try:
            allowed_net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if target_net.version == allowed_net.version and target_net.subnet_of(allowed_net):
            return

    raise ScopeError(
        f"'{target}' is outside your authorized scan ranges ({', '.join(allowlist)}). "
        "Add it under Settings first if you're authorized to scan it."
    )
