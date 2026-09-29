"""
NEVUS - CPE helpers.

nmap reports CPEs in the old 2.2 URI format (cpe:/a:vendor:product:version)
while the NVD API only accepts the 2.3 formatted string
(cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*).
"""

import re


def _split22(cpe: str):
    return cpe[len("cpe:/"):].split(":")


def cpe_part(cpe: str) -> str:
    """Return the CPE part: 'a' (application), 'o' (OS) or 'h' (hardware)."""
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")
        return parts[2] if len(parts) > 2 else ""
    if cpe.startswith("cpe:/"):
        return cpe[5:6]
    return ""


def cpe_version(cpe: str) -> str:
    """Return the version component of a CPE, or '' if it has none."""
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")
        version = parts[5] if len(parts) > 5 else ""
    elif cpe.startswith("cpe:/"):
        comps = _split22(cpe)
        version = comps[3] if len(comps) > 3 else ""
    else:
        return ""
    return "" if version in ("", "*", "-") else version


def to_cpe23(cpe: str) -> str:
    """Convert a CPE 2.2 URI into a CPE 2.3 formatted string."""
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if not cpe.startswith("cpe:/"):
        raise ValueError(f"Unsupported CPE format: {cpe}")

    comps = _split22(cpe)
    comps += [""] * (7 - len(comps))
    part, vendor, product, version, update, edition, language = comps[:7]
    sw_edition = target_sw = target_hw = other = ""

    # Packed edition: ~edition~sw_edition~target_sw~target_hw~other
    if edition.startswith("~"):
        packed = edition.split("~")
        packed += [""] * (6 - len(packed))
        edition, sw_edition, target_sw, target_hw, other = packed[1:6]

    # NVD stores OpenSSH-style versions such as 8.9p1 as version 8.9 + update p1
    match = re.match(r"^(\d+(?:\.\d+)*)(p\d+)$", version)
    if match and not update:
        version, update = match.group(1), match.group(2)

    fields = [part, vendor, product, version, update, edition, language,
              sw_edition, target_sw, target_hw, other]
    return "cpe:2.3:" + ":".join(f if f else "*" for f in fields)
