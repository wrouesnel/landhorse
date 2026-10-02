#!/usr/bin/env python3
"""gen-copyright.py - write debian/copyright for landhorse and its vendored modules.

Run from the repository root after `go mod vendor`. Each vendored module's license is
identified from its license file; a module whose license can't be identified stops the
build, unless it is listed in OVERRIDES with a reason.
"""
import os
import re
import sys

# Modules whose license file is missing or unrecognisable, with what to record and why.
OVERRIDES = {}

HEADER = """Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: landhorse
Upstream-Contact: Will Rouesnel <wrouesnel@wrouesnel.com>
Comment: The binary links github.com/yuseferi/zax/v2, which is GPL-3, so the
 combined work is distributed under GPL-3 (landhorse's own code is GPL-2+).

Files: *
Copyright: 2026 Will Rouesnel <wrouesnel@wrouesnel.com>
License: GPL-2+

Files: data/*.metainfo.xml
Copyright: 2026 Will Rouesnel <wrouesnel@wrouesnel.com>
License: CC0-1.0
"""

LICENSE_TEXTS = {
    "GPL-2+": """ This program is free software; you can redistribute it and/or modify it
 under the terms of the GNU General Public License as published by the Free
 Software Foundation; either version 2 of the License, or (at your option) any
 later version.
 .
 On Debian systems, the complete text of the GNU General Public License version 2
 can be found in "/usr/share/common-licenses/GPL-2".""",
    "GPL-3": """ This program is free software: you can redistribute it and/or modify it
 under the terms of the GNU General Public License version 3 as published by the
 Free Software Foundation.
 .
 On Debian systems, the complete text of the GNU General Public License version 3
 can be found in "/usr/share/common-licenses/GPL-3".""",
    "Apache-2.0": """ Licensed under the Apache License, Version 2.0 (the "License"); you may not
 use this file except in compliance with the License.
 .
 On Debian systems, the complete text of the Apache License, Version 2.0 can be
 found in "/usr/share/common-licenses/Apache-2.0".""",
    "CC0-1.0": """ To the extent possible under law, the author has dedicated all copyright and
 related and neighboring rights to this file to the public domain worldwide.
 .
 On Debian systems, the complete text of the CC0 1.0 Universal license can be found
 in "/usr/share/common-licenses/CC0-1.0".""",
    "missing": """ No license has been published for this module. See the Comment field.""",
}


def detect(text):
    """Return the DEP-5 short name for a license text, or None."""
    t = " ".join(text.split())
    if "GNU GENERAL PUBLIC LICENSE" in t and "Version 3" in t:
        return "GPL-3"
    if "Apache License" in t and "Version 2.0" in t:
        return "Apache-2.0"
    if "Permission is hereby granted, free of charge" in t:
        return "Expat"
    if "Permission to use, copy, modify, and/or distribute" in t or "Permission to use, copy, modify, and distribute" in t:
        return "ISC"
    if "Redistribution and use in source and binary forms" in t:
        # The third clause forbids using names to endorse derived products; its wording varies.
        return "BSD-3-clause" if re.search(r"(?i)used to endorse or promote", t) else "BSD-2-clause"
    if "public domain" in t.lower():
        return "public-domain"
    return None


def license_file(path):
    for name in sorted(os.listdir(path)):
        if re.match(r"(?i)^(licen[cs]e|copying)(\.(md|txt))?$", name):
            return os.path.join(path, name)
    return None


def copyrights(text, module):
    lines = []
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"(?i)^copyright\s*(?:\(c\)|©)?\s*(.+)$", line)
        if m and re.search(r"\d{4}", m.group(1)) and "notice" not in line.lower():
            holder = m.group(1).rstrip(".")
            holder = re.sub(r"(?i)\s*all rights reserved\.?$", "", holder)
            lines.append(holder)
    return lines or [f"the {module} authors"]


def indent(text):
    out = []
    for line in text.strip("\n").splitlines():
        out.append(" " + line.rstrip() if line.strip() else " .")
    return "\n".join(out)


def main():
    modules = []
    with open("vendor/modules.txt") as f:
        for line in f:
            m = re.match(r"^# (\S+) (\S+)", line)
            if m:
                modules.append(m.group(1))

    stanzas, needed, used_texts = [], set(), {}
    for module in sorted(set(modules)):
        path = os.path.join("vendor", module)
        if not os.path.isdir(path):
            continue  # listed for its go.mod only; no packages vendored
        if module in OVERRIDES:
            holder, lic, comment = OVERRIDES[module]
            stanzas.append(f"Files: vendor/{module}/*\nCopyright: {holder}\nLicense: {lic}\nComment: {comment}\n")
            needed.add(lic)
            continue
        lf = license_file(path)
        if lf is None:
            sys.exit(f"gen-copyright: {module} has no license file; add it to OVERRIDES")
        text = open(lf, encoding="utf-8", errors="replace").read()
        lic = detect(text)
        if lic is None:
            sys.exit(f"gen-copyright: can't identify the license of {module} ({lf}); add it to OVERRIDES")
        holders = "\n ".join(copyrights(text, module))
        stanzas.append(f"Files: vendor/{module}/*\nCopyright: {holders}\nLicense: {lic}\n")
        needed.add(lic)
        if lic not in LICENSE_TEXTS:
            used_texts.setdefault(lic, (module, text))

    out = [HEADER]
    out.extend(stanzas)
    needed.update({"GPL-2+", "CC0-1.0"})
    for lic in sorted(needed):
        if lic in LICENSE_TEXTS:
            body = LICENSE_TEXTS[lic]
        else:
            module, text = used_texts[lic]
            body = indent(text) + f"\n .\n The text above is from {module}."
        out.append(f"License: {lic}\n{body}\n")
    with open("debian/copyright", "w") as f:
        f.write("\n".join(out))


if __name__ == "__main__":
    main()
