#!/usr/bin/env python3
"""Regenerate the fake-codesigning provisioning profiles with a future
ExpirationDate, re-signed using the bundled SelfSigned.p12 certificate.

The fake profiles ship with an ExpirationDate that eventually passes (e.g.
2026-10-30), which makes bazel's plisttool reject them with "ExpirationDate is
in the past". This script decodes each .mobileprovision, pushes ExpirationDate
into the future, and re-signs it with the self-signed cert.
"""

import datetime
import os
import plistlib
import subprocess
import sys
import tempfile


def run(args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True)


def main():
    profiles_dir = "build-system/fake-codesigning/profiles"
    p12 = "build-system/fake-codesigning/certs/SelfSigned.p12"
    keychain = "mango-fake.keychain"
    keychain_pw = "secret"

    # --- temp keychain with the self-signed identity ---
    run(["security", "delete-keychain", keychain], check=False)
    run(["security", "create-keychain", "-p", keychain_pw, keychain])
    run(["security", "unlock-keychain", "-p", keychain_pw, keychain])
    run(["security", "import", p12, "-k", keychain, "-P", "",
         "-T", "/usr/bin/codesign", "-T", "/usr/bin/security"])
    run(["security", "set-key-partition-list", "-S", "apple-tool:,apple:",
         "-k", keychain_pw, keychain])

    out = run(["security", "find-identity", "-v", "-p", "codesigning",
               keychain]).stdout
    identity = None
    for line in out.splitlines():
        if '"' in line:
            identity = line.split('"')[1]
            break
    if not identity:
        print("no codesigning identity found")
        sys.exit(1)
    print("identity:", identity)

    new_expiration = datetime.datetime(2030, 1, 1, 0, 0, 0)

    for name in sorted(os.listdir(profiles_dir)):
        if not name.endswith(".mobileprovision"):
            continue
        src = os.path.join(profiles_dir, name)
        xml = run(["security", "cms", "-D", "-i", src]).stdout
        data = plistlib.loads(xml.encode("utf-8"))
        data["ExpirationDate"] = new_expiration
        tmp = tempfile.mktemp(suffix=".plist")
        with open(tmp, "wb") as f:
            plistlib.dump(data, f, fmt=plistlib.FMT_XML)
        run(["security", "cms", "-S", "-k", keychain, "-N", identity,
             "-i", tmp, "-o", src])
        os.unlink(tmp)
        print("regenerated", name)

    run(["security", "delete-keychain", keychain], check=False)
    print("done")


if __name__ == "__main__":
    main()
