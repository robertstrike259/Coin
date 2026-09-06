"""CI + local check: em dashes (U+2014) and en dashes (U+2013) are forbidden
anywhere in project sources, docs, and configs. ASCII hyphen-minus only."""
import pathlib
import sys

BAD = {chr(0x2013), chr(0x2014)}
ROOTS = ["src", "apps", "tests", ".github", "scripts", "CMakeLists.txt",
         "vcpkg.json", "README.md", "SPEC.md"]


def files():
    for r in ROOTS:
        p = pathlib.Path(__file__).resolve().parent.parent / r
        if p.is_file():
            yield p
        elif p.is_dir():
            yield from (f for f in p.rglob("*") if f.is_file())


def main():
    hits = []
    for f in files():
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        found = sorted({c for c in BAD if c in text})
        if found:
            hits.append("%s: %s" % (f, ",".join("U+%04X" % ord(c) for c in found)))
    if hits:
        print("forbidden dashes found:")
        print("\n".join(hits))
        return 1
    print("no em/en dashes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
