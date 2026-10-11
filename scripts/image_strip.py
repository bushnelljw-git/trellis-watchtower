#!/usr/bin/env python3
"""Leave an image with no shell, package manager, network tool, installer or
setuid or setgid program.

The owner, 2026-10-03: "Can you ensure that we striping down our containers that
we are running so there is no possible way to get a shell to them?" Cloud Run has
no exec or SSH into a container, so nobody can open one remotely; this is for the
other way in, a code-execution bug in the service itself, which then finds no
shell to start, no package manager to fetch one and no network tool to talk out
with. Python stays: it is what the service runs. Nor does it find a setuid or
setgid program to raise its privileges with (the coordinator's rework, the same
day, matching call-center's builder).

Each image runs this as its LAST build step, as root, in exec form (there is no
shell left to run anything after it), with the file bind-mounted from the build
context so it never enters a layer:

    RUN --mount=type=bind,source=scripts/image_strip.py,target=/tmp/image_strip.py \
        ["python", "-I", "-B", "/tmp/image_strip.py"]

What it does, in order:

1. Uninstalls pip, setuptools and wheel (pip uninstalls itself last), and deletes
   the standard library's `ensurepip`, which carries a pip wheel of its own.
2. Purges PURGE from dpkg by hand: every file each package's list names, its
   files under /var/lib/dpkg/info, its stanza in /var/lib/dpkg/status, and any
   alternative only it provided. dpkg's own purge can't do this: the maintainer
   scripts it runs need the very shell being removed. The status file keeps
   every package still present, so an image scanner and a person reading it
   agree on what the image holds (no stale entry for a removed package, and no
   remaining package hidden).
   The setuid and setgid programs (su, mount, umount, passwd, chsh, chfn,
   gpasswd, newgrp, chage, expiry, unix_chkpwd) are useless without their bit
   and no service calls them, so their packages are purged whole too.
3. Deletes what only dpkg, apt and debconf read (their caches, logs, lock and
   backup files, /etc/apt, /etc/dpkg), drops every shell that no longer exists
   from /etc/shells, and gives an account whose shell is gone NO_LOGIN's first
   program that exists. Then clears every setuid and setgid bit left anywhere on
   the image's own filesystem, folders included (/var/mail's group bit, say).
4. Checks the result and fails the build on any surprise: a PURGE package that
   isn't installed (the base image moved: review this list), a removed package
   still in dpkg's status, a FORBIDDEN program on any PATH folder, pip,
   setuptools or wheel still installed, or any setuid or setgid file left.

Not removed: coreutils and the other essential tools a running service never
calls but that run no code of their own (an `env` or a `find -exec` needs a
program to start, and none of these is left). The scripts among them that need
/bin/sh (which, zgrep and the like) simply no longer start.

Standard library only. tpa-platform's copy and auth-notary's are byte for byte
the same file; change both together.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import os
import shutil
import stat
import subprocess
import sys
import sysconfig
from pathlib import Path

#: The Debian packages removed outright: the two shells (bash brings rbash), apt
#: and what only apt uses (its library, its signature checker, its keyring),
#: dpkg and debconf, and perl; then every package that ships a setuid or setgid
#: program: login (newgrp, sg), passwd (passwd, chsh, chfn, gpasswd, chage,
#: expiry; useradd and groupadd ran before this step), mount (mount, umount),
#: util-linux (su, and runuser, nsenter, unshare and setpriv with it) and
#: libpam-modules-bin (unix_chkpwd). Every one must be installed: a name the
#: base image no longer has fails the build, so a moved base is reviewed here.
PURGE = (
    "bash",
    "dash",
    "apt",
    "libapt-pkg7.0",
    "sqv",
    "debian-archive-keyring",
    "debconf",
    "dpkg",
    "perl-base",
    "login",
    "passwd",
    "mount",
    "util-linux",
    "libpam-modules-bin",
)

#: Python's own installers. pip goes last, since it does the uninstalling.
PYTHON_INSTALLERS = ("setuptools", "wheel", "pip")

#: No file or link of these names may be left in a PATH folder.
FORBIDDEN = frozenset({
    # shells
    "sh", "bash", "dash", "rbash", "ash", "busybox", "zsh", "ksh", "mksh", "csh", "tcsh",
    "fish",
    # package managers and their friends
    "apt", "apt-get", "apt-cache", "apt-cdrom", "apt-config", "apt-key", "apt-mark",
    "aptitude", "dpkg", "dpkg-deb", "dpkg-divert", "dpkg-maintscript-helper", "dpkg-query",
    "dpkg-realpath", "dpkg-split", "dpkg-statoverride", "dpkg-trigger", "dpkg-preconfigure",
    "dpkg-reconfigure", "update-alternatives", "debconf", "start-stop-daemon",
    # network tools
    "curl", "wget", "nc", "netcat", "ncat", "telnet", "socat",
    # setuid and setgid programs, and the privilege tools that went with them
    "su", "sudo", "doas", "pkexec", "runuser", "sulogin", "login", "newgrp", "sg", "passwd",
    "chsh", "chfn", "gpasswd", "chage", "expiry", "mount", "umount", "unix_chkpwd",
    "unix_update", "nsenter", "unshare", "setpriv",
    # perl, and Python's installers
    "perl", "pip", "pip3", "easy_install",
})
#: Versioned spellings: perl5.40.1, pip3.12.
FORBIDDEN_PREFIXES = ("perl5", "pip3.")

PATH_FOLDERS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")

DPKG = Path("/var/lib/dpkg")
STATUS = DPKG / "status"
INFO = DPKG / "info"
ALTERNATIVES_DB = DPKG / "alternatives"
ALTERNATIVES = Path("/etc/alternatives")
#: What an account whose shell is gone is given: the first that exists (login,
#: which carries nologin, is purged; coreutils' false stays).
NO_LOGIN = ("/usr/sbin/nologin", "/usr/bin/false")
#: The setuid and setgid bits.
SET_ID = stat.S_ISUID | stat.S_ISGID

#: What only dpkg, apt and debconf read or write, and so means nothing once
#: they are gone. /var/lib/dpkg/status and the remaining packages' info files
#: stay: they are the record of what the image holds.
TOOL_STATE = (
    "/var/lib/dpkg/status-old",
    "/var/lib/dpkg/available",
    "/var/lib/dpkg/available-old",
    "/var/lib/dpkg/diversions-old",
    "/var/lib/dpkg/statoverride-old",
    "/var/lib/dpkg/lock",
    "/var/lib/dpkg/lock-frontend",
    "/var/lib/dpkg/cmethopt",
    "/var/lib/dpkg/arch-native",
    "/var/lib/dpkg/triggers",
    "/var/lib/dpkg/updates",
    "/var/lib/dpkg/parts",
    "/var/lib/apt",
    "/var/cache/apt",
    "/var/cache/debconf",
    "/var/log/apt",
    "/var/log/dpkg.log",
    "/var/log/alternatives.log",
    "/etc/apt",
    "/etc/dpkg",
)


def fail(why: str) -> None:
    print(f"image_strip: FAIL - {why}", file=sys.stderr)
    sys.exit(1)


def say(line: str) -> None:
    print(f"image_strip: {line}")


def where(path: str) -> str:
    """Where a listed path itself sits: its folder resolved, its own name kept.

    A link is never followed, so `/usr/bin/sh` (a link to dash) is itself, and
    `/lib/x86_64-linux-gnu/x` and `/usr/lib/x86_64-linux-gnu/x` (merged /usr)
    are one place.
    """
    head, tail = os.path.split(path)
    return os.path.join(os.path.realpath(head), tail)


# --- 1. Python's installers ----------------------------------------------------


def installed(name: str) -> bool:
    try:
        importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return False
    return True


def strip_python_installers() -> None:
    present = [name for name in PYTHON_INSTALLERS if installed(name)]
    if present:
        if "pip" not in present:
            fail(f"{', '.join(present)} installed with no pip to uninstall them")
        subprocess.run(  # noqa: S603, RUF100 - a fixed argv, by exec: there is no shell
            [sys.executable, "-m", "pip", "uninstall", "--yes", "--no-input", *present],
            check=True,
        )
        say("uninstalled " + ", ".join(present))
    ensurepip = Path(sysconfig.get_paths()["stdlib"]) / "ensurepip"
    if ensurepip.exists():
        shutil.rmtree(ensurepip)
        say(f"deleted {ensurepip} (it carries a pip wheel)")


# --- 2. dpkg, by hand ----------------------------------------------------------


def stanzas() -> list[tuple[str, str]]:
    """dpkg's status file as (package name, stanza text), in order."""
    text = STATUS.read_text(encoding="utf-8")
    found: list[tuple[str, str]] = []
    for block in text.split("\n\n"):
        if not block.strip():
            continue
        name = ""
        for line in block.splitlines():
            if line.startswith("Package: "):
                name = line[len("Package: "):].strip()
                break
        if not name:
            fail("a stanza in /var/lib/dpkg/status names no package")
        found.append((name, block.strip("\n")))
    return found


def info_files(package: str) -> list[Path]:
    """/var/lib/dpkg/info/<package>.* and <package>:<arch>.*, and nothing else."""
    files = []
    for path in INFO.iterdir():
        owner = path.name.rsplit(".", 1)[0]
        if owner == package or (owner.split(":", 1)[0] == package and ":" in owner):
            files.append(path)
    return files


def listed(package: str, *, required: bool = True) -> list[str]:
    """The paths dpkg's list for `package` names. A package that is only
    remembered (removed, its configuration kept) has no list."""
    lists = [p for p in info_files(package) if p.name.endswith(".list")]
    if not lists and not required:
        return []
    if len(lists) != 1:
        fail(f"{package} has {len(lists)} file lists in {INFO}, not one")
    return [line for line in lists[0].read_text(encoding="utf-8").splitlines() if line]


def diverted_by(packages: set[str]) -> list[str]:
    diversions = DPKG / "diversions"
    if not diversions.exists():
        return []
    lines = diversions.read_text(encoding="utf-8").splitlines()
    return [lines[i] for i in range(0, len(lines) - 2, 3) if lines[i + 2] in packages]


def drop_alternatives(gone: set[str]) -> list[str]:
    """Remove every alternative whose every choice was a purged package's file.

    The database file is dpkg's format: the mode, the master link, then a
    (name, link) pair per slave and a blank line; then each choice as its path,
    its priority and one line per slave, and a blank line.
    """
    dropped: list[str] = []
    if not ALTERNATIVES_DB.is_dir():
        return dropped
    for db in sorted(ALTERNATIVES_DB.iterdir()):
        lines = db.read_text(encoding="utf-8").split("\n")
        master_link = lines[1]
        at, slaves = 2, []
        while lines[at]:
            slaves.append((lines[at], lines[at + 1]))
            at += 2
        at += 1
        choices = []
        while at < len(lines) and lines[at]:
            choices.append(lines[at])
            at += 2 + len(slaves)
        if not choices or not all(where(choice) in gone for choice in choices):
            continue
        for name, link in [(db.name, master_link), *slaves]:
            for path in (ALTERNATIVES / name, Path(link)):
                if path.is_symlink():
                    path.unlink()
        db.unlink()
        dropped.append(db.name)
    return dropped


def purge_packages() -> None:
    entries = stanzas()
    names = {name for name, _ in entries}
    missing = [package for package in PURGE if package not in names]
    if missing:
        fail(
            "not installed: " + ", ".join(missing) + ". The base image moved; review PURGE "
            "(a renamed package, such as a new libapt-pkg, belongs in it)"
        )
    purge = set(PURGE)
    if diverted := diverted_by(purge):
        fail("a package being purged diverts " + ", ".join(diverted))

    # Nothing a staying package lists is touched: shared folders, mostly.
    keep: set[str] = set()
    for name in names - purge:
        keep.update(where(path) for path in listed(name, required=False))
    gone: set[str] = set()
    folders: set[str] = set()
    for package in PURGE:
        for path in listed(package):
            place = where(path)
            if place in keep:
                continue
            if os.path.isdir(place) and not os.path.islink(place):
                folders.add(place)
                continue
            gone.add(place)
            if os.path.lexists(place):
                os.unlink(place)
    for folder in sorted(folders, key=lambda f: f.count("/"), reverse=True):
        if os.path.isdir(folder) and not os.listdir(folder):
            os.rmdir(folder)

    dropped = drop_alternatives(gone)
    for package in PURGE:
        for record in info_files(package):
            record.unlink()
    kept = [text for name, text in entries if name not in purge]
    fresh = STATUS.with_name("status.image-strip")
    fresh.write_text("\n\n".join(kept) + "\n", encoding="utf-8")
    fresh.chmod(0o644)
    os.replace(fresh, STATUS)
    say(
        f"purged {len(PURGE)} packages ({', '.join(PURGE)}): {len(gone)} files"
        + (f", alternatives {', '.join(dropped)}" if dropped else "")
        + f"; {len(kept)} packages stay in {STATUS}"
    )


# --- 3. What only the removed tools read -----------------------------------------


def tidy() -> None:
    for name in TOOL_STATE:
        path = Path(name)
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        elif path.exists() or path.is_symlink():
            path.unlink()
    for name in ("/etc/shells", "/var/lib/shells.state"):
        path = Path(name)
        if path.exists():
            lines = path.read_text(encoding="utf-8").splitlines()
            kept = [line for line in lines if line.startswith("#") or os.path.exists(line.strip())]
            path.write_text("".join(line + "\n" for line in kept), encoding="utf-8")
    no_login = next((path for path in NO_LOGIN if os.path.exists(path)), "")
    if not no_login:
        fail("none of " + ", ".join(NO_LOGIN) + " is left for an account whose shell is gone")
    passwd = Path("/etc/passwd")
    rows = []
    for line in passwd.read_text(encoding="utf-8").splitlines():
        fields = line.split(":")
        if len(fields) == 7 and fields[6] and not os.path.exists(fields[6]):
            fields[6] = no_login
        rows.append(":".join(fields))
    passwd.write_text("".join(row + "\n" for row in rows), encoding="utf-8")


def set_id_entries(root: str = "/") -> list[str]:
    """Every file or folder under `root` with a setuid or setgid bit, on `root`'s
    own filesystem only: a build's /proc, /sys, /dev and its bind mounts (this
    script, /etc/hosts) are not the image. Links carry no mode of their own."""
    device = os.lstat(root).st_dev
    found = []
    for folder, folders, files in os.walk(root):
        kept = []
        for name in folders:
            if os.lstat(os.path.join(folder, name)).st_dev == device:
                kept.append(name)
        folders[:] = kept
        for name in [*folders, *files]:
            path = os.path.join(folder, name)
            info = os.lstat(path)
            if info.st_dev == device and not stat.S_ISLNK(info.st_mode) and info.st_mode & SET_ID:
                found.append(path)
    if os.lstat(root).st_mode & SET_ID:
        found.append(root)
    return sorted(found)


def clear_set_id_bits(root: str = "/") -> list[str]:
    cleared = set_id_entries(root)
    for path in cleared:
        os.chmod(path, stat.S_IMODE(os.lstat(path).st_mode) & ~SET_ID)
    if cleared:
        say("cleared the setuid or setgid bit on " + ", ".join(cleared))
    return cleared


def refuse_set_id(root: str = "/") -> None:
    if left := set_id_entries(root):
        fail("still setuid or setgid: " + ", ".join(left))


# --- 4. The result -------------------------------------------------------------


def check() -> None:
    left = []
    for folder in PATH_FOLDERS:
        if not os.path.isdir(folder):
            continue
        for name in os.listdir(folder):
            if name in FORBIDDEN or name.startswith(FORBIDDEN_PREFIXES):
                left.append(os.path.join(folder, name))
    if left:
        fail("still on the PATH: " + ", ".join(sorted(left)))
    still = sorted({name for name, _ in stanzas()} & set(PURGE))
    if still:
        fail("still in dpkg's status: " + ", ".join(still))
    if any(info_files(package) for package in PURGE):
        fail("a purged package still has files in " + str(INFO))
    importlib.invalidate_caches()
    for name in (*PYTHON_INSTALLERS, "ensurepip", "pkg_resources"):
        if installed(name) or importlib.util.find_spec(name) is not None:
            fail(f"Python can still find {name}")
    refuse_set_id()
    if not os.access(sys.executable, os.X_OK):
        fail(f"{sys.executable} is gone; Python stays")
    say("no shell, package manager, network tool, perl, Python installer or setuid or "
        "setgid file is left")


def main() -> int:
    if os.geteuid() != 0:
        fail("run it as the build's root, before USER")
    strip_python_installers()
    purge_packages()
    tidy()
    clear_set_id_bits()
    check()
    return 0


if __name__ == "__main__":
    sys.exit(main())
