"""Run pylint."""

import os.path
import re
import shutil
import subprocess
import sys
import unittest
from pkg_resources import get_distribution, DistributionNotFound
from .. import no_less_than

CONFIG = os.path.join(os.path.dirname(__file__), "pylint.conf")


def _pylint_older_than(version):
    """
    version should be in the form "x.y.z"
    """
    output = subprocess.run(
        ["pylint", "--version"], capture_output=True, check=False
    )
    if output.stderr:
        return True
    match = re.match(
        r"pylint (\d+\.\d+\.\d+).*", output.stdout.decode("utf-8")
    )
    if not match:
        return True
    for requested, actual in zip(version.split("."), match[1].split(".")):
        if int(actual) < int(requested):
            return True
    return False


astroid_version = "0.0.0"
try:
    vermatch = re.match(r"[\.\d]*", get_distribution("astroid").version)
    if vermatch is not None:
        astroid_version = ".".join(vermatch.group().split("."))
except DistributionNotFound:
    pass


# Astroid bug https://github.com/PyCQA/astroid/issues/1856
# reported fixed by https://github.com/PyCQA/astroid/pull/1866
# version starting from 2.12.13 is usable again.
@unittest.skipIf(
    _pylint_older_than("2.12.3")
    or (
        no_less_than(astroid_version)("2.12.0")
        and no_less_than("2.12.13")(astroid_version)
    ),
    "pylint older than 2.12.2 (bookworm) or astroid is version 2.12",
)
class PylintStyleChecker(unittest.TestCase):
    def test_pylint(self):
        """Test: Run pylint on Python source code."""
        if not shutil.which("pylint"):
            self.fail("pylint not installed.")

        cmd = [
            sys.executable,
            "-m",
            "pylint",
            "--jobs=0",
            "--rcfile=" + CONFIG,
            "statichcpd",
        ]
        output = subprocess.run(cmd, capture_output=True, check=False)

        if output.returncode != 0:
            # Strip trailing summary (introduced in pylint 1.7). This summary might look like:
            #
            # ------------------------------------
            # Your code has been rated at 10.00/10
            #
            out = re.sub(
                "^(-+|Your code has been rated at .*)$",
                "",
                output.stdout.decode(),
                flags=re.MULTILINE,
            ).rstrip()

            # Strip logging of used config file (introduced in pylint 1.8)
            err = re.sub(
                "^Using config file .*\n", "", output.stderr.decode()
            ).rstrip()

            msgs = []
            if err:
                msgs.append(
                    f"pylint exited with code {output.returncode} "
                    f"and has unexpected output on stderr:\n{err}"
                )
            if out:
                msgs.append(f"pylint found issues:\n{out}")
            if not msgs:
                msgs.append(
                    f"pylint exited with code {output.returncode} "
                    "and has no output on stdout or stderr."
                )
            self.fail("\n".join(msgs))
