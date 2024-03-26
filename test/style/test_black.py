import glob
import subprocess
import shutil
import sys
import unittest
import re
from pkg_resources import get_distribution, DistributionNotFound

from .. import no_less_than

black_version = "0.0"
try:
    vermatch = re.match(r"[\.\d]*", get_distribution("black").version)
    if vermatch is not None:
        black_version = vermatch.group()
except DistributionNotFound:
    pass


class BlackFormatter(unittest.TestCase):
    @unittest.skipUnless(
        no_less_than("21.1")(black_version),
        "Do not trust earlier black versions",
    )
    def test_black(self):
        if not shutil.which("black"):
            self.fail(f"black not installed.")
        cmd = (
            ["python3", "-m", "black", "--check", "--diff", "-l", "79"]
            + glob.glob("statichcpd/**/*.py", recursive=True)
            + glob.glob("test/**/*.py", recursive=True)
        )
        output = subprocess.run(cmd, capture_output=True)
        if output.returncode == 1:
            self.fail(
                f"black found code that needs reformatting:\n{output.stdout.decode()}"
            )
        if output.returncode != 0:
            self.fail(
                f"black exited with code {output.returncode}:\n{output.stderr.decode()}"
            )
