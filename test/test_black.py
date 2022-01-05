import glob
import subprocess
import shutil
import sys
import unittest


class BlackFormatter(unittest.TestCase):
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
