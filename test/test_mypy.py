from os import environ, getcwd
from os.path import join
from pkg_resources import get_distribution, DistributionNotFound
from subprocess import call
from unittest import TestCase, skipUnless, main
from typing import List

mypy_version = 0
try:
    mypy_version = float(get_distribution("mypy").version)
except DistributionNotFound:
    pass


class TypeCheckTest(TestCase):
    def __init__(self, *args, **kwargs) -> None:
        self.pkgname = "statichcpd"
        super(TypeCheckTest, self).__init__(*args, **kwargs)
        self.mypy_env = environ.copy()
        self.mypy_env.update({"MYPYPATH": join(getcwd(), "mypystubs")})
        self.pypath = self.mypy_env.get("PYTHONPATH", getcwd())  # type: str
        self.mypy_opts = ["--strict"]

    @skipUnless(mypy_version >= 0.67, "Do not trust earlier mypy versions")
    def test_run_mypy(self):
        mypy_call = (
            ["mypy"] + self.mypy_opts + ["-p", self.pkgname]
        )  # type: List[str]
        result = call(mypy_call, env=self.mypy_env)  # type: int
        self.assertEqual(result, 0, "mypy typecheck")


if __name__ == "__main__":
    main()
