from os import environ, getcwd
from os.path import join
from pkg_resources import get_distribution, DistributionNotFound
from subprocess import call
from unittest import TestCase, skipUnless, main
from typing import List

mypy_version = 0
try:
    mypy_version = [
        int(x) for x in get_distribution("mypy").version.split(".")[:2]
    ]
except DistributionNotFound:
    pass


class TypeCheckTest(TestCase):
    def __init__(self, *args, **kwargs) -> None:
        self.pkgname = "statichcpd"
        super(TypeCheckTest, self).__init__(*args, **kwargs)
        self.mypy_env: List[str] = environ.copy()
        self.mypy_env.update({"MYPYPATH": "mypystubs"})
        self.mypy_opts: List[str] = ["--strict"]

    # Skip mypy tests specifically for 0.971 version due to the following bug:
    # https://github.com/python/mypy/issues/7604#issuecomment-1249824784
    @skipUnless(mypy_version > [0, 971], "Do not trust earlier mypy versions")
    def test_run_mypy(self):
        mypy_call = (
            ["mypy"] + self.mypy_opts + ["-p", self.pkgname]
        )  # type: List[str]
        result = call(mypy_call, env=self.mypy_env)  # type: int
        self.assertEqual(result, 0, "mypy typecheck")


if __name__ == "__main__":
    main()
