from setuptools import setup
from re import findall

with open('debian/changelog', 'r') as clog:
    _, version, _ = findall(
            r'(?P<src>.*) \((?P<version>.*)\) (?P<suite>.*); .*',
            clog.readline().strip())[0]

setup(
    name='statichcpd',
    version=version,
    description='A static DHCP server',
    url='https://gitlab.pb.local/sdn/statichcpd',
    author='Reshma Sreekumar',
    author_email='reshma.sreekumar@cloud.ionos.com',
    packages=['statichcpd'],
    install_requires=['dpkt', 'pyroute2'],
    license='MIT',
    long_description=open('README.md').read(),
)

