from setuptools import setup
from os import path

def load_dependencies():
    with open('requirements.txt') as dependencies:
            return dependencies.read().splitlines()

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst')) as f:
    long_description = f.read()

setup(
    name='animus-omni',
    version = '0.0.2',
    license = 'MIT',
    author = 'Animus Intelligence, LLC',
    author_email = 'info@animus.io',
    description = 'Animus commandline tools to reduce Internet radiation from log files',
    long_description = long_description,
    packages = ['animus', 'animus.LogParsers'],
    scripts = ['omni-reduce'],
    data_files = [('requirements', ['requirements.txt'])],
    py_modules = ['animus'],
    install_requires = load_dependencies(),
    url = 'https://github.com/Animus-Intelligence/omni',
    classifiers = ['Development Status :: 3 - Alpha'],
    )
