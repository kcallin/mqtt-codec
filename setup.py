import sys
from os.path import join, dirname
from setuptools import setup, find_packages


def read_path(filename):
    with open(join(dirname(__file__), filename)) as f:
        return f.read()

# Documentation on this setup function can be found at
#
# https://setuptools.readthedocs.io/en/latest/ (2018-09-04)
#

# PEP 345
# https://www.python.org/dev/peps/pep-0345/

# PEP 440 -- Version Identification and Dependency Specification
# https://www.python.org/dev/peps/pep-0440/


py_version = (sys.version_info.major, sys.version_info.minor)
if py_version < (3, 4):
    install_requires = [
        # Syntax introduced sometime between setuptools-32.1.0 and setuptools-36.7.0
        # 'enum34>=1.1.6;python_version<"3.4"',
        # https://stackoverflow.com/questions/21082091/install-requires-based-on-python-version
        'enum34>=1.1.6',
    ]
else:
    install_requires=[]


setup(
    name="mqtt-codec",
    version="0.1.2",
    install_requires=install_requires,
    tests_require = [],
    classifiers=[  # Optional
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ],
    test_suite="tests",
    use_2to3=True,
    packages=find_packages(),
    author="Keegan Callin",
    author_email="kc@kcallin.net",
#    license="PSF",
#    keywords="hello world example examples",
#    could also include long_description, download_url, classifiers, etc.
    url="https://github.com/kcallin/mqtt-codec",   # project home page
    description="Weapons grade MQTT packet codec.",
    long_description=read_path('README.rst'),
    project_urls={
        "Bug Tracker": "https://github.com/kcallin/mqtt-codec/issues",
        "Documentation": "https://mqtt-codec.readthedocs.io/en/latest/",
        "Source Code": "https://github.com/kcallin/mqtt-codec",
    },
    python_requires='~=2.7,~=3.6',
)
