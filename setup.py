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

setup(
    name="mqtt-codec",
    version="0.1.0",
    install_requires=[
        'enum34>=1.1.6;python_version<"3.4"',
    ],
    tests_require = [
        'mock',
    ],
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
    ],
    test_suite="tests",
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
    python_requires='==2.7.*',
)

