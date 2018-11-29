=======================
Project Administration
=======================

The release procedure was created using information from these core sources:

* `PEP 503 - Simple Repository API <https://www.python.org/dev/peps/pep-0503/>`_
* `Python Packaging User Guide <https://packaging.python.org/>`_
* `Twine <https://pypi.org/project/twine/>`_


Test Release
=============

Verify that version and release numbers in ``doc/source/conf.py`` match
``setup.py``.

.. code-block:: bash

    $ grep -e version -e release doc/source/conf.py
    # The short X.Y version
    version = u'1.0.0'
    # The full version, including alpha/beta/rc tags
    release = u'1.0.0'
    $


Ensure there are no old build artifacts.

.. code-block:: bash

    $ rm dist/*
    $ ls dist
    $


It's a common problem to accidentally forget to commit important
changes.  To combat this the ``pyvertest.py`` procedure clones the haka
repository, passes it to a docker container, and runs a test battery in
a set of environments.

.. code-block:: none

    $ ./pyvertest.py
    [... removed for brevity ...]
    pip install python:3.7-alpine3.8
    docker run --rm -v /home/kcallin/src/mqtt-codec:/mqtt-codec python:3.7-alpine3.8 pip install /mqtt-codec
    Processing /mqtt-codec
    Building wheels for collected packages: mqtt-codec
      Running setup.py bdist_wheel for mqtt-codec: started
      Running setup.py bdist_wheel for mqtt-codec: finished with status 'done'
      Stored in directory: /root/.cache/pip/wheels/c1/64/0f/d02b6f3717526372cf5d4a5beb9b63181eb54bd4ed964fa7e1
    Successfully built mqtt-codec
    Installing collected packages: mqtt-codec
    Successfully installed mqtt-codec-1.0.0-uncontrolled-20181125
    Return code 0
    > All okay.


Ensure that CHANGELOG.rst has release version and release date correct
as well as release content listed.

.. code-block:: bash

    $ vi CHANGELOG.rst
    $ git commit -S CHANGELOG.rst


Create test release artifacts.

.. code-block:: none

    $ python setup.py egg_info -D -b 'test' sdist
    running sdist
    running egg_info
    writing requirements to mqtt_codec.egg-info/requires.txt
    writing mqtt_codec.egg-info/PKG-INFO
    writing top-level names to mqtt_codec.egg-info/top_level.txt
    writing dependency_links to mqtt_codec.egg-info/dependency_links.txt
    reading manifest file 'mqtt_codec.egg-info/SOURCES.txt'
    writing manifest file 'mqtt_codec.egg-info/SOURCES.txt'
    running check
    creating mqtt-codec-0.1.2
    creating mqtt-codec-0.1.2/mqtt_codec
    [... removed for brevity ...]
    copying tests/test_reactor.py -> mqtt-codec-0.1.2/tests
    copying tests/test_scheduler.py -> mqtt-codec-0.1.2/tests
    Writing mqtt-codec-0.1.2/setup.cfg
    Creating tar archive
    removing 'mqtt-codec-0.1.2' (and everything under it)
    $ ls dist
    mqtt-codec-0.1.2.tar.gz
    $


GPG sign test release artifact:

.. code-block:: none

    $ gpg --detach-sign -a dist/mqtt-codec-0.1.2.tar.gz

    You need a passphrase to unlock the secret key for
    user: "Keegan Callin <kc@kcallin.net>"
    4096-bit RSA key, ID DD53792F, created 2017-01-01 (main key ID 14BC2EFF)

    gpg: gpg-agent is not available in this session
    $ ls dist
    mqtt-codec-0.1.2.tar.gz  mqtt-codec-0.1.2.tar.gz.asc
    $ gpg --verify dist/mqtt-codec-0.1.2.tar.gz.asc
    gpg: assuming signed data in `dist/mqtt-codec-0.1.2.tar.gz'
    gpg: Signature made Sat 01 Sep 2018 11:00:31 AM MDT using RSA key ID DD53792F
    gpg: Good signature from "Keegan Callin <kc@kcallin.net>" [ultimate]
    Primary key fingerprint: BD51 01F1 9699 A719 E563  6D85 4A4A 7B98 14BC 2EFF
         Subkey fingerprint: BE56 D781 0163 488F C7AE  62AC 3914 0AE2 DD53 792F
    $


.. https://packaging.python.org/guides/making-a-pypi-friendly-readme/#validating-restructuredtext-markup
   (Retrieved 2018-11-28)

Ensure that twine version 1.12.0 or high is installed:

.. code-block:: none

    $ twine --version
    twine version 1.12.0 (pkginfo: 1.4.2, requests: 2.20.1, setuptools: 40.6.2,
    requests-toolbelt: 0.8.0, tqdm: 4.28.1)


Verify that distribution passes twine checks:

.. code-block:: none

    $ twine check dist/*
    Checking distribution dist/mqtt-codec-1.0.1.tar.gz: Passed


Release artifacts to **TEST** PyPI.

.. code-block:: none

    $ twine upload --repository-url https://test.pypi.org/legacy/ dist/*
    Uploading distributions to https://test.pypi.org/legacy/
    Enter your username: kc
    Enter your password:
    Uploading mqtt-codec-0.1.2.tar.gz
    $


The resulting entry should be inspected for correctness.  "The database
for TestPyPI may be periodically pruned, so it is not unusual for user
accounts to be deleted [#]_".  Packages on **TEST** PyPI and **real**
PyPI cannot be removed upon distributor demand.  On **TEST** PyPI
packages may be removed on prune, on **real** PyPI they will remain
forever.  A checklist to help verify the PyPI release page follows:

* Version Number is Correct
* Documentation Link is Correct
* ReST README.rst is rendered correctly on the front page.


After the checklist is complete then it is time to upload to **real**
PyPI and verify that the release is complete.  There is no undoing
this operation.  Think Carefully.


PEP 508 -- Dependency specification for Python Software Packages

PEP-314 -- Metadata for Python Software Packages v1.1

.. [#] `Test PyPI, Registering Your Account <https://packaging.python.org/guides/using-testpypi/#registering-your-account>`_,
       retrieved 2018-09-07.


Official Release
=================

Create, sign, and push release tag:

.. code-block:: bash

    $ git tag -s v0.1.0
    $ git push origin v0.1.0


Remove test artifacts:

.. code-block:: bash

    $ rm dist/*
    $ ls dist
    $


Create official release artifacts.

.. code-block:: none

    $ python setup.py egg_info -D -b '' sdist
    running sdist
    running egg_info
    writing requirements to mqtt_codec.egg-info/requires.txt
    writing mqtt_codec.egg-info/PKG-INFO
    writing top-level names to mqtt_codec.egg-info/top_level.txt
    writing dependency_links to mqtt_codec.egg-info/dependency_links.txt
    reading manifest file 'mqtt_codec.egg-info/SOURCES.txt'
    writing manifest file 'mqtt_codec.egg-info/SOURCES.txt'
    running check
    creating mqtt-codec-0.1.2
    creating mqtt-codec-0.1.2/mqtt_codec
    [... removed for brevity ...]
    copying tests/test_reactor.py -> mqtt-codec-0.1.2/tests
    copying tests/test_scheduler.py -> mqtt-codec-0.1.2/tests
    Writing mqtt-codec-0.1.2/setup.cfg
    Creating tar archive
    removing 'mqtt-codec-0.1.2' (and everything under it)
    $ ls dist
    mqtt-codec-0.1.2.tar.gz
    $


GPG sign official release artifact:

.. code-block:: none

    $ gpg --detach-sign -a dist/mqtt-codec-0.1.2.tar.gz

    You need a passphrase to unlock the secret key for
    user: "Keegan Callin <kc@kcallin.net>"
    4096-bit RSA key, ID DD53792F, created 2017-01-01 (main key ID 14BC2EFF)

    gpg: gpg-agent is not available in this session
    $ ls dist
    mqtt-codec-0.1.2.tar.gz  mqtt-codec-0.1.2.tar.gz.asc
    $ gpg --verify dist/mqtt-codec-0.1.2.tar.gz.asc
    gpg: assuming signed data in `dist/mqtt-codec-0.1.2.tar.gz'
    gpg: Signature made Sat 01 Sep 2018 11:00:31 AM MDT using RSA key ID DD53792F
    gpg: Good signature from "Keegan Callin <kc@kcallin.net>" [ultimate]
    Primary key fingerprint: BD51 01F1 9699 A719 E563  6D85 4A4A 7B98 14BC 2EFF
         Subkey fingerprint: BE56 D781 0163 488F C7AE  62AC 3914 0AE2 DD53 792F
    $


The access credentials in `~/.pypirc` contains the username/password
that twine uses for PyPI.

.. code-block:: none

    $ cat ~/.pypirc
    [distutils]
    index-servers =
        pypi

    [pypi]
    username:<XXXXXX>
    password:<XXXXXX>
    $ twine upload dist/*


Distribute Documentation
===========================

Documentation is distributed through
`readthedocs.org <https://mqtt-codec.readthedocs.io/en/latest>`_.  After
a release visit the
`mqtt-codec readthedocs Version <https://readthedocs.org/projects/mqtt-codec/versions/>`_,
page and make sure the correct versions are marked as "Active".

The ``mqtt-codec`` project documentation uses
`PlantUML <https://pypi.org/project/plantuml/>`_ to draw diagrams and
this package is not support out-of-the-box by `readthedocs`.  The
project root directory contains a ``.readthedocs.yml`` file to set the
build `readthedocs` build environment to one that supports PlantUML and
bypass the problem.


Increment Version Number
=========================

The release number in `setup.py` has been consumed and should never be
used again.  Take the time to increment the number, commit the change,
then push the change.

.. code-block:: none

    $ vi setup.py
    $ vi doc/source/conf.py
    $ git commit setup.py
    $ git push origin master
