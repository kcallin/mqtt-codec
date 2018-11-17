=======================
Project Administration
=======================

The release procedure was created using information from these core sources:

* `PEP 503 - Simple Repository API <https://www.python.org/dev/peps/pep-0503/>`_
* `Python Packaging User Guide <https://packaging.python.org/>`_
* `Twine <https://pypi.org/project/twine/>`_


Build Release
==============

Verify that version and release numbers in ``doc/source/conf.py`` match
``setup.py``.

.. code-block:: bash

    $ grep -e version -e release doc/source/admin.rst
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

Verify all tests pass.

.. code-block:: none

    $ python setup.py test
    running test
    running egg_info
    creating mqtt_codec.egg-info
    writing requirements to mqtt_codec.egg-info/requires.txt
    writing mqtt_codec.egg-info/PKG-INFO
    writing top-level names to mqtt_codec.egg-info/top_level.txt
    writing dependency_links to mqtt_codec.egg-info/dependency_links.txt
    writing manifest file 'mqtt_codec.egg-info/SOURCES.txt'
    reading manifest file 'mqtt_codec.egg-info/SOURCES.txt'
    writing manifest file 'mqtt_codec.egg-info/SOURCES.txt'
    running build_ext
    test_0 (tests.test_mqtt.TestCodecVarInt) ... ok
    test_127 (tests.test_mqtt.TestCodecVarInt) ... ok
    test_2097151 (tests.test_mqtt.TestCodecVarInt) ... ok
    [... removed for brevity ...]
    test_decode_encode (tests.test_mqtt.TestUtf8Codec) ... ok
    test_encode_max_len_utf8 (tests.test_mqtt.TestUtf8Codec) ... ok
    test_encode_too_long_utf8 (tests.test_mqtt.TestUtf8Codec) ... ok

    ----------------------------------------------------------------------
    Ran 31 tests in 0.003s

    OK

Create, sign, and push release tag:

.. code-block:: bash

    $ git tag -s v0.1.0
    $ git push origin v0.1.0

It's a common problem to accidentally forget to commit important
changes.  To combat this:

1. Clone repository from github.
2. Checkout the release tag into a temporary directory.
3. Verify that the temporary directory and your working directory do not
   differ in any significant detail.

.. code-block:: bash

    $ work_dir="$(pwd)"
    $ temp_dir="$(mktemp -d --suffix=-mqtt-codec)"
    $ cd "${temp_dir}"
    $ git clone git@github.com:kcallin/mqtt-codec.git .
    $ git checkout <release-tag>
    $ python setup.py test
    $ diff -ur -x .git -x '*.pyc' "${work_dir}" "${temp_dir}/mqtt-codec"

Create release build artifacts.

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

Distribute Release
=====================

GPG signatures are created for release artifacts.

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


Test Release
-------------

Release artifacts are uploaded to **TEST** PyPI.

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

Release
--------

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

PEP 508 -- Dependency specification for Python Software Packages

PEP-314 -- Metadata for Python Software Packages v1.1

.. [#] `Test PyPI, Registering Your Account <https://packaging.python.org/guides/using-testpypi/#registering-your-account>`_,
       retrieved 2018-09-07.


Distribute Documentation
===========================

.. code-block:: none

    $ pip install sphinxcontrib-seqdiag
    $ make html
    $

Increment Version Number
=========================

The release number in `setup.py` has been consumed and should never be
used again.  Take the time to increment the number, commit the change,
then push the change.

.. code-block:: none

    $ vi setup.py
    $ git commit setup.py
    $ git push origin master
