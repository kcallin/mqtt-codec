================
Developer Guide
================

The developer's guide is for a person who wants to change and contribute
changes to `mqtt-codec`.  It builds on information in :doc:`user_guide`.


Uncontrolled Builds
====================

Uncontrolled source builds are created in the standard python fashion:

.. code-block:: none

    $ python setup.py sdist
    running sdist
    running egg_info
    writing requirements to mqtt_codec.egg-info/requires.txt
    writing mqtt_codec.egg-info/PKG-INFO
    writing top-level names to mqtt_codec.egg-info/top_level.txt
    writing dependency_links to mqtt_codec.egg-info/dependency_links.txt
    reading manifest file 'mqtt_codec.egg-info/SOURCES.txt'
    writing manifest file 'mqtt_codec.egg-info/SOURCES.txt'
    running check
    creating mqtt-codec-0.1.0-uncontrolled-20180907
    creating mqtt-codec-0.1.0-uncontrolled-20180907/mqtt_codec
    creating mqtt-codec-0.1.0-uncontrolled-20180907/mqtt_codec.egg-info
    [... removed for brevity ...]
    copying tests/test_reactor.py -> mqtt-codec-0.1.0-uncontrolled-20180907/tests
    copying tests/test_scheduler.py -> mqtt-codec-0.1.0-uncontrolled-20180907/tests
    Writing mqtt-codec-0.1.0-uncontrolled-20180907/setup.cfg
    creating dist
    Creating tar archive
    removing 'mqtt-codec-0.1.0-uncontrolled-20180907' (and everything under it)
    $ ls dist
    mqtt-codec-0.1.0-uncontrolled-20180907.tar.gz
    $

The output artifact has the word "uncontrolled" along with a build date
so that users will know the artifact is not a release or from a
continuous integration build server.


Tests
======

The `mqtt-codec` library comes with a battery of tests.

The built-in automated tests can be run from the command-line
using ``setup.py``.

.. code-block:: none

    $ python setup.py test
    $


Coverage
=========

Test coverage is monitored using
`coverage.py <https://coverage.readthedocs.io>`_ version 4.5 or higher.
Normally this can be installed through your operating system's package
manager (like rpm or apt-get) or by using `pip`.  A coverage
configuration file is included at `.coveragerc` and the tool can be run
in this fashion:

.. code-block:: none

    $ coverage run setup.py test
    running test
    running egg_info
    writing requirements to mqtt_codec.egg-info/requires.txt
    writing mqtt_codec.egg-info/PKG-INFO
    writing top-level names to mqtt_codec.egg-info/top_level.txt
    writing dependency_links to mqtt_codec.egg-info/dependency_links.txt
    reading manifest file 'mqtt_codec.egg-info/SOURCES.txt'
    writing manifest file 'mqtt_codec.egg-info/SOURCES.txt'
    running build_ext
    test_read_after_close (tests.test_io.TestBytesReader) ... ok
    test_body_underflow (tests.test_io.TestDecodeBytes) ... ok
    [... removed for brevity...]
    test_subscribe (tests.test_mqtt.TestUnsubscribe) ... ok
    test_decode_encode (tests.test_mqtt.TestUtf8Codec) ... ok
    test_encode_max_len_utf8 (tests.test_mqtt.TestUtf8Codec) ... ok
    test_encode_too_long_utf8 (tests.test_mqtt.TestUtf8Codec) ... ok

    ----------------------------------------------------------------------
    Ran 48 tests in 0.014s

    OK
    $ coverage report
    Name                     Stmts   Miss Branch BrPart  Cover
    ----------------------------------------------------------
    mqtt_codec/__init__.py       0      0      0      0   100%
    mqtt_codec/io.py           162      4     32      1    97%
    mqtt_codec/packet.py       587     40    110     27    89%
    ----------------------------------------------------------
    TOTAL                      749     44    142     28    91%


Docstrings
===========

Python source code is documented according to the the numpy
documentation standard at
https://numpydoc.readthedocs.io/en/latest/format.html.


Documentation
==============

The documentation for ``mqtt-codec`` is created with
`Sphinx <http://www.sphinx-doc.org/>`_ and is build the fashion usual to
that framework:

.. code-block:: bash

   $ cd doc
   $ make html
   $


The documentation contains doctests which can be verified in this
fashion:

.. code-block:: none

   $ make doctest
   Running Sphinx v1.7.7
   loading pickled environment... done
   building [mo]: targets for 0 po files that are out of date
   building [doctest]: targets for 5 source files that are out of date
   updating environment: 0 added, 1 changed, 0 removed
   reading sources... [100%] user_guide
   looking for now-outdated files... none found
   pickling environment... done
   checking consistency... done
   running tests...

   Document: user_guide
   --------------------
   1 items passed all tests:
   14 tests in default
   14 tests in 1 items.
   14 passed and 0 failed.
   Test passed.

   Doctest summary
   ===============
      14 tests
       0 failures in tests
       0 failures in setup code
       0 failures in cleanup code
   build succeeded.

   Testing of doctests in the sources finished, look at the results in build/doctest/output.txt.

As suggested by the text, the output can be found in ``build/doctest/output.txt``.


.. include:: ../../CONTRIBUTING.rst

.. The project will eventually track requirements using a project like
   `Pipfile <https://github.com/pypa/pipfile>`_.
