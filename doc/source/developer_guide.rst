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


Coverage
=========

Code coverage numbers on the ``mqtt-codec`` are normally above 90%.
This by itself does not guarantee correctness but it does provide some
safety when making code changes.

.. code-block:: bash

    $ dnf install python2-pytest python2-pytest-cov
    $ py.test --cov=mqtt_codec tests/
    $

It is hard to drive coverage numbers higher because the code is written
using a "fail-fast" style.  There are many code paths that are
indicative of programming errors and therefore purposely panic.  There
is not way for unit tests to hit these code paths so library test
coverage will never be 100%.


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


.. include:: ../../CONTRIBUTING.rst

.. The project will eventually track requirements using a project like
   `Pipfile <https://github.com/pypa/pipfile>`_.
