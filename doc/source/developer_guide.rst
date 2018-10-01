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
    writing requirements to haka_mqtt.egg-info/requires.txt
    writing haka_mqtt.egg-info/PKG-INFO
    writing top-level names to haka_mqtt.egg-info/top_level.txt
    writing dependency_links to haka_mqtt.egg-info/dependency_links.txt
    reading manifest file 'haka_mqtt.egg-info/SOURCES.txt'
    writing manifest file 'haka_mqtt.egg-info/SOURCES.txt'
    running check
    creating haka-mqtt-0.1.0-uncontrolled-20180907
    creating haka-mqtt-0.1.0-uncontrolled-20180907/haka_mqtt
    creating haka-mqtt-0.1.0-uncontrolled-20180907/haka_mqtt.egg-info
    [... removed for brevity ...]
    copying tests/test_reactor.py -> haka-mqtt-0.1.0-uncontrolled-20180907/tests
    copying tests/test_scheduler.py -> haka-mqtt-0.1.0-uncontrolled-20180907/tests
    Writing haka-mqtt-0.1.0-uncontrolled-20180907/setup.cfg
    creating dist
    Creating tar archive
    removing 'haka-mqtt-0.1.0-uncontrolled-20180907' (and everything under it)
    $ ls dist
    haka-mqtt-0.1.0-uncontrolled-20180907.tar.gz
    $

The output artifact has the word "uncontrolled" along with a build date
so that users will know the artifact is not a release or from a
continuous integration build server.


Docstrings
===========

Python source code is documented according to the the numpy
documentation standard at
https://numpydoc.readthedocs.io/en/latest/format.html.


Documentation
==============

The documentation for `mqtt-codec` is created with
`Sphinx <http://www.sphinx-doc.org/>`_.


.. The project will eventually track requirements using a project like
   `Pipfile <https://github.com/pypa/pipfile>`_.
