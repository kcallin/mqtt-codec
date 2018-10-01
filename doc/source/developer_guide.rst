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


Contributing Changes
=====================

.. Adapted from http://wiki.eclipse.org/Development_Resources/Contributing_via_Git#The_Commit_Record

Minimally, your git commit record must have the following:

1. Your name and e-mail address captured in the "Author" field.
2. A single line summary in the message field followed by a more
   detailed description.
3. A "Signed-off-by" entry with matching credentials in the message
   footer.

If the commit fixes a bug then a link should be included in the message
footer.  The id (bug number) of the bug should also be included in the
message summary.

You can specify additional authors using one or more "Also-by" entries
in the message footer.

For example:

::

    commit 862e6ff22ad56c10df6de3385ffa4c7d02363d1d
    Author: Joe Somebody <somebody@someplace.net>
    Date:   Mon Jun 17 17:19:38 2013 -0700

        [410937] Auto share multiple projects in single job

        When multiple projects are imported together, perform all the necessary
        auto shares in a single job rather than spawning a separate job for each
        project.

        Bug: https://bugs.eclipse.org/bugs/show_bug.cgi?id=410937
        Also-by: Some Otherperson <otherperson@someplace.net>
        Signed-off-by: Joe Somebody <somebody@someplace.net>

The "Signed-off-by" entry is required. By including this, you confirm
that you are in compliance with the Certificate of Origin described in
the ECA document.

Note that the footer entries must occur at the bottom of the commit
message and must not include any blank lines.

Signing off on a commit
========================

Git contains built-in support for signing off on a commit.

From command-line `git`, add -s to the command:

.. code-block:: none

   $ git commit -s --gpg-sign[=<keyid>] -m "Auto share multiple projects in single job"

.. The project will eventually track requirements using a project like
   `Pipfile <https://github.com/pypa/pipfile>`_.
