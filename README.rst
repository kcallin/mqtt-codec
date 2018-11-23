===========
mqtt-codec
===========

A weapons grade MQTT packet encoder and decoder (codec).

Status
=======

The `mqtt-codec` package is an MQTT packet encoder and decoder (codec).
The library has high test coverage (~94%) and is known to perform well
in distributed IoT networks with thousands of nodes.


Installation
=============

The mqtt-codec package can be from `<pypi.org>`_ with
`pip <https://pypi.org/project/pip/>`_:

.. code-block:: bash

   pip install mqtt-codec

Installations can also be performed from source in the traditional
manner:

.. code-block:: bash

   python setup.py install


Python Requirements
====================

The ``mqtt-codec`` project has been tested on Linux against these
environments:

* Python 2.7
* Python 3.4
* Python 3.5
* Python 3.6
* Python 3.7

Python versions Python 3.0 - 3.3 may work but are not tested as part of
the project continuous integration infrastructure.


Library Requirements
=====================

When running Python versions less than 3.4 the ``enum34`` package is
required.  There are no other package requirements.


Project Infrastructure
=======================

The project is coordinated through public infrastructure available at
several places:

* `Releases (pypi) <https://pypi.org/project/mqtt-codec>`_
* `Documentation (readthedocs.io) <https://mqtt-codec.readthedocs.io/en/latest/>`_
* `Bug Tracker (github) <https://github.com/kcallin/mqtt-codec/issues>`_
* `Code Repository (github) <https://github.com/kcallin/mqtt-codec>`_
