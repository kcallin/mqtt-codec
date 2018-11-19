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

Although not tested the codec likely works on Python 3.0 - 3.3.
Standard docker containers for these Python versions don't yet exist
and so they have not yet been tested.


Library Requirements
=====================

When running Python versions less than 3.4 the ``enum34`` pacakge is
required.  Besides there are no other required packages.


Project Infrastructure
=======================

The project is coordinated through public infrastructure available at
several places:

* `Releases <https://pypi.org/project/mqtt-codec>`_
* `Documentation <https://mqtt-codec.readthedocs.io/en/latest/>`_
* `Bug Tracker <https://github.com/kcallin/mqtt-codec/issues>`_
* `Code Repository <https://github.com/kcallin/mqtt-codec>`_
