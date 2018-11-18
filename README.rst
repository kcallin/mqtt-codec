===========
mqtt-codec
===========

A thorough implementation of an MQTT Packet parser.

Status
=======

The project's ambition is to be thorough implementation of an MQTT
packet parser.  This ambition has not yet been realized and the project
is not ready for public consumption (2018-09-30).


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
