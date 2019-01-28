.. mqtt-codec documentation master file, created by
   sphinx-quickstart on Sun Sep 30 09:27:27 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

==================================
mqtt-codec Package Documentation
==================================

The `mqtt-codec` package is an MQTT packet encoder and decoder (codec).
The library has high test coverage (~94%) and is known to perform well
in distributed IoT networks with thousands of nodes.

Installation
=============

The mqtt-codec package is distributed through
`pypi.org <https://pypi.org>`_ and can be installed with the standard
Python package manager `pip <https://pip.pypa.io/en/stable/>`_:

.. code-block:: bash

   $ pip install mqtt-codec

If you do not have pip then the package can be downloaded from
`mqtt-codec <https://pypi.org/project/mqtt-codec>`_ and installed with
the standard `setup.py` method:

.. code-block:: bash

   $ python setup.py install


Project Infrastructure
=======================

The project is coordinated through public infrastructure:

* `Releases (pypi) <https://pypi.org/project/mqtt-codec>`_
* `Documentation (readthedocs.io) <https://mqtt-codec.readthedocs.io/en/latest/>`_
* `Bug Tracker (github) <https://github.com/kcallin/mqtt-codec/issues>`_
* `Code Repository (github) <https://github.com/kcallin/mqtt-codec>`_


Table of Contents
==================
.. toctree::
   :maxdepth: 2
   :caption: Contents:

   user_guide
   mqtt_codec
   changelog
   developer_guide
   admin


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
