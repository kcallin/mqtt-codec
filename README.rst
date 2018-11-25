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

Usage
======

The library can be used like so:

.. doctest::

   >>> from io import BytesIO
   >>> from binascii import b2a_hex
   >>> import mqtt_codec.packet
   >>> import mqtt_codec.io
   >>>
   >>> # Encode a Connect packet
   >>> will = mqtt_codec.packet.MqttWill(qos=0, topic='hello', message='message', retain=True)
   >>> connect = mqtt_codec.packet.MqttConnect(client_id='client_id', clean_session=False, keep_alive=0, will=will)
   >>> f = BytesIO()
   >>> try:
   ...   num_bytes_written = connect.encode(f)
   ...   buf = f.getvalue()
   ... finally:
   ...   f.close()
   ...
   >>> assert len(buf) == num_bytes_written
   >>> print('0x{} ({} bytes)'.format(b2a_hex(buf), len(buf)))
   0x102500044d515454042400000009636c69656e745f6964000568656c6c6f00076d657373616765 (39 bytes)
   >>>
   >>> # Decode the connect packet and assert equality.
   >>> with mqtt_codec.io.BytesReader(buf) as f:
   ...   num_bytes_read, decoded_connect = connect.decode(f)
   ...
   >>> assert len(buf) == num_bytes_written
   >>> assert connect == decoded_connect
   >>> print('  Encoded {}'.format(connect))
     Encoded MqttConnect(client_id='client_id', clean_session=False, keep_alive=0s, username=None, password=None, will=MqttWill(topic=hello, payload=0x6d657373616765, retain=True, qos=0))
   >>> print('= Decoded {}'.format(decoded_connect))
   = Decoded MqttConnect(client_id=u'client_id', clean_session=False, keep_alive=0s, username=None, password=None, will=MqttWill(topic=hello, payload=0x6d657373616765, retain=True, qos=0))


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
