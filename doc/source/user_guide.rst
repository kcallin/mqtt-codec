============
User Guide
============

The `mqtt_codec` package is a stateless package for encoding and
decoding MQTT 3.1.1 packets.

Usage
======

Typical usage of the codec looks like this:

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


Building Documentation
=======================

.. code-block:: none

    $ pip install sphinxcontrib-seqdiag
    $ make html
    $


Semantic Versioning
====================

The `mqtt-codec` package is versioned according to `Semantic Versioning
<https://semver.org>`_ 2.0.0 guidelines.  A summary of SemVer is
included here for your convenience:

    Given a version number MAJOR.MINOR.PATCH, increment the:

    1. MAJOR version when you make incompatible API changes,
    2. MINOR version when you add functionality in a
       backwards-compatible manner, and
    3. PATCH version when you make backwards-compatible bug fixes.

    Additional labels for pre-release and build metadata are available
    as extensions to the MAJOR.MINOR.PATCH format.

    -- Semantic Versioning Summary, <https://semver.org/#summary>, retrieved 2018-10-01.

