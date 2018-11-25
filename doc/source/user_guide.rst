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


Requirements
=============

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


Package Dependencies
---------------------

When running Python versions less than 3.4 the ``enum34`` pacakge is
required.  Besides there are no other required packages.


Processor and Memory Usage
===========================

The maximum size of an MQTT packet is :const:`mqtt_codec.packet.MqttFixedHeader.MAX_REMAINING_LEN` (=268435455 bytes).
Encoding or decoding an mqtt message may consume up to this many bytes.
Smaller messages require less memory to encode or decode.

While constructing an MQTT packet it is necessary to temporarily encode
it so that the byte size of contained UTF-8 strings can be determined
and the final packet size calculated.  This means that constructing an
MQTT packet can temporarily consume up to
:const:`mqtt_codec.packet.MqttFixedHeader.MAX_REMAINING_LEN` (=268435455 bytes)
of memory and a proportionate amount of processor time.  In practice
most packets tend to be much smaller than this and the processor time
seems small enough for most applications.


Testing and Quality
====================

The `mqtt-codec` package is tested against most use and abuse cases.  It
has proven itself in distributed IoT environments with thousands of
nodes and expected to perform as well or better than most quality
industrial scale systems.  There is a high bar to marking a release as
stable and it usually takes more than a month of field data collection
on a prospective release before this happens.

The codec has not proven itself in hostile and malicious environments
and has not seen thorough 3rd-party review from a security specialist.
If you are interested in assisting then please contact the author,
`Keegan Callin <mailto:kc@kcallin.net>`_.


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


Bugs and Enhancements
======================

As the maintainer of this library I,
`Keegan Callin <mailto:kc@kcallin.net>`_, welcome your polite,
constructive comments and criticisms of this library at the
`github issue tracker <https://github.com/kcallin/mqtt-codec/issues>`_.
