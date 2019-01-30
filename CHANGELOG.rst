===========
Change Log
===========


1.0.2 (2019-01-27)
===================

Fix
----
#5: QoS=0 publish messages incorrectly read/write packet_id.

    In Publish messages with QoS=0, packet_id is being serialized and
    deserialized in violation of MQTT 3.1.1 spec (See 3.3.2.2).

    https://github.com/kcallin/haka-mqtt/issues/5

#6: Corrupt MqttSuback results in non-DecodeError exception.

    While decoding MqttSuback, a corrupted SubscribeResult results in
    a TypeError instead of DecodeError.  This violates the decode
    method's interface spec.

    https://github.com/kcallin/mqtt-codec/issues/6


1.0.1 (2018-11-28)
===================

New
----

#4: MqttConnect.__repr__ has seconds units on keep_alive.

    https://github.com/kcallin/haka-mqtt/issues/21


1.0.0 (2018-11-24)
===================

New
----

* First stable production release.


0.1.3 (2018-11-17)
===================

New
----

* Python 3 support.
* Updating packaging mechanism.


0.1.2 (2018-11-15)
===================

New
----
* Python 3 compatibility.
* MqttConnect object now has read-only attributes.

Fixes
------
#2: MqttPublish.payload somtimes has a type that is not bytes.

    https://github.com/kcallin/mqtt-codec/issues/2


0.1.1 (2018-10-22)
===================
* Documentation improvements.
* MqttConnect.__str__ no longer shows user/pass.
* setup.py:install_requires now compatible with setuptools 18.


0.1.0 (2018-10-03)
===================

Initial release.
