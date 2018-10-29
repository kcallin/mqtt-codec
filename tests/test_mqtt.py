import struct
import unittest
from io import BytesIO
from struct import Struct

import mqtt_codec.io
import mqtt_codec.packet
from mqtt_codec.packet import (
    MqttControlPacketType,
    MqttFixedHeader,
)
from mqtt_codec.io import BytesReader
from binascii import a2b_hex


class TestDecodeFixedHeader(unittest.TestCase):
    def test_decode_zero_nrb(self):
        buf = bytearray(a2b_hex('c000'))
        num_bytes_consumed, h = mqtt_codec.packet.MqttFixedHeader.decode(BytesReader(buf))
        self.assertEqual(h.remaining_len, 0)
        self.assertEqual(2, num_bytes_consumed)

    def test_decode_one_nrb(self):
        buf = bytearray(a2b_hex('c001'))
        num_bytes_consumed, h = mqtt_codec.packet.MqttFixedHeader.decode(BytesReader(buf))
        self.assertEqual(h.remaining_len, 1)
        self.assertEqual(2, num_bytes_consumed)

    def test_underflow_0(self):
        buf = b''
        self.assertRaises(mqtt_codec.io.UnderflowDecodeError, mqtt_codec.packet.MqttFixedHeader.decode, BytesReader(buf))

    def test_remaining_len_too_large(self):
        self.assertRaises(mqtt_codec.io.OversizePacketEncodeError,
                          MqttFixedHeader,
                          MqttControlPacketType.pingreq,
                          0,
                          MqttFixedHeader.MAX_REMAINING_LEN + 1)


class TestCodecVarInt(unittest.TestCase):
    def assert_codec_okay(self, n, buf):
        bio = BytesIO()
        expected_buf = a2b_hex(buf)

        num_bytes_written = mqtt_codec.io.encode_varint(n, bio)
        actual_buf = bio.getvalue()
        self.assertEqual(expected_buf, actual_buf)
        self.assertEqual(num_bytes_written, len(actual_buf))

        bio.seek(0)
        self.assertEqual((len(actual_buf), n), mqtt_codec.io.decode_varint(bio))

    def test_0(self):
        self.assert_codec_okay(0, '00')

    def test_127(self):
        self.assert_codec_okay(127, '7f')

    def test_128(self):
        self.assert_codec_okay(128, '8001')

    def test_16383(self):
        self.assert_codec_okay(16383, 'ff7f')

    def test_16384(self):
        self.assert_codec_okay(16384, '808001')

    def test_2097151(self):
        self.assert_codec_okay(2097151, 'ffff7f')

    def test_2097152(self):
        self.assert_codec_okay(2097152, '80808001')

    def test_268435455(self):
        self.assert_codec_okay(268435455, 'ffffff7f')

    def test_underflow_zero_bytes(self):
        bio = BytesIO()
        self.assertRaises(mqtt_codec.io.UnderflowDecodeError, mqtt_codec.io.decode_varint, bio)

    def test_mid_underflow(self):
        bio = BytesIO(a2b_hex('808080'))
        self.assertRaises(mqtt_codec.io.UnderflowDecodeError, mqtt_codec.io.decode_varint, bio)

    def test_decode_error_too_big(self):
        bio = BytesIO(a2b_hex('ffffffff'))
        self.assertRaises(mqtt_codec.io.DecodeError, mqtt_codec.io.decode_varint, bio)


class TestUtf8Codec(unittest.TestCase):
    def test_decode_encode(self):
        buf = a2b_hex('000541f0aa9b94')
        with BytesIO(buf) as f:
            num_bytes_consumed, s = mqtt_codec.io.decode_utf8(f)
        self.assertEqual(u'A\U0002a6d4', s)
        self.assertEqual(len(buf), num_bytes_consumed)

        bio = BytesIO()
        num_bytes_written = mqtt_codec.io.encode_utf8(s, bio)
        self.assertEqual(bytearray(buf), bytearray(bio.getvalue()))
        self.assertEqual(num_bytes_consumed, num_bytes_written)

    def test_encode_max_len_utf8(self):
        with BytesIO() as buf:
            try:
                mqtt_codec.io.encode_utf8((2 ** 16 - 1) * "a", buf)
                self.fail("Expected an AssertionError to be raised.")
            except AssertionError:
                pass

    def test_encode_too_long_utf8(self):
        with BytesIO() as buf:
            try:
                mqtt_codec.io.encode_utf8(2 ** 16 * "a", buf)
                self.fail("Expected an AssertionError to be raised.")
            except AssertionError:
                pass


class CodecHelper(unittest.TestCase):
    def buffer_packet(self, p):
        bio = BytesIO()
        try:
            num_encoded_bytes = p.encode(bio)
            buf = bio.getvalue()
            self.assertEqual(num_encoded_bytes, len(buf))
        finally:
            bio.close()

        return buf

    def assert_codec_okay(self, p, expected_bytes_hex=None):
        buf = self.buffer_packet(p)
        num_decoded_bytes, decoded_p = p.decode(BytesReader(buf))

        if expected_bytes_hex:
            expected_bytes = a2b_hex(expected_bytes_hex)
            self.assertEqual(expected_bytes, buf)

        self.assertEqual(num_decoded_bytes, len(buf))
        self.assertEqual(p, decoded_p)


class TestConnectCodec(CodecHelper, unittest.TestCase):
    def test_basic_connect(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttConnect('client_id', False, 0))

    def test_full_connect(self):
        will = mqtt_codec.packet.MqttWill(0, 'hello', b'message', True)
        self.assert_codec_okay(mqtt_codec.packet.MqttConnect('client_id', False, 0, will=will))


class TestConnackCodec(CodecHelper, unittest.TestCase):
    def test_decode(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttConnack(False, mqtt_codec.packet.ConnackResult.accepted), '20020000')


class TestSubscribeCodec(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttSubscribe(7, [
            mqtt_codec.packet.MqttTopic(u'hello', 0),
            mqtt_codec.packet.MqttTopic(u'x', 1),
            mqtt_codec.packet.MqttTopic(u'Z', 2),
        ]))


class TestSubackCodec(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttSuback(3, [
            mqtt_codec.packet.SubscribeResult.qos0,
            mqtt_codec.packet.SubscribeResult.qos1,
            mqtt_codec.packet.SubscribeResult.qos2,
            mqtt_codec.packet.SubscribeResult.fail,
        ]))


class TestPublish(CodecHelper, unittest.TestCase):
    def test_publish(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttPublish(3, 'flugelhorn', b'silly_payload', False, 2, False))

    def test_publish_payload(self):
        publish = mqtt_codec.packet.MqttPublish(3, 'flugelhorn', b'silly_payload', False, 2, False)
        with BytesIO() as f:
            publish.encode(f)
            buf = f.getvalue()

        buf = bytearray(buf)
        num_bytes_consumed, recovered_publish = mqtt_codec.packet.MqttPublish.decode(BytesReader(buf))


class TestPuback(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttPuback(2))


class TestPubrec(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttPubrec(3))


class TestPubrel(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttPubrel(3))


class TestPubcomp(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttPubcomp(3))


class TestUnsubscribe(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttUnsubscribe(3, ['flugelhorn']))


class TestUnsuback(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttUnsuback(3))


class TestPingreq(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttPingreq())


class TestPingresp(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttPingresp())


class TestDisconnect(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttDisconnect())


class TestDecode(unittest.TestCase):
    def test_decode(self):
        ba = bytearray(b'a')
        FIELD_U8 = Struct('>B')
        try:
            b, = FIELD_U8.unpack_from(ba)
        except struct.error as e:
            pass

        ba.extend(b'cdef')