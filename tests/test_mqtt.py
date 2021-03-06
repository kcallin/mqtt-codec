import struct
import unittest
from io import BytesIO
from struct import Struct

from mqtt_codec.io import (
    DecodeError,
    BytesReader
)
import mqtt_codec.io
import mqtt_codec.packet
from mqtt_codec.packet import (
    MqttControlPacketType,
    MqttFixedHeader,
)
from binascii import a2b_hex


class TestDecodeFixedHeader(unittest.TestCase):
    def test_decode_zero_nrb(self):
        buf = bytearray(a2b_hex('c000'))
        num_bytes_consumed, h = mqtt_codec.packet.MqttFixedHeader.decode(BytesReader(buf))
        self.assertEqual(h.remaining_len, 0)
        self.assertEqual(2, num_bytes_consumed)
        self.assertEqual(2, h.size)

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

    def test_invalid_packet_type(self):
        buf = bytearray(a2b_hex('ff01'))
        self.assertRaises(DecodeError, mqtt_codec.packet.MqttFixedHeader.decode, BytesReader(buf))

    def test_invalid_flags(self):
        buf = bytearray(a2b_hex('cf01'))
        self.assertRaises(DecodeError, mqtt_codec.packet.MqttFixedHeader.decode, BytesReader(buf))

    def test_eq(self):
        buf = bytearray(a2b_hex('c000'))
        num_bytes_consumed, h = mqtt_codec.packet.MqttFixedHeader.decode(BytesReader(buf))
        self.assertEqual(h, h)

    def test_packat(self):
        buf = bytearray(a2b_hex('c000'))
        num_bytes_consumed, h = mqtt_codec.packet.MqttFixedHeader.decode(BytesReader(buf))
        self.assertEqual(h, h.packet())


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
        repr_src = repr(p)
        str_src = repr(p)
        buf = self.buffer_packet(p)
        num_decoded_bytes, decoded_p = p.decode(BytesReader(buf))
        repr_recovered = repr(decoded_p)
        str_recovered = str(decoded_p)
        # self.assertEqual(repr_encoded, repr_decoded)

        if expected_bytes_hex:
            expected_bytes = a2b_hex(expected_bytes_hex)
            self.assertEqual(expected_bytes, buf)

        self.assertEqual(num_decoded_bytes, len(buf))
        self.assertEqual(p, decoded_p)

    def assert_extra_bytes_fail(self, p):
        with BytesIO() as f:
            p.encode(f)
            buf = bytearray(f.getvalue())

        buf[1] += 1
        buf.append(0)

        self.assertRaises(DecodeError, p.decode, BytesReader(buf))


class TestConnectCodec(CodecHelper, unittest.TestCase):
    def test_basic_connect(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttConnect('client_id', False, 0))

    def test_full_connect(self):
        will = mqtt_codec.packet.MqttWill(2, 'hello', b'message', True)
        self.assert_codec_okay(mqtt_codec.packet.MqttConnect('client_id',
                                                             True,
                                                             0,
                                                             username='tribble',
                                                             password='bibble',
                                                             will=will))

    def test_will_no_retain(self):
        will = mqtt_codec.packet.MqttWill(0, 'hello', b'message', False)
        self.assert_codec_okay(mqtt_codec.packet.MqttConnect('client_id',
                                                             True,
                                                             0,
                                                             username='tribble',
                                                             password='bibble',
                                                             will=will))

    def test_will_eq(self):
        will0 = mqtt_codec.packet.MqttWill(0, 'hello', b'message', True)
        self.assertEqual(will0, will0)

        will1 = mqtt_codec.packet.MqttWill(0, 'hello', b'message1', True)
        self.assertNotEqual(will0, will1)

    def test_extra_bytes(self):
        buf = bytearray(a2b_hex('c000'))
        num_bytes_consumed, h = mqtt_codec.packet.MqttFixedHeader.decode(BytesReader(buf))
        self.assertEqual(h.remaining_len, 0)
        self.assertEqual(2, num_bytes_consumed)

        connect = mqtt_codec.packet.MqttConnect('client_id', False, 0)
        with BytesIO() as f:
            num_bytes_written = connect.encode(f)
            value0 = f.getvalue()
            f.seek(1)
            f.write(b'\x7f')
            f.seek(0)
            value1 = f.getvalue()
            self.assertRaises(DecodeError, mqtt_codec.packet.MqttConnect.decode, f)

    def test_bad_connect_header(self):
        connect = mqtt_codec.packet.MqttConnect('client_id', False, 0)
        with BytesIO() as f:
            connect.encode(f)

            buf = bytearray(f.getvalue())
            self.assertEqual(len(buf), connect.size)

        self.assertEqual(b'\x10\x15\x00\x04MQTT\x04\x00\x00\x00\x00\tclient_id', buf)
        # Corrupt the connect header.
        buf[4] = ord('K')
        self.assertRaises(DecodeError, mqtt_codec.packet.MqttConnect.decode, BytesReader(buf))

    def test_bad_protocol_level(self):
        connect = mqtt_codec.packet.MqttConnect('client_id', False, 0)
        with BytesIO() as f:
            connect.encode(f)

            buf = bytearray(f.getvalue())
            self.assertEqual(len(buf), connect.size)

        self.assertEqual(b'\x10\x15\x00\x04MQTT\x04\x00\x00\x00\x00\tclient_id', buf)
        # Corrupt the connect header.
        buf[8] = 0xff
        self.assertRaises(DecodeError, mqtt_codec.packet.MqttConnect.decode, BytesReader(buf))

    def test_bad_flags(self):
        connect = mqtt_codec.packet.MqttConnect('client_id', False, 0)
        with BytesIO() as f:
            connect.encode(f)

            buf = bytearray(f.getvalue())
            self.assertEqual(len(buf), connect.size)

        self.assertEqual(b'\x10\x15\x00\x04MQTT\x04\x00\x00\x00\x00\tclient_id', buf)
        # Corrupt the connect header.
        buf[9] = 0xff
        self.assertRaises(DecodeError, mqtt_codec.packet.MqttConnect.decode, BytesReader(buf))

    def test_bad_will_qos(self):
        connect = mqtt_codec.packet.MqttConnect('client_id', False, 0)
        with BytesIO() as f:
            connect.encode(f)

            buf = bytearray(f.getvalue())
            self.assertEqual(len(buf), connect.size)

        self.assertEqual(b'\x10\x15\x00\x04MQTT\x04\x00\x00\x00\x00\tclient_id', buf)
        # Corrupt the connect header.
        buf[9] = buf[9] | 0x18
        self.assertRaises(DecodeError, mqtt_codec.packet.MqttConnect.decode, BytesReader(buf))


class TestConnackCodec(CodecHelper, unittest.TestCase):
    def test_decode(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttConnack(False, mqtt_codec.packet.ConnackResult.accepted),
                               '20020000')

    def test_session_present(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttConnack(True, mqtt_codec.packet.ConnackResult.accepted),
                               '20020100')

    def test_bad_session_present(self):
        buf = a2b_hex('20020200')
        self.assertRaises(DecodeError, mqtt_codec.packet.MqttConnack.decode, BytesReader(buf))

    def test_bad_return_code(self):
        buf = a2b_hex('200201ff')
        self.assertRaises(DecodeError, mqtt_codec.packet.MqttConnack.decode, BytesReader(buf))


class TestTopic(unittest.TestCase):
    def test_bad_qos(self):
        self.assertRaises(ValueError, mqtt_codec.packet.MqttTopic, 'hello', 10)


class TestSubscribeCodec(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttSubscribe(7, [
            mqtt_codec.packet.MqttTopic('hello', 0),
            mqtt_codec.packet.MqttTopic('x', 1),
            mqtt_codec.packet.MqttTopic('Z', 2),
        ]))

    def test_subscribe_typerror(self):
        self.assertRaises(TypeError, mqtt_codec.packet.MqttSubscribe, 7, 'hello')

    def test_mqtt_bad_topic(self):
        buf = bytearray(b'\x82\x12\x00\x07\x00\x05hello\x00\x00\x01x\x01\x00\x01Z\x02')
        buf[11] = 10
        self.assertRaises(DecodeError, mqtt_codec.packet.MqttSubscribe.decode, BytesReader(buf))


class TestSubscribeResult(unittest.TestCase):
    def test_qos0(self):
        self.assertEqual(0, mqtt_codec.packet.SubscribeResult.qos0.qos())

    def test_qos1(self):
        self.assertEqual(1, mqtt_codec.packet.SubscribeResult.qos1.qos())

    def test_qos2(self):
        self.assertEqual(2, mqtt_codec.packet.SubscribeResult.qos2.qos())

    def test_fail_qos(self):
        self.assertRaises(TypeError, mqtt_codec.packet.SubscribeResult.fail.qos)


class TestSubackCodec(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttSuback(3, [
            mqtt_codec.packet.SubscribeResult.qos0,
            mqtt_codec.packet.SubscribeResult.qos1,
            mqtt_codec.packet.SubscribeResult.qos2,
            mqtt_codec.packet.SubscribeResult.fail,
        ]))

    def test_bad_result(self):
        # with BytesIO() as f:
        #     mqtt_codec.packet.MqttSuback(3, [mqtt_codec.packet.SubscribeResult.qos0,]).encode(f)
        #     print(repr(f.getvalue()))

        buf = bytearray(b'\x90\x03\x00\x03\x00')
        buf[-1] = 0xff
        self.assertRaises(DecodeError, mqtt_codec.packet.MqttSuback.decode, BytesReader(buf))


class TestPublish(CodecHelper, unittest.TestCase):
    def test_publish(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttPublish(3, 'flugelhorn', b'silly_payload', False, 2, False))

    def test_publish_retain_qos0(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttPublish(3, 'flugelhorn', b'silly_payload', False, 0, True))

    def test_publish_dupe_retain_qos1(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttPublish(3, 'flugelhorn', b'silly_payload', True, 1, True))

    def test_publish_payload(self):
        publish = mqtt_codec.packet.MqttPublish(3, 'flugelhorn', b'silly_payload', False, 2, False)
        with BytesIO() as f:
            publish.encode(f)
            buf = f.getvalue()

        buf = bytearray(buf)
        num_bytes_consumed, recovered_publish = mqtt_codec.packet.MqttPublish.decode(BytesReader(buf))

    def test_qos_dupe_disagree_decode(self):
        # with BytesIO() as f:
        #     p = mqtt_codec.packet.MqttPublish(3, 'flugelhorn', b'silly_payload', False, 2, False)
        #     p.encode(f)
        #     print(repr(f.getvalue()))

        buf = bytearray(b'4\x1b\x00\nflugelhorn\x00\x03silly_payload')
        buf[0] = buf[0] & 0xf0 | 0x08
        self.assertRaises(DecodeError, mqtt_codec.packet.MqttPublish.decode, BytesReader(buf))


class TestPuback(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttPuback(2))

    def test_extra_bytes(self):
        self.assert_extra_bytes_fail(mqtt_codec.packet.MqttPuback(2))


class TestPubrec(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttPubrec(3))

    def test_extra_bytes(self):
        self.assert_extra_bytes_fail(mqtt_codec.packet.MqttPubrec(2))


class TestPubrel(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttPubrel(3))

    def test_extra_bytes(self):
        self.assert_extra_bytes_fail(mqtt_codec.packet.MqttPubrel(2))


class TestPubcomp(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttPubcomp(3))

    def test_extra_bytes(self):
        self.assert_extra_bytes_fail(mqtt_codec.packet.MqttPubcomp(2))


class TestUnsubscribe(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttUnsubscribe(3, ['flugelhorn']))

    def test_type_error(self):
        self.assertRaises(TypeError, mqtt_codec.packet.MqttUnsubscribe, 3, 'str')


class TestUnsuback(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttUnsuback(3))

    def test_extra_bytes(self):
        self.assert_extra_bytes_fail(mqtt_codec.packet.MqttUnsuback(2))


class TestPingreq(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttPingreq())

    def test_extra_bytes(self):
        self.assert_extra_bytes_fail(mqtt_codec.packet.MqttPingreq())


class TestPingresp(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttPingresp())

    def test_extra_bytes(self):
        self.assert_extra_bytes_fail(mqtt_codec.packet.MqttPingresp())


class TestDisconnect(CodecHelper, unittest.TestCase):
    def test_subscribe(self):
        self.assert_codec_okay(mqtt_codec.packet.MqttDisconnect())

    def test_extra_bytes(self):
        self.assert_extra_bytes_fail(mqtt_codec.packet.MqttDisconnect())


class TestDecode(unittest.TestCase):
    def test_decode(self):
        ba = bytearray(b'a')
        FIELD_U8 = Struct('>B')
        try:
            b, = FIELD_U8.unpack_from(ba)
        except struct.error as e:
            pass

        ba.extend(b'cdef')
