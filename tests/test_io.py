import unittest
from io import BytesIO

from mqtt_codec.io import encode_bytes, decode_bytes, LimitReader, UnderflowDecodeError, encode_utf8, decode_utf8, \
    Utf8DecodeError, BytesReader


class TestDecodeBytes(unittest.TestCase):
    def test_len_underflow(self):
        with BytesIO() as buf:
            encode_bytes(b'01234', buf)
            buf.seek(0)
            limited_buf = LimitReader(buf, 1)
            self.assertRaises(UnderflowDecodeError, decode_bytes, limited_buf)

    def test_body_underflow(self):
        with BytesIO() as buf:
            encode_bytes(b'01234', buf)
            buf.seek(0)
            limited_buf = LimitReader(buf, 3)
            self.assertRaises(UnderflowDecodeError, decode_bytes, limited_buf)

    def test_encode_bytes_type_error(self):
        with BytesIO() as buf:
            self.assertRaises(TypeError, encode_bytes, 1, buf)


class TestDecodeUtf8(unittest.TestCase):
    def test_len_underflow(self):
        with BytesIO() as buf:
            encode_utf8('abcd', buf)
            buf.seek(0)
            limited_buf = LimitReader(buf, 1)
            self.assertRaises(UnderflowDecodeError, decode_utf8, limited_buf)

    def test_body_underflow(self):
        with BytesIO() as buf:
            encode_utf8('abcd', buf)
            buf.seek(0)
            limited_buf = LimitReader(buf, 3)
            self.assertRaises(UnderflowDecodeError, decode_utf8, limited_buf)

    def test_invalid_utf8(self):
        with BytesIO() as buf:
            encode_bytes(b'0\xff1234', buf)
            buf.seek(0)
            self.assertRaises(Utf8DecodeError, decode_utf8, buf)


class TestLimitReader(unittest.TestCase):
    def test_unlimited(self):
        with BytesIO() as buf:
            expected_bytes = b'12345'
            buf.write(expected_bytes)
            r = LimitReader(buf)
            buf.seek(0)
            bytes_read = r.read(None)
            self.assertEqual(expected_bytes, bytes_read)


class TestBytesReader(unittest.TestCase):
    def test_read_after_close(self):
        with BytesIO() as buf:
            r = BytesReader(b'12345')
            self.assertFalse(r.closed)
            r.close()
            self.assertTrue(r.closed)
            self.assertRaises(ValueError, r.read)

    def test_context(self):
        with BytesReader(b'asdfasdf') as r:
            self.assertFalse(r.closed)
        self.assertTrue(r.closed)