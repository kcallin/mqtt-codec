"""
========================
`mqtt_codec.io` Package
========================

"""

import codecs
from struct import Struct


def encode_bytes(src_buf, dst_file):
    """Encode a buffer length followed by the bytes of the buffer
    itself.

    Parameters
    ----------
    src_buf: bytes
        Source bytes to be encoded.  Function asserts that
        0 <= len(src_buf) <= 2**16-1.
    dst_file: file
        File-like object with write method.

    Returns
    -------
    int
        Number of bytes written to `dst_file`.
    """
    len_src_buf = len(src_buf)
    assert 0 <= len_src_buf <= 2**16-1
    num_written_bytes = len_src_buf + 2

    len_buf = FIELD_U16.pack(len_src_buf)
    dst_file.write(len_buf)
    dst_file.write(src_buf)

    return num_written_bytes


def decode_bytes(f):
    """Decode a buffer length from a 2-byte unsigned int then read the
    subsequent bytes.

    Parameters
    ----------
    f: file
        File-like object with read method.

    Raises
    ------
    UnderflowDecodeError
        When the end of stream is encountered before the end of the
        encoded bytes.

    Returns
    -------
    int
        Number of bytes read from `f`.
    bytes
        Value bytes decoded from `f`.
    """

    buf = f.read(FIELD_U16.size)
    if len(buf) < FIELD_U16.size:
        raise UnderflowDecodeError()

    (num_bytes,) = FIELD_U16.unpack_from(buf)
    num_bytes_consumed = FIELD_U16.size + num_bytes

    buf = f.read(num_bytes)
    if len(buf) < num_bytes:
        raise UnderflowDecodeError()

    return num_bytes_consumed, buf


def encode_utf8(s, f):
    """UTF-8 encodes string `s` to file-like object `f` according to
    the MQTT Version 3.1.1 specification in section 1.5.3.

    The maximum length for the encoded string is 2**16-1 (65535) bytes.
    An assertion error will result if the encoded string is longer.

    Parameters
    ----------
    s: str
        String to be encoded.
    f: file
        File-like object.

    Returns
    -------
    int
        Number of bytes written to f.
    """
    encode = codecs.getencoder('utf8')

    encoded_str_bytes, num_encoded_chars = encode(s)
    num_encoded_str_bytes = len(encoded_str_bytes)
    assert 0 <= num_encoded_str_bytes <= 2**16-1
    num_encoded_bytes = num_encoded_str_bytes + 2

    f.write(FIELD_U8.pack((num_encoded_str_bytes & 0xff00) >> 8))
    f.write(FIELD_U8.pack(num_encoded_str_bytes & 0x00ff))
    f.write(encoded_str_bytes)

    return num_encoded_bytes


def decode_utf8(f):
    """Decode a utf-8 string encoded as described in MQTT Version
    3.1.1 section 1.5.3 line 177.  This is a 16-bit unsigned length
    followed by a utf-8 encoded string.

    Parameters
    ----------
    f: file
        File-like object with read method.

    Raises
    ------
    UnderflowDecodeError
        Raised when a read failed to extract enough bytes from the
        underlying stream to decode the string.
    DecodeError
        When any code point in the utf-8 string is invalid.

    Returns
    -------
    (num_bytes_consumed: int, value: str)
        A 2-tuple containing the number of bytes consumed and a str
        object.
    """
    decode = codecs.getdecoder('utf8')

    buf = f.read(FIELD_U16.size)
    if len(buf) < FIELD_U16.size:
        raise UnderflowDecodeError()

    (num_utf8_bytes,) = FIELD_U16.unpack_from(buf)
    num_bytes_consumed = FIELD_U16.size + num_utf8_bytes

    buf = f.read(num_utf8_bytes)
    if len(buf) < num_utf8_bytes:
        raise UnderflowDecodeError()

    try:
        s, num_chars = decode(buf)
    except UnicodeError:
        raise DecodeError('Invalid unicode character.')

    return num_bytes_consumed, s


def encode_varint(v, f):
    """Encode integer `v` to file `f`.

    Parameters
    ----------
    v: int
        Integer v >= 0.
    f: file
        Object containing a write method.

    Returns
    -------
    int
        Number of bytes written.
    """
    assert v >= 0
    num_bytes = 0

    while True:
        b = v % 0x80
        v = v // 0x80

        if v > 0:
            b = b | 0x80

        f.write(FIELD_U8.pack(b))

        num_bytes += 1
        if v == 0:
            break

    return num_bytes


def decode_varint(f, max_bytes=4):
    """Decode variable integer using algorithm similar to that described
    in MQTT Version 3.1.1 line 297.

    Parameters
    ----------
    f: file
        Object with a read method.
    max_bytes: int or None
        If a varint cannot be constructed using `max_bytes` or fewer
        from f then raises a `DecodeError`.  If None then there is no
        maximum number of bytes.

    Raises
    -------
    DecodeError
        When length is greater than max_bytes.
    UnderflowDecodeError
        When file ends before enough bytes can be read to construct the
        varint.

    Returns
    -------
    int
        Number of bytes consumed.
    int
        Value extracted from `f`.

    """
    num_bytes_consumed = 0

    value = 0
    m = 1

    while True:
        buf = f.read(1)
        if len(buf) == 0:
            raise UnderflowDecodeError()

        (u8,) = FIELD_U8.unpack(buf)
        value += (u8 & 0x7f) * m
        m *= 0x80
        num_bytes_consumed += 1

        if u8 & 0x80 == 0:
            # No further bytes
            break
        elif max_bytes is not None and num_bytes_consumed >= max_bytes:
            raise DecodeError('Variable integer contained more than maximum bytes ({}).'.format(max_bytes))

    return num_bytes_consumed, value


class DecodeError(Exception):
    pass


class UnderflowDecodeError(DecodeError):
    pass


class EncodeError(Exception):
    pass


class OverflowEncodeError(EncodeError):
    pass


class OversizePacketEncodeError(EncodeError):
    """Raised when the parameters used to create the MQTT packet would
    result in an impossibly large packet."""
    pass


class FileDecoder(object):
    """Creates an object that extracts values from the file-like
    object `f`.

    Parameters
    ----------
    f: file
        Object with read method.
    """

    def __init__(self, f):
        self.__f = f
        self.__num_bytes_consumed = 0

    @property
    def num_bytes_consumed(self):
        """int: number of bytes consumed from underlying stream."""
        return self.__num_bytes_consumed

    def unpack(self, struct):
        """Read as many bytes as are required to extract struct then
        unpack and return a tuple of the values.

        Raises
        ------
        UnderflowDecodeError
            Raised when a read failed to extract enough bytes from the
            underlying stream to extract the bytes.

        Parameters
        ----------
        struct: struct.Struct

        Returns
        -------
        tuple
            Tuple of extracted values.
        """
        v = struct.unpack(self.read(struct.size))
        return v

    def unpack_utf8(self):
        """Decode a utf-8 string encoded as described in MQTT Version
        3.1.1 section 1.5.3 line 177.  This is a 16-bit unsigned length
        followed by a utf-8 encoded string.

        Raises
        ------
        UnderflowDecodeError
            Raised when a read failed to extract enough bytes from the
            underlying stream to decode the string.
        DecodeError
            When any code point in the utf-8 string is invalid.

        Returns
        -------
        int
            Number of bytes consumed.
        str
            A string utf-8 decoded from the underlying stream.
        """
        num_bytes_consumed, s = decode_utf8(self.__f)
        self.__num_bytes_consumed += num_bytes_consumed
        return num_bytes_consumed, s

    def unpack_bytes(self):
        """Unpack a utf-8 string encoded as described in MQTT Version
        3.1.1 section 1.5.3 line 177.  This is a 16-bit unsigned length
        followed by a utf-8 encoded string.

        Returns
        -------
        int
            Number of bytes consumed
        bytes
            A bytes object extracted from the underlying stream.
        """
        num_bytes_consumed, b = decode_bytes(self.__f)
        self.__num_bytes_consumed += num_bytes_consumed
        return num_bytes_consumed, b

    def unpack_varint(self, max_bytes):
        """Decode variable integer using algorithm similar to that described
        in MQTT Version 3.1.1 line 297.

        Parameters
        ----------
        max_bytes: int or None
            If a varint cannot be constructed using `max_bytes` or fewer
            from f then raises a `DecodeError`.  If None then there is no
            maximum number of bytes.

        Raises
        -------
        DecodeError
            When length is greater than max_bytes.
        UnderflowDecodeError
            When file ends before enough bytes can be read to construct the
            varint.

        Returns
        -------
        int
            Number of bytes consumed.
        int
            Value extracted from `f`.

        """
        num_bytes_consumed, value = decode_varint(self.__f, max_bytes)
        self.__num_bytes_consumed += num_bytes_consumed
        return num_bytes_consumed, value

    def read(self, num_bytes):
        """Read `num_bytes` and return them.

        Parameters
        ----------
        num_bytes : int
            Number of bytes to extract from the underlying stream.

        Raises
        ------
        UnderflowDecodeError
            Raised when a read failed to extract enough bytes from the
            underlying stream to extract the bytes.

        Returns
        -------
        bytes
            A bytes object extracted from underlying stream.
        """
        buf = self.__f.read(num_bytes)
        assert len(buf) <= num_bytes
        if len(buf) < num_bytes:
            raise UnderflowDecodeError()
        self.__num_bytes_consumed += num_bytes

        return buf


class LimitReader(object):
    def __init__(self, f, limit=None):
        self.__f = f
        self.__num_bytes_consumed = 0
        self.__limit = limit

    @property
    def limit(self):
        """int or None: maximum number of bytes to read from underlying stream."""
        return self.__limit

    def read(self, max_bytes=1):
        """Read at most `max_bytes` from internal buffer.

        Parameters
        -----------
        max_bytes: int
            Maximum number of bytes to read.

        Returns
        --------
        bytes
            Bytes extracted from internal buffer.  Length may be less
            than `max_bytes`.  On end-of file returns a bytes object
            with zero-length.
        """

        if self.limit is None:
            b = self.__f.read(max_bytes)
        else:
            if self.__num_bytes_consumed + max_bytes > self.limit:
                max_bytes = self.limit - self.__num_bytes_consumed
            b = self.__f.read(max_bytes)
        self.__num_bytes_consumed += len(b)

        return b


class BytesReader(object):
    """Creates a file-like object that reads from a buffer.

    Parameters
    ----------
    buf: bytes or bytearray
        Object to read from.
    """

    def __init__(self, buf):
        assert isinstance(buf, (bytes, bytearray)), type(buf)
        self.__buf = buf
        self.__num_bytes_consumed = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def read(self, max_bytes=1):
        """Read at most `max_bytes` from internal buffer.

        Parameters
        -----------
        max_bytes: int
            Maximum number of bytes to read.

        Raises
        ------
        ValueError
            If read is called after close has been called.

        Returns
        --------
        bytes
            Bytes extracted from internal buffer.  Length may be less
            than `max_bytes`.  On end-of file returns a bytes object
            with zero-length.
        """
        if self.__num_bytes_consumed is None:
            raise ValueError('I/O operation on closed file.')

        if self.__num_bytes_consumed + max_bytes >= len(self.__buf):
            max_bytes = len(self.__buf) - self.__num_bytes_consumed

        b = self.__buf[self.__num_bytes_consumed:self.__num_bytes_consumed + max_bytes]
        self.__num_bytes_consumed += max_bytes

        if isinstance(b, bytearray):
            b = bytes(b)

        assert isinstance(b, bytes)
        return b

    @property
    def closed(self):
        """bool: `True` if `self.close()` has been called; `False` otherwise."""
        return self.__num_bytes_consumed is None

    def close(self):
        """Read operations conducted after this method is called will
        raise `ValueError`.  This makes the object behave like other
        read objects even though no resources are freed."""
        self.__num_bytes_consumed = None


FIELD_U16 = Struct('>H')
FIELD_PACKET_ID = FIELD_U16
FIELD_U8 = Struct('>B')