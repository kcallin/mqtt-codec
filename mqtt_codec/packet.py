"""
============================
`mqtt_codec.packet` Package
============================

"""
# Standard Python Packages
from __future__ import absolute_import

from binascii import b2a_hex
from io import BytesIO

# 3rd Party Packages
from enum import IntEnum, unique

# mqtt_codec packages
import mqtt_codec.io as mqtt_io
from mqtt_codec.io import (
    DecodeError,
    OverflowEncodeError,
    OversizePacketEncodeError,
)


class MqttControlPacketType(IntEnum):
    connect = 1
    connack = 2
    publish = 3
    puback = 4
    pubrec = 5
    pubrel = 6
    pubcomp = 7
    subscribe = 8
    suback = 9
    unsubscribe = 10
    unsuback = 11
    pingreq = 12
    pingresp = 13
    disconnect = 14


def are_flags_valid(packet_type, flags):
    """True when flags comply with [MQTT-2.2.2-1] requirements based on
    packet_type; False otherwise.

    Parameters
    ----------
    packet_type: MqttControlPacketType
    flags: int
        Integer representation of 4-bit MQTT header flags field.
        Values outside of the range [0, 15] will certainly cause the
        function to return False.

    Returns
    -------
    bool
    """
    if packet_type == MqttControlPacketType.publish:
        rv = 0 <= flags <= 15
    elif packet_type in (MqttControlPacketType.pubrel,
                         MqttControlPacketType.subscribe,
                         MqttControlPacketType.unsubscribe):
        rv = flags == 2
    elif packet_type in (MqttControlPacketType.connect,
                         MqttControlPacketType.connack,
                         MqttControlPacketType.puback,
                         MqttControlPacketType.pubrec,
                         MqttControlPacketType.pubcomp,
                         MqttControlPacketType.suback,
                         MqttControlPacketType.unsuback,
                         MqttControlPacketType.pingreq,
                         MqttControlPacketType.pingresp,
                         MqttControlPacketType.disconnect):
        rv = flags == 0
    else:
        raise NotImplementedError()

    return rv


class MqttFixedHeader(object):
    """
    Raises
    -------
    mqtt_codec.io.TooBigEncodeError
        The `remaining_len` exceeds the maximum of
        `MqttFixedHeader.MAX_REMAINING_LEN` (=268435455 bytes).

    Parameters
    ----------
    packet_type: MqttControlPacketType
    flags: int
        An assert statement verifies
        that are_flags_valid(packet_type, flags) is True.
    remaining_len: int
        Asserted to be 0 <= remaining_len <= MqttFixedHeader.MAX_REMAINING_LEN


    See MQTT Version 3.1.1 section 2.2 Fixed Header (line 233).

    +--------+-------------------------------+
    |        |              Bit              |
    |        +---+---+---+---+---+---+---+---+
    |        | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
    +========+===+===+===+===+===+===+===+===+
    | byte 1 | control type  |    flags      |
    +--------+---------------+---------------+
    | byte 2 |      remaining length         |
    +--------+-------------------------------+
    """
    MAX_REMAINING_LEN = 268435455

    def __init__(self, packet_type, flags, remaining_len):
        assert packet_type in MqttControlPacketType, packet_type
        self.packet_type = packet_type
        if not (0 <= remaining_len <= MqttFixedHeader.MAX_REMAINING_LEN):
            raise OversizePacketEncodeError()

        assert are_flags_valid(packet_type, flags)

        self.flags = flags
        self.remaining_len = remaining_len

        size = 1
        with BytesIO() as buf:
            mqtt_io.encode_varint(self.remaining_len, buf)
            size += len(buf.getvalue())
        size += self.remaining_len

        self.size = size

    @staticmethod
    def decode(f):
        """Extract a `MqttFixedHeader` from `f`.

        Parameters
        ----------
        f: file
            Object with read method.

        Raises
        -------
        DecodeError
            When bytes decoded have values incompatible with a
            `MqttFixedHeader` object.
        UnderflowDecodeError
            When end-of-stream is encountered before the end of the
            fixed header.

        Returns
        -------
        int
            Number of bytes consumed from `f`.
        MqttFixedHeader
            Header object extracted from `f`.
        """
        decoder = mqtt_io.FileDecoder(f)
        (byte_0,) = decoder.unpack(mqtt_io.FIELD_U8)

        packet_type_u4 = (byte_0 >> 4)
        flags = byte_0 & 0x0f

        try:
            packet_type = MqttControlPacketType(packet_type_u4)
        except ValueError:
            raise DecodeError('Unknown packet type 0x{:02x}.'.format(packet_type_u4))

        if not are_flags_valid(packet_type, flags):
            raise DecodeError('Invalid flags for packet type.')

        num_bytes, num_remaining_bytes = decoder.unpack_varint(4)

        return decoder.num_bytes_consumed, MqttFixedHeader(packet_type, flags, num_remaining_bytes)

    def encode(self, f):
        """

        Parameters
        ----------
        f: file
            file-like object

        Returns
        -------
        int
            Number of bytes written.
        """
        try:
            b = (int(self.packet_type) << 4) | self.flags
            f.write(mqtt_io.FIELD_U8.pack(b))
            num_bytes_consumed = 1
            num_bytes_consumed += mqtt_io.encode_varint(self.remaining_len, f)
        except IndexError:
            raise OverflowEncodeError()

        return num_bytes_consumed

    def packet(self):
        return self

    def __eq__(self, other):
        return (
            hasattr(other, 'packet_type')
            and self.packet_type == other.packet_type
            and hasattr(other, 'flags')
            and self.flags == other.flags
            and hasattr(other, 'remaining_len')
            and self.remaining_len == other.remaining_len
        )


class MqttWill(object):
    """

    Parameters
    ----------
    qos: int
        0 <= qos <= 2
    topic: str
    message: bytes
    retain: bool
    """

    def __init__(self, qos, topic, message, retain):
        assert isinstance(message, bytes)
        self.qos = qos
        self.topic = topic
        self.message = message
        self.retain = retain

    def __repr__(self):
        msg = 'MqttWill(topic={}, payload=0x{}, retain={}, qos={})'
        return msg.format(self.topic, b2a_hex(self.message), self.retain, self.qos)

    def __eq__(self, other):
        return (
                hasattr(other, 'qos')
                and self.qos == other.qos
                and hasattr(other, 'topic')
                and self.topic == other.topic
                and hasattr(other, 'message')
                and self.message == other.message
                and hasattr(other, 'retain')
                and self.retain == other.retain
        )


class MqttPacketBody(MqttFixedHeader):
    """
    Raises
    -------
    mqtt_codec.io.TooBigEncodeError
        The message body is impossibly large to create an MQTT packet
        for.  It must be greater than
        `MqttFixedHeader.MAX_REMAINING_LEN` (=268435455 bytes) in order
        to cause this error.

    Parameters
    ----------
    packet_type: MqttControlPacketType
    flags: int
        Flags 0 <= flags <= 2**8-1.
    """

    def __init__(self, packet_type, flags):
        bio = BytesIO()
        self.encode_body(bio)
        num_body_bytes = len(bio.getvalue())
        MqttFixedHeader.__init__(self, packet_type, flags, num_body_bytes)

    def encode_body(self, f):
        raise NotImplementedError()

    def encode(self, f):
        num_bytes_written = 0
        num_bytes_written += MqttFixedHeader.encode(self, f)
        num_bytes_written += self.encode_body(f)

        return num_bytes_written

    @classmethod
    def decode_body(cls, header, buf):
        raise NotImplementedError()

    @classmethod
    def decode(cls, f):
        """

        Parameters
        ----------
        f: file
            Object with a read method.

        Returns
        -------
        int
            Number of bytes consumed from `f`.
        MqttFixedHeader
            Header object extracted from `f`.
        """

        num_header_bytes_consumed, header = MqttFixedHeader.decode(f)
        num_body_bytes_consumed, packet = cls.decode_body(header, f)
        if header.remaining_len != num_body_bytes_consumed:
            params = header.remaining_len, num_body_bytes_consumed
            msg = 'Header remaining length {} not equal to body bytes consumed {}.'.format(*params)
            raise DecodeError(msg)
        num_bytes_consumed = num_header_bytes_consumed + num_body_bytes_consumed

        return num_bytes_consumed, packet


class MqttConnect(MqttPacketBody):
    """Represents an `MqttConnect` object.

    The object str(self) will have the username and password obscured.

    The object repr(self) does not obscure the username and password.

    Raises
    -------
    mqtt_codec.io.TooBigEncodeError
        The parameters are impossible large to create
        an MQTT packet for.  It encoded length must be greater than
        `MqttFixedHeader.MAX_REMAINING_LEN` (=268435455 bytes) in order
        to cause this error.

    Parameters
    ----------
    client_id: str
    clean_session: bool
    keep_alive: int
    username: str or None
    password: str or None
    will: MqttWill or None
    """
    CONNECT_HEADER = b'\x00\x04MQTT'
    PROTOCOL_LEVEL = b'\x04'

    def __init__(self, client_id, clean_session, keep_alive, username=None, password=None, will=None):
        self.__client_id = client_id
        self.__username = username
        self.__password = password
        self.__clean_session = clean_session
        self.__keep_alive = keep_alive
        self.__will = will

        MqttPacketBody.__init__(self, MqttControlPacketType.connect, 0)

    @property
    def client_id(self):
        """str: Client id."""
        return self.__client_id

    @property
    def username(self):
        """str or None: MQTT username."""
        return self.__username

    @property
    def password(self):
        """str or None: MQTT password."""
        return self.__password

    @property
    def clean_session(self):
        """bool: MQTT password."""
        return self.__clean_session

    @property
    def keep_alive(self):
        """int: Keep alive period as described in MQTT 3.1.1
        specification 3.1.2.10.  When zero keep-alive is disabled.
        If positive then after `self.keep_alive` seconds of inactivity
        the client will send a ping to the server."""
        return self.__keep_alive

    @property
    def will(self):
        """MqttWill or None: A message that will be published on behalf
        of the client by the server in case of an unexpected
        disconnect.  If `None` then the server does not publish any
        message on behalf of the client."""
        return self.__will

    @staticmethod
    def __encode_name(f):
        f.write(MqttConnect.CONNECT_HEADER)
        return len(MqttConnect.CONNECT_HEADER)

    @staticmethod
    def __encode_protocol_level(f):
        f.write(MqttConnect.PROTOCOL_LEVEL)

        return 1

    def __encode_connect_flags(self, f):
        flags = 0x00

        if self.username:
            flags = flags | 0x80

        if self.password:
            flags = flags | 0x40

        if self.will is not None:
            flags = flags | 0x04

            if self.will.retain:
                flags = flags | 0x20

            if self.will.qos:
                flags = flags | (self.will.qos << 3)

        if self.clean_session:
            flags = flags | 0x02

        f.write(mqtt_io.FIELD_U8.pack(flags))

        return 1

    def __encode_keep_alive(self, f):
        f.write(mqtt_io.FIELD_U8.pack((self.keep_alive & 0xff00) >> 8))
        f.write(mqtt_io.FIELD_U8.pack(self.keep_alive & 0x00ff))

        return 2

    def encode_body(self, f):
        """
        Parameters
        ----------
        f: file
            File-like object with a write method.

        Returns
        -------
        int
            Number of bytes written to `f`.
        """
        num_bytes_written = 0
        num_bytes_written += self.__encode_name(f)
        num_bytes_written += self.__encode_protocol_level(f)
        num_bytes_written += self.__encode_connect_flags(f)
        num_bytes_written += self.__encode_keep_alive(f)

        if self.client_id is not None:
            num_bytes_written += mqtt_io.encode_utf8(self.client_id, f)

        if self.will is not None:
            num_bytes_written += mqtt_io.encode_utf8(self.will.topic, f)
            num_bytes_written += mqtt_io.encode_bytes(self.will.message, f)

        if self.username is not None:
            num_bytes_written += mqtt_io.encode_utf8(self.username, f)

        if self.password is not None:
            num_bytes_written += mqtt_io.encode_utf8(self.password, f)

        return num_bytes_written

    @classmethod
    def decode_body(cls, header, f):
        """

        Parameters
        ----------
        header: MqttFixedHeader
        f: file
            File-like object with a read method.

        Returns
        -------
        int
            Number of bytes consumed from `f`.
        MqttConnect
            Connect object extracted from `f`.
        """
        decoder = mqtt_io.FileDecoder(mqtt_io.LimitReader(f, header.remaining_len))
        connect_header = decoder.read(len(MqttConnect.CONNECT_HEADER))
        if connect_header != MqttConnect.CONNECT_HEADER:
            raise DecodeError('Invalid connect packet header.')

        protocol_level = decoder.read(1)
        if protocol_level != MqttConnect.PROTOCOL_LEVEL:
            raise DecodeError('Invalid protocol level {}.'.format(protocol_level))

        flags = decoder.unpack(mqtt_io.FIELD_U8)[0]
        has_username = bool(flags & 0x80)
        has_password = bool(flags & 0x40)
        has_will = bool(flags & 0x04)
        will_retained = bool(flags & 0x20)
        will_qos = (flags & 0x18) >> 3
        clean_session = bool(flags & 0x02)
        zero = flags & 0x01

        if zero != 0:
            raise DecodeError()

        keep_alive = decoder.unpack(mqtt_io.FIELD_U16)[0]

        num_str_byes, client_id = decoder.unpack_utf8()

        if has_will:
            num_str_byes, will_topic = decoder.unpack_utf8()
            num_bytes, will_message = decoder.unpack_bytes()
            will = MqttWill(will_qos, will_topic, will_message, will_retained)
        else:
            if will_qos != 0:
                # [MQTT-3.1.2-13]
                raise DecodeError('Expected will_qos to be zero since will flag is zero.')

            will = None

        if has_username:
            num_str_byes, username = decoder.unpack_utf8()
        else:
            username = None

        if has_password:
            num_str_byes, password = decoder.unpack_utf8()
        else:
            password = None

        connect = MqttConnect(client_id, clean_session, keep_alive, username, password, will)
        return decoder.num_bytes_consumed, connect

    def __str__(self):
        """Returns a str representation of self.  The username and
        password fields will be hashed out so that if the result of this
        call is placed in logfiles it will not compromise the username
        and password.

        Returns
        -------
        str
        """
        msg = 'MqttConnect(client_id={}, clean_session={}, keep_alive={}s, username=***, password=***, will={})'
        return msg.format(repr(self.client_id),
                          self.clean_session,
                          self.keep_alive,
                          repr(self.will))

    def __repr__(self):
        """A full string representation of the object including username
        and password.  It might not be good to write this result to a
        log file.

        Returns
        -------
        str
        """
        msg = 'MqttConnect(client_id={}, clean_session={}, keep_alive={}s, username={}, password={}, will={})'
        return msg.format(repr(self.client_id),
                          self.clean_session,
                          self.keep_alive,
                          repr(self.username),
                          repr(self.password),
                          self.will)


@unique
class ConnackResult(IntEnum):
    accepted = 0
    fail_bad_protocol_version = 1
    fail_bad_client_id = 2
    fail_server_unavailable = 3
    fail_bad_username_or_password = 4
    fail_not_authorized = 5


class MqttConnack(MqttPacketBody):
    """

    Parameters
    ----------
    session_present: bool
        Session present.
    return_code: ConnackResult
        Connack return code [Line 709 mqtt]
    """

    def __init__(self, session_present, return_code):
        assert 0 <= return_code <= 255
        assert isinstance(session_present, bool)
        assert isinstance(return_code, ConnackResult)

        self.session_present = session_present
        self.return_code = return_code

        MqttPacketBody.__init__(self, MqttControlPacketType.connack, 0)

    def encode_body(self, f):
        """

        Parameters
        ----------
        f: file
            File-like object with write method.

        Returns
        -------
        int
            Number of bytes written to file.
        """
        num_bytes_written = 2

        if self.session_present:
            flags = 1
        else:
            flags = 0

        f.write(mqtt_io.FIELD_U8.pack(flags))
        f.write(mqtt_io.FIELD_U8.pack(self.return_code))

        return num_bytes_written

    @classmethod
    def decode_body(cls, header, f):
        """

        Parameters
        ----------
        header: MqttFixedHeader
        f: file
            Object with a read method.

        Raises
        ------
        DecodeError
            When bytes have values incompatible with a MqttConnack
            packet.
        UnderflowDecodeError
            When not enough bytes are available to decode a complete
            packet.

        Returns
        -------
        int
            Number of bytes consumed from `f`.
        MqttConnack
            Connack object extracted from `f`.
        """
        decoder = mqtt_io.FileDecoder(mqtt_io.LimitReader(f, header.remaining_len))
        session_present_u8 = decoder.unpack(mqtt_io.FIELD_U8)[0]

        if session_present_u8 == 0:
            session_present = False
        elif session_present_u8 == 1:
            session_present = True
        else:
            raise DecodeError('Incorrectly encoded session_present flag ({}).'.format(session_present_u8))

        return_code_u8 = decoder.unpack(mqtt_io.FIELD_U8)[0]
        try:
            return_code = ConnackResult(return_code_u8)
        except ValueError:
            raise DecodeError("Unrecognized return code {}.".format(return_code_u8))

        return decoder.num_bytes_consumed, MqttConnack(session_present, return_code)

    def __repr__(self):
        msg = 'MqttConnack(session_present={}, return_code={})'
        return msg.format(self.session_present, repr(self.return_code))


class MqttTopic(object):
    """

    Parameters
    ----------
    name: str
    max_qos: int

    """

    def __init__(self, name, max_qos):
        if not 0 <= max_qos <= 2:
            raise ValueError('Invalid QOS.')

        self.name = name
        self.max_qos = max_qos

    def __repr__(self):
        return 'Topic({}, max_qos={})'.format(repr(self.name), self.max_qos)

    def __eq__(self, other):
        return (
            hasattr(other, 'name')
            and self.name == other.name
            and hasattr(other, 'max_qos')
            and self.max_qos == other.max_qos
        )


class MqttSubscribe(MqttPacketBody):
    """
    Raises
    -------
    mqtt_codec.io.TooBigEncodeError
        The parameters are impossibly large to create
        an MQTT packet for.  The encoded length must be greater than
        `MqttFixedHeader.MAX_REMAINING_LEN` (=268435455 bytes) in order
        to cause this error.

    Parameters
    ----------
    packet_id: int
        0 <= packet_id <= 2**16-1
    topics: iterable of MqttTopic
    """

    def __init__(self, packet_id, topics):
        self.packet_id = packet_id
        self.topics = tuple(topics)

        if isinstance(topics, (str, unicode, bytes)):
            raise TypeError()

        assert len(topics) >= 1  # MQTT 3.8.3-3
        flags = 2  # MQTT 3.8.1-1
        MqttPacketBody.__init__(self, MqttControlPacketType.subscribe, flags)

    def encode_body(self, f):
        """

        Parameters
        ----------
        f: file
            File-like object with write method.

        Returns
        -------
        int
            Number of bytes written to file.
        """
        num_bytes_written = 0
        num_bytes_written += f.write(mqtt_io.FIELD_U16.pack(self.packet_id))
        for topic in self.topics:
            num_bytes_written += mqtt_io.encode_utf8(topic.name, f)
            num_bytes_written += f.write(mqtt_io.FIELD_U8.pack(topic.max_qos))

        return num_bytes_written

    @classmethod
    def decode_body(cls, header, f):
        """Generates a `MqttSubscribe` packet given a
        `MqttFixedHeader`.  This method asserts that header.packet_type
        is `subscribe`.

        Parameters
        ----------
        header: MqttFixedHeader
        f: file
            Object with a read method.

        Raises
        ------
        DecodeError
            When there are extra bytes at the end of the packet.

        Returns
        -------
        int
            Number of bytes consumed from `f`.
        MqttSubscribe
            Subscribe object extracted from `f`.
        """
        assert header.packet_type == MqttControlPacketType.subscribe

        decoder = mqtt_io.FileDecoder(mqtt_io.LimitReader(f, header.remaining_len))
        packet_id, = decoder.unpack(mqtt_io.FIELD_PACKET_ID)

        topics = []
        while header.remaining_len > decoder.num_bytes_consumed:
            num_str_bytes, name = decoder.unpack_utf8()
            max_qos, = decoder.unpack(mqtt_io.FIELD_U8)
            try:
                sub_topic = MqttTopic(name, max_qos)
            except ValueError:
                raise DecodeError('Invalid QOS {}'.format(max_qos))
            topics.append(sub_topic)

        assert header.remaining_len == decoder.num_bytes_consumed

        return decoder.num_bytes_consumed, MqttSubscribe(packet_id, topics)

    def __repr__(self):
        return 'MqttSubscribe(packet_id={}, topics=[{}])'.format(self.packet_id, ', '.join(repr(t) for t in self.topics))

    def __eq__(self, other):
        return (
            hasattr(other, 'packet_type')
            and self.packet_type == other.packet_type
            and hasattr(other, 'flags')
            and self.flags == other.flags
            and hasattr(other, 'remaining_len')
            and self.remaining_len == other.remaining_len
            and hasattr(other, 'packet_id')
            and self.packet_id == other.packet_id
            and hasattr(other, 'topics')
            and self.topics == other.topics
        )


class SubscribeResult(IntEnum):
    qos0 = 0x00
    qos1 = 0x01
    qos2 = 0x02
    fail = 0x80

    def qos(self):
        """

        Raises
        -------
        TypeError
            If result is not a qos.

        Returns
        -------
        int
            QOS as an integer
        """
        if self == SubscribeResult.qos0:
            rv = 0
        elif self == SubscribeResult.qos1:
            rv = 1
        elif self == SubscribeResult.qos2:
            rv = 2
        else:
            raise TypeError()

        return rv


class MqttSuback(MqttPacketBody):
    """
    Raises
    -------
    mqtt_codec.io.TooBigEncodeError
        There are too many results to create an MQTT packet for.  The
        encoded lenght must be greater than
        `MqttFixedHeader.MAX_REMAINING_LEN` (=268435455 bytes) in order
        to cause this error.

    Parameters
    ----------
    packet_id: int
        0 <= packet_id <= 2**16-1
    results: iterable of SubscribeResult
    """
    def __init__(self, packet_id, results):
        """

        """
        self.__packet_id = packet_id
        self.__results = tuple(results)

        assert len(self.results) >= 1  # MQTT 3.8.3-3

        flags = 0
        MqttPacketBody.__init__(self, MqttControlPacketType.suback, flags)

    @property
    def packet_id(self):
        """int: packet_id such that 0 <= packet_id <= 2**16-1."""
        return self.__packet_id

    @property
    def results(self):
        """tuple of SubscribeResult:
            Tuple of return codes specifying the maximum QoS level that was
            granted in each or fail if the subscription failed.
        """
        return self.__results

    def encode_body(self, f):
        """

        Parameters
        ----------
        f: file
            File-like object with write method.

        Returns
        -------
        int
            Number of bytes written to file.
        """
        num_bytes_written = 0
        num_bytes_written += f.write(mqtt_io.FIELD_U16.pack(self.packet_id))
        for result in self.results:
            num_bytes_written += f.write(mqtt_io.FIELD_U8.pack(int(result)))

        return num_bytes_written

    @classmethod
    def decode_body(cls, header, f):
        """Generates a `MqttSuback` packet given a
        `MqttFixedHeader`.  This method asserts that header.packet_type
        is `suback`.

        Parameters
        ----------
        header: MqttFixedHeader
        f: file
            Object with a read method.

        Raises
        ------
        DecodeError
            When there are extra bytes at the end of the packet.

        Returns
        -------
        int
            Number of bytes consumed from `f`.
        MqttSuback
            Suback object extracted from `f`.
        """
        assert header.packet_type == MqttControlPacketType.suback

        decoder = mqtt_io.FileDecoder(mqtt_io.LimitReader(f, header.remaining_len))
        packet_id, = decoder.unpack(mqtt_io.FIELD_PACKET_ID)

        results = []
        while header.remaining_len > decoder.num_bytes_consumed:
            result, = decoder.unpack(mqtt_io.FIELD_U8)
            try:
                results.append(SubscribeResult(result))
            except ValueError:
                raise DecodeError('Unsupported result {:02x}.'.format(ord(result)))

        assert header.remaining_len == decoder.num_bytes_consumed

        return decoder.num_bytes_consumed, MqttSuback(packet_id, results)

    def __repr__(self):
        return 'MqttSuback(packet_id={}, results=[{}])'.format(self.packet_id, ', '.join(repr(r) for r in self.results))


class MqttPublish(MqttPacketBody):
    """Represents a mqtt publish packet.

    Raises
    -------
    mqtt_codec.io.TooBigEncodeError
        The encoded length of parameters is too long to create an MQTT
        packet for.  The encoded lenght must be greater than
        `MqttFixedHeader.MAX_REMAINING_LEN` (=268435455 bytes) in order
        to cause this error.

        Shorten the payload or topic to allow the message to fit.

    Parameters
    ----------
    packet_id: int
        0 <= packet_id <= 2**16 -1
    topic: str
    payload: bytes
    dupe: bool
        Represents the DUP flag as described by the MQTT
        specification:

            If the DUP flag is set to 0, it indicates that this is the
            first occasion that the Client or Server has attempted to
            send this MQTT PUBLISH Packet. If the DUP flag is set to 1,
            it indicates that this might be re-delivery of an earlier
            attempt to send the Packet.

            The DUP flag MUST be set to 1 by the Client or Server when
            it attempts to re-deliver a PUBLISH Packet [MQTT-3.3.1-1].
            The DUP flag MUST be set to 0 for all QoS 0 messages
            [MQTT-3.3.1-2].

            The value of the DUP flag from an incoming PUBLISH packet is
            not propagated when the PUBLISH Packet is sent to
            subscribers by the Server. The DUP flag in the outgoing
            PUBLISH packet is set independently to the incoming PUBLISH
            packet, its value MUST be determined solely by whether the
            outgoing PUBLISH packet is a retransmission [MQTT-3.3.1-3].
    qos: int
        0 <= qos <= 2
    retain: bool

    Attributes
    ----------
    packet_id : int
        Integer such that 0 <= packet_id <= (2**16)-1.
    topic : str
    payload : bytes
    dupe : bool
        Represents the DUP flag as described by the MQTT
        specification:

            If the DUP flag is set to 0, it indicates that this is the
            first occasion that the Client or Server has attempted to
            send this MQTT PUBLISH Packet. If the DUP flag is set to 1,
            it indicates that this might be re-delivery of an earlier
            attempt to send the Packet.

            The DUP flag MUST be set to 1 by the Client or Server when
            it attempts to re-deliver a PUBLISH Packet [MQTT-3.3.1-1].
            The DUP flag MUST be set to 0 for all QoS 0 messages
            [MQTT-3.3.1-2].

            The value of the DUP flag from an incoming PUBLISH packet is
            not propagated when the PUBLISH Packet is sent to
            subscribers by the Server. The DUP flag in the outgoing
            PUBLISH packet is set independently to the incoming PUBLISH
            packet, its value MUST be determined solely by whether the
            outgoing PUBLISH packet is a retransmission [MQTT-3.3.1-3].
    qos : int
        Integer such that 0 <= qos <= 2.
    retain: bool
    """

    def __init__(self, packet_id, topic, payload, dupe, qos, retain):
        assert 0 <= packet_id <= 2**16 - 1
        assert 0 <= qos <= 2
        assert isinstance(payload, bytes)
        assert isinstance(dupe, bool)
        assert isinstance(retain, bool)
        if qos == 0:
            # The DUP flag MUST be set to 0 for all QoS 0 messages
            # [MQTT-3.3.1-2]
            assert dupe is False

        self.packet_id = packet_id
        self.topic = topic
        self.payload = payload
        self.dupe = dupe
        self.qos = qos
        self.retain = retain

        flags = 0
        if dupe:
            flags |= 0x08

        flags |= (qos << 1)

        if retain:
            flags |= 0x01

        MqttPacketBody.__init__(self, MqttControlPacketType.publish, flags)

    def encode_body(self, f):
        """

        Parameters
        ----------
        f: file
            File-like object with write method.

        Returns
        -------
        int
            Number of bytes written to file.
        """

        num_bytes_written = 0
        num_bytes_written += mqtt_io.encode_utf8(self.topic, f)
        num_bytes_written += f.write(mqtt_io.FIELD_U16.pack(self.packet_id))
        num_bytes_written += f.write(self.payload)

        return num_bytes_written

    @classmethod
    def decode_body(cls, header, f):
        """Generates a `MqttPublish` packet given a
        `MqttFixedHeader`.  This method asserts that header.packet_type
        is `publish`.

        Parameters
        ----------
        header: MqttFixedHeader
        f: file
            Object with a read method.

        Raises
        ------
        DecodeError
            When there are extra bytes at the end of the packet.

        Returns
        -------
        (num_bytes_consumed: int, packet: MqttPublish)
            Number of bytes written to file.
        """
        assert header.packet_type == MqttControlPacketType.publish

        dupe = bool(header.flags & 0x08)
        retain = bool(header.flags & 0x01)
        qos = ((header.flags & 0x06) >> 1)

        if qos == 0 and dupe:
            # The DUP flag MUST be set to 0 for all QoS 0 messages
            # [MQTT-3.3.1-2]
            raise DecodeError("Unexpected dupe=True for qos==0 message [MQTT-3.3.1-2].")

        decoder = mqtt_io.FileDecoder(mqtt_io.LimitReader(f, header.remaining_len))
        num_bytes_consumed, topic_name = decoder.unpack_utf8()
        packet_id, = decoder.unpack(mqtt_io.FIELD_PACKET_ID)

        payload_len = header.remaining_len - decoder.num_bytes_consumed
        payload = decoder.read(payload_len)

        if header.remaining_len != decoder.num_bytes_consumed:
            raise DecodeError('Extra bytes at end of packet.')

        return decoder.num_bytes_consumed, MqttPublish(packet_id, topic_name, payload, dupe, qos, retain)

    def __repr__(self):
        msg = 'MqttPublish(packet_id={}, topic={}, payload=0x{}, dupe={}, qos={}, retain={})'
        return msg.format(
            self.packet_id,
            repr(self.topic),
            b2a_hex(self.payload),
            self.dupe,
            self.qos,
            self.retain)


class MqttPuback(MqttPacketBody):
    """
    Parameters
    ----------
    packet_id: int
        0 <= packet_id <= 2**16 -1
    """
    def __init__(self, packet_id):
        self.packet_id = packet_id

        MqttPacketBody.__init__(self, MqttControlPacketType.puback, 0)

    def encode_body(self, f):
        """

        Parameters
        ----------
        f: file
            File-like object with write method.

        Returns
        -------
        int
            Number of bytes written to file.
        """

        return f.write(mqtt_io.FIELD_U16.pack(self.packet_id))

    @classmethod
    def decode_body(cls, header, f):
        """Generates a `MqttPuback` packet given a
        `MqttFixedHeader`.  This method asserts that header.packet_type
        is `puback`.

        Parameters
        ----------
        header: MqttFixedHeader
        f: file
            Object with a read method.

        Raises
        ------
        DecodeError
            When there are extra bytes at the end of the packet.

        Returns
        -------
        int
            Number of bytes consumed from `f`.
        MqttPuback
            MqttPuback object extracted from `f`.
        """
        assert header.packet_type == MqttControlPacketType.puback

        decoder = mqtt_io.FileDecoder(mqtt_io.LimitReader(f, header.remaining_len))
        packet_id, = decoder.unpack(mqtt_io.FIELD_U16)

        if header.remaining_len != decoder.num_bytes_consumed:
            raise DecodeError('Extra bytes at end of packet.')

        return decoder.num_bytes_consumed, MqttPuback(packet_id)

    def __repr__(self):
        msg = 'MqttPuback(packet_id={})'
        return msg.format(self.packet_id)


class MqttPubrec(MqttPacketBody):
    """
    Parameters
    ----------
    packet_id: int
        0 <= packet_id <= 2**16 -1
    """
    def __init__(self, packet_id):
        self.packet_id = packet_id

        MqttPacketBody.__init__(self, MqttControlPacketType.pubrec, 0)

    def encode_body(self, f):
        """

        Parameters
        ----------
        f: file
            File-like object with write method.

        Returns
        -------
        int
            Number of bytes written to file.
        """

        return f.write(mqtt_io.FIELD_U16.pack(self.packet_id))

    @classmethod
    def decode_body(cls, header, f):
        """Generates a `MqttPubrec` packet given a
        `MqttFixedHeader`.  This method asserts that header.packet_type
        is `pubrec`.

        Parameters
        ----------
        header: MqttFixedHeader
        f: file
            Object with a read method.

        Raises
        ------
        DecodeError
            When there are extra bytes at the end of the packet.

        Returns
        -------
        int
            Number of bytes consumed from `f`.
        MqttPubrec
            MqttPubrec object extracted from `f`.
        """
        assert header.packet_type == MqttControlPacketType.pubrec

        decoder = mqtt_io.FileDecoder(mqtt_io.LimitReader(f, header.remaining_len))
        packet_id, = decoder.unpack(mqtt_io.FIELD_U16)

        if header.remaining_len != decoder.num_bytes_consumed:
            raise DecodeError('Extra bytes at end of packet.')

        return decoder.num_bytes_consumed, MqttPubrec(packet_id)

    def __repr__(self):
        msg = 'MqttPubrec(packet_id={})'
        return msg.format(self.packet_id)


class MqttPubrel(MqttPacketBody):
    """
    Parameters
    ----------
    packet_id: int
        0 <= packet_id <= 2**16 -1
    """
    def __init__(self, packet_id):
        self.packet_id = packet_id

        MqttPacketBody.__init__(self, MqttControlPacketType.pubrel, 2)

    def encode_body(self, f):
        """

        Parameters
        ----------
        f: file
            File-like object with write method.

        Returns
        -------
        int
            Number of bytes written to file.
        """

        return f.write(mqtt_io.FIELD_U16.pack(self.packet_id))

    @classmethod
    def decode_body(cls, header, f):
        """Generates a `MqttPubrel` packet given a
        `MqttFixedHeader`.  This method asserts that header.packet_type
        is `pubrel`.

        Parameters
        ----------
        header: MqttFixedHeader
        f: file
            Object with a read method.

        Raises
        ------
        DecodeError
            When there are extra bytes at the end of the packet.

        Returns
        -------
        int
            Number of bytes consumed from `f`.
        MqttPubrel
            MqttPubrel object extracted from `f`.
        """
        assert header.packet_type == MqttControlPacketType.pubrel

        decoder = mqtt_io.FileDecoder(mqtt_io.LimitReader(f, header.remaining_len))
        packet_id, = decoder.unpack(mqtt_io.FIELD_U16)

        if header.remaining_len != decoder.num_bytes_consumed:
            raise DecodeError('Extra bytes at end of packet.')

        return decoder.num_bytes_consumed, MqttPubrel(packet_id)

    def __repr__(self):
        msg = 'MqttPubrel(packet_id={})'
        return msg.format(self.packet_id)


class MqttPubcomp(MqttPacketBody):
    """
    Parameters
    ----------
    packet_id: int
        0 <= packet_id <= 2**16 -1
    """
    def __init__(self, packet_id):
        assert isinstance(packet_id, int)
        assert 0 <= packet_id <= 2**16-1

        self.__packet_id = packet_id

        MqttPacketBody.__init__(self, MqttControlPacketType.pubcomp, 0)

    @property
    def packet_id(self):
        """int: packet id such that 0 <= packet_id <= 2**16-1."""
        return self.__packet_id

    def encode_body(self, f):
        """

        Parameters
        ----------
        f: file
            File-like object with write method.

        Returns
        -------
        int
            Number of bytes written to file.
        """

        return f.write(mqtt_io.FIELD_U16.pack(self.packet_id))

    @classmethod
    def decode_body(cls, header, f):
        """Generates a `MqttPubcomp` packet given a
        `MqttFixedHeader`.  This method asserts that header.packet_type
        is `pubcomp`.

        Parameters
        ----------
        header: MqttFixedHeader
        f: file
            Object with a read method.

        Raises
        ------
        DecodeError
            When there are extra bytes at the end of the packet.

        Returns
        -------
        int
            Number of bytes consumed from `f`.
        MqttPubcomp
            MqttPubcomp object extracted from `f`.
        """
        assert header.packet_type == MqttControlPacketType.pubcomp

        decoder = mqtt_io.FileDecoder(mqtt_io.LimitReader(f, header.remaining_len))
        packet_id, = decoder.unpack(mqtt_io.FIELD_U16)

        if header.remaining_len != decoder.num_bytes_consumed:
            raise DecodeError('Extra bytes at end of packet.')

        return decoder.num_bytes_consumed, MqttPubcomp(packet_id)

    def __repr__(self):
        msg = 'MqttPubcomp(packet_id={})'
        return msg.format(self.packet_id)


class MqttUnsubscribe(MqttPacketBody):
    """
    Raises
    -------
    mqtt_codec.io.TooBigEncodeError
        The encoded length of topic parameters is too long to create an
        MQTT packet for.  The encoded lenghth must be greater than
        `MqttFixedHeader.MAX_REMAINING_LEN` (=268435455 bytes) in order
        to cause this error.

        Shorten the number of topics or the length of the topic strings.

    Parameters
    ----------
    packet_id: int
        0 <= packet_id <= 2**16 -1
    topics: iterable of str
    """
    def __init__(self, packet_id, topics):
        self.packet_id = packet_id
        self.topics = tuple(topics)

        if isinstance(topics, (str, unicode, bytes)):
            raise TypeError()

        assert len(topics) >= 1  # MQTT 3.10.3-2
        flags = 2  # MQTT 3.10.1-1
        MqttPacketBody.__init__(self, MqttControlPacketType.unsubscribe, flags)

    def encode_body(self, f):
        """

        Parameters
        ----------
        f: file
            File-like object with write method.

        Returns
        -------
        int
            Number of bytes written to file.
        """
        num_bytes_written = 0
        num_bytes_written += f.write(mqtt_io.FIELD_U16.pack(self.packet_id))
        for topic in self.topics:
            num_bytes_written += mqtt_io.encode_utf8(topic, f)

        return num_bytes_written

    @classmethod
    def decode_body(cls, header, f):
        """Generates a `MqttUnsubscribe` packet given a
        `MqttFixedHeader`.  This method asserts that header.packet_type
        is `unsubscribe`.

        Parameters
        ----------
        header: MqttFixedHeader
        f: file
            Object with a read method.

        Raises
        ------
        DecodeError
            When there are extra bytes at the end of the packet.

        Returns
        -------
        int
            Number of bytes consumed from `f`.
        MqttUnsubscribe
            MqttUnsubscribe object extracted from `f`.
        """
        assert header.packet_type == MqttControlPacketType.unsubscribe

        decoder = mqtt_io.FileDecoder(mqtt_io.LimitReader(f, header.remaining_len))
        packet_id, = decoder.unpack(mqtt_io.FIELD_PACKET_ID)

        topics = []
        while header.remaining_len > decoder.num_bytes_consumed:
            num_str_bytes, topic = decoder.unpack_utf8()
            topics.append(topic)

        assert header.remaining_len - decoder.num_bytes_consumed == 0

        return decoder.num_bytes_consumed, MqttUnsubscribe(packet_id, topics)

    def __repr__(self):
        return 'MqttUnsubscribe(packet_id={}, topics=[{}])'.format(self.packet_id, ', '.join(self.topics))


class MqttUnsuback(MqttPacketBody):
    """

    Parameters
    ----------
    packet_id: int
        0 <= packet_id <= 2**16-1
    """

    def __init__(self, packet_id):
        self.packet_id = packet_id

        MqttPacketBody.__init__(self, MqttControlPacketType.unsuback, 0)

    def encode_body(self, f):
        """

        Parameters
        ----------
        f: file
            File-like object with write method.

        Returns
        -------
        int
            Number of bytes written to file.
        """
        return f.write(mqtt_io.FIELD_U16.pack(self.packet_id))

    @classmethod
    def decode_body(cls, header, f):
        """Generates a `MqttUnsuback` packet given a
        `MqttFixedHeader`.  This method asserts that header.packet_type
        is `unsuback`.

        Parameters
        ----------
        header: MqttFixedHeader
        f: file
            Object with a read method.

        Raises
        ------
        DecodeError
            When there are extra bytes at the end of the packet.

        Returns
        -------
        int
            Number of bytes consumed from `f`.
        MqttUnsuback
            MqttUnsuback object extracted from `f`.
        """
        assert header.packet_type == MqttControlPacketType.unsuback

        decoder = mqtt_io.FileDecoder(mqtt_io.LimitReader(f, header.remaining_len))
        packet_id, = decoder.unpack(mqtt_io.FIELD_PACKET_ID)

        if header.remaining_len != decoder.num_bytes_consumed:
            raise DecodeError('Extra bytes at end of packet.')

        return decoder.num_bytes_consumed, MqttUnsuback(packet_id)

    def __repr__(self):
        return 'MqttUnsuback(packet_id={})'.format(self.packet_id)


class MqttPingreq(MqttPacketBody):
    def __init__(self):
        MqttPacketBody.__init__(self, MqttControlPacketType.pingreq, 0)

    def encode_body(self, f):
        """

        Parameters
        ----------
        f: file
            File-like object with write method.

        Returns
        -------
        int
            Number of bytes written to file.
        """
        return 0

    @classmethod
    def decode_body(cls, header, f):
        """Generates a `MqttPingreq` packet given a
        `MqttFixedHeader`.  This method asserts that header.packet_type
        is `pingreq`.

        Parameters
        ----------
        header: MqttFixedHeader
        f: file
            Object with a read method.

        Raises
        ------
        DecodeError
            When there are extra bytes at the end of the packet.

        Returns
        -------
        int
            Number of bytes consumed from `f`.
        MqttPingreq
            MqttPingreq object extracted from `f`.
        """
        assert header.packet_type == MqttControlPacketType.pingreq

        if header.remaining_len != 0:
            raise DecodeError('Extra bytes at end of packet.')

        return 0, MqttPingreq()

    def __repr__(self):
        return 'MqttPingreq()'


class MqttPingresp(MqttPacketBody):
    def __init__(self):
        MqttPacketBody.__init__(self, MqttControlPacketType.pingresp, 0)

    def encode_body(self, f):
        """

        Parameters
        ----------
        f: file
            File-like object with write method.

        Returns
        -------
        int
            Number of bytes written to file.
        """
        return 0

    @classmethod
    def decode_body(cls, header, f):
        """Generates a `MqttPingresp` packet given a
        `MqttFixedHeader`.  This method asserts that header.packet_type
        is `pingresp`.

        Parameters
        ----------
        header: MqttFixedHeader
        f: file
            Object with a read method.

        Raises
        ------
        DecodeError
            When there are extra bytes at the end of the packet.

        Returns
        -------
        int
            Number of bytes consumed from `f`.
        MqttPingresp
            MqttPingresp object extracted from `f`.
        """
        assert header.packet_type == MqttControlPacketType.pingresp

        if header.remaining_len != 0:
            raise DecodeError('Extra bytes at end of packet.')

        return 0, MqttPingresp()

    def __repr__(self):
        return 'MqttPingresp()'


class MqttDisconnect(MqttPacketBody):
    def __init__(self):
        MqttPacketBody.__init__(self, MqttControlPacketType.disconnect, 0)

    def encode_body(self, f):
        """

        Parameters
        ----------
        f: file
            File-like object with write method.

        Returns
        -------
        int
            Number of bytes written to file.
        """
        return 0

    @classmethod
    def decode_body(cls, header, f):
        """Generates a `MqttDisconnect` packet given a
        `MqttFixedHeader`.  This method asserts that header.packet_type
        is `disconnect`.

        Parameters
        ----------
        header: MqttFixedHeader
        f: file
            Object with a read method.

        Raises
        ------
        DecodeError
            When there are extra bytes at the end of the packet.

        Returns
        -------
        int
            Number of bytes consumed from `f`.
        MqttDisconnect
            MqttDisconnect object extracted from `f`.
        """
        assert header.packet_type == MqttControlPacketType.disconnect

        if header.remaining_len != 0:
            raise DecodeError('Extra bytes at end of packet.')

        return 0, MqttDisconnect()

    def __repr__(self):
        return 'MqttDisconnect()'