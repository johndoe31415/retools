#	retools - Reverse engineering toolkit
#	Copyright (C) 2019-2020 Johannes Bauer
#
#	This file is part of retools.
#
#	retools is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	retools is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with retools; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import re
import base64
import collections
from .MultiRegex import MultiRegex, NoRegexMatchedException

class EncodingException(ValueError): pass

class EncodableTypes():
	_EncodedType = collections.namedtuple("EncodedType", [ "name", "value" ])
	_Encoder = collections.namedtuple("Encoder", [ "name", "encode" ])

	_KNOWN_ENCODING_PATTERNS = MultiRegex(collections.OrderedDict((
		("int",		re.compile(r"(?P<sign>[us])int(?P<len>\d+)(-(?P<endian>[bl?])e)?")),
		("str",		re.compile(r"str(-(?P<encoding>[-a-zA-Z0-9*]+))?")),
		("float",	re.compile(r"float(?P<length>\d+)?(-(?P<endian>[bl])e)?")),
		("hex",		re.compile(r"hex")),
		("base64",	re.compile(r"b(ase)?64")),
		("ip",		re.compile(r"ip")),
	)))
	_STR_ENCODING_ALIASES = {
		"lat1":		"latin1",
		"u16-be":	"utf-16-be",
		"u16-le":	"utf-16-le",
	}

	@classmethod
	def get_known_types(cls):
		return [ "[us]int-(len)-(endian)", "str-(encoding)" ]

	@classmethod
	def decode_int(cls, value):
		if value.startswith("0x") or value.startswith("0X"):
			return int(value, 16)
		elif value.startswith("0o"):
			return int(value, 8)
		else:
			return int(value)

	@classmethod
	def encode_uint(cls, value, little_endian, length):
		value = cls.decode_int(value)
		if value < 0:
			raise EncodingException("Unsigned int of %d bits must be greater or equal than zero, %d is not." % (8 * length, value))
		maxvalue = (256 ** length) - 1
		if value > maxvalue:
			raise EncodingException("Unsigned int of %d bits must be less or equal to %d, %d is not." % (8 * length, maxvalue, value))
		return value.to_bytes(length = length, byteorder = "little" if little_endian else "big")

	@classmethod
	def encode_sint(cls, value, little_endian, length):
		value = cls.decode_int(value)
		bits = 8 * length
		minvalue = -(2 ** (bits - 1))
		maxvalue = -minvalue - 1
		if value < minvalue:
			raise EncodingException("Signed int of %d bits must be greater or equal to %d, %d is not." % (bits, minvalue, value))
		if value > maxvalue:
			raise EncodingException("Signed int of %d bits must be less or equal to %d, %d is not." % (bits, maxvalue, value))
		if value < 0:
			value = (2 ** bits) + value
		return value.to_bytes(length = length, byteorder = "little" if little_endian else "big")

	@classmethod
	def _match_int(cls, pattern, name, match):
		sign = match["sign"] or "s"
		length = int(match["len"])
		endian = match["endian"] or "l"
		if (length % 8) != 0:
			raise EncodingException("Cannot encode '%s', bit length is not divisible by 8." % (pattern))
		if length <= 0:
			raise EncodingException("Cannot encode '%s', bit length must be at least 8." % (pattern))

		if endian in [ "b", "l" ]:
			endian_chars = [ endian ]
		else:
			endian_chars = [ "b", "l" ]

		for endian_char in endian_chars:
			little_endian = (endian_char == "l")
			length_bytes = length // 8
			if sign == "s":
				encoder = lambda value: cls.encode_sint(value, little_endian, length_bytes)
			else:
				encoder = lambda value: cls.encode_uint(value, little_endian, length_bytes)
			yield cls._Encoder(name = "%sint-%d-%se" % (sign, length, endian_char), encode = encoder)

	@classmethod
	def _match_str(cls, pattern, name, match):
		encoding = match["encoding"] or "utf-8"
		if encoding == "*":
			encodings = [ "utf-8", "utf-16-be", "utf-16-le", "latin1" ]
		else:
			encodings = [ cls._STR_ENCODING_ALIASES.get(encoding, encoding) ]

		for encoding in encodings:
			encoder = lambda value: value.encode(encoding = encoding)
			yield cls._Encoder(name = "str-%s" % (encoding), encode = encoder)

	@classmethod
	def _match_float(cls, pattern, name, match):
		length = int(match["length"] or "32")
		endian = match["endian"] or "l"
		raise NotImplementedError("Float support not yet implemented")

	@classmethod
	def _match_ip(cls, pattern, name, match):
		__ipv4_re = re.compile(r"(?P<a1>\d{1,3})\.(?P<a2>\d{1,3})\.(?P<a3>\d{1,3})\.(?P<a4>\d{1,3})")
		def _parse_ip(ip_str):
			match = __ipv4_re.fullmatch(ip_str)
			if not match:
				raise ValueError("Not a valid value for an IPv4 address: %s" % (ip_str))
			match = match.groupdict()
			match = { name: int(value) for (name, value) in match.items() }
			if not all(0 <= value <= 255 for value in match.values()):
				raise ValueError("Not a valid value for an IPv4 address: %s" % (ip_str))
			return (match["a1"], match["a2"], match["a3"], match["a4"])

		def _encode_ip_str(ip_str):
			ip = _parse_ip(ip_str)
			return ("%d.%d.%d.%d" % (ip[0], ip[1], ip[2], ip[3])).encode("ascii")

		def _encode_ip_be_int(ip_str):
			ip = _parse_ip(ip_str)
			return bytes(ip)

		def _encode_ip_le_int(ip_str):
			ip = _parse_ip(ip_str)
			return bytes(reversed(ip))

		yield cls._Encoder(name = "ipv4-str", encode = _encode_ip_str)
		yield cls._Encoder(name = "ipv4-be", encode = _encode_ip_be_int)
		yield cls._Encoder(name = "ipv4-le", encode = _encode_ip_le_int)

	@classmethod
	def _match_hex(cls, pattern, name, match):
		yield cls._Encoder(name = name, encode = lambda value: bytes.fromhex(value))

	@classmethod
	def _match_base64(cls, pattern, name, match):
		yield cls._Encoder(name = name, encode = lambda value: base64.b64decode(value))

	@classmethod
	def encode(cls, value, encode_as):
		try:
			encoders = cls._KNOWN_ENCODING_PATTERNS.fullmatch(encode_as, callback = cls, groupdict = True)
		except NoRegexMatchedException:
			raise EncodingException("Unknown encoding type '%s'." % (encode_as))
		for encoder in encoders:
			encoded_data = encoder.encode(value)
			yield cls._EncodedType(name = encoder.name, value = encoded_data)

	@classmethod
	def encode_argument(cls, argument):
		encoding_value = argument.split(":", maxsplit = 1)
		if len(encoding_value) != 2:
			raise EncodingException("Cannot encode '%s', missing type/value." % (argument))
		(encode_as, value) = encoding_value
		return cls.encode(value = value, encode_as = encode_as)

if __name__ == "__main__":
	assert(EncodableTypes.encode("1234", "uint16") == bytes.fromhex("d2 04"))
	assert(EncodableTypes.encode("1234", "uint32") == bytes.fromhex("d2 04 00 00"))
	assert(EncodableTypes.encode("1234", "uint16-be") == bytes.fromhex("04 d2"))
	assert(EncodableTypes.encode("-1", "sint8") == bytes.fromhex("ff"))
	assert(EncodableTypes.encode("127", "sint8") == bytes.fromhex("7f"))
	assert(EncodableTypes.encode("-128", "sint8") == bytes.fromhex("80"))
	assert(EncodableTypes.encode("-1", "sint16") == bytes.fromhex("ff ff"))
	assert(EncodableTypes.encode("-2", "sint16") == bytes.fromhex("fe ff"))
	assert(EncodableTypes.encode("1234", "str") == b"1234")
	assert(EncodableTypes.encode("1234", "str-u16-le") == b"1\x002\x003\x004\x00")
	assert(EncodableTypes.encode("aabbcc", "hex") == bytes.fromhex("aa bb cc"))
	assert(EncodableTypes.encode("Zm9vYmFy", "b64") == b"foobar")
	assert(EncodableTypes.encode("12.34", "float32-le") == bytes.fromhex("a4 70 45 41"))
	assert(EncodableTypes.encode("12.34", "float64-le") == bytes.fromhex("ae 47 e1 7a 14 ae 28 40"))
