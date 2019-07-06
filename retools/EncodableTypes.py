#	retools - Reverse engineering toolkit
#	Copyright (C) 2019-2019 Johannes Bauer
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

import collections

class EncodingException(ValueError): pass

class EncodableTypes():
	@classmethod
	def get_known_types(cls):
		return cls._KNOWN_TYPES.keys()

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
	def encode_string(cls, value, encoding):
		return value.encode(encoding)

	@classmethod
	def encode(cls, value, encode_as):
		encoder = cls._KNOWN_TYPES[encode_as]
		return encoder(value)


	_KNOWN_TYPES = collections.OrderedDict([
		("uint8",		lambda x: EncodableTypes.encode_uint(x, little_endian = True, length = 1)),
		("uint16",		lambda x: EncodableTypes.encode_uint(x, little_endian = True, length = 2)),
		("uint32",		lambda x: EncodableTypes.encode_uint(x, little_endian = True, length = 4)),
		("uint64",		lambda x: EncodableTypes.encode_uint(x, little_endian = True, length = 8)),
		("uint16-be",	lambda x: EncodableTypes.encode_uint(x, little_endian = False, length = 2)),
		("uint32-be",	lambda x: EncodableTypes.encode_uint(x, little_endian = False, length = 4)),
		("uint64-be",	lambda x: EncodableTypes.encode_uint(x, little_endian = False, length = 8)),
		("sint8",		lambda x: EncodableTypes.encode_sint(x, little_endian = True, length = 1)),
		("sint16",		lambda x: EncodableTypes.encode_sint(x, little_endian = True, length = 2)),
		("sint32",		lambda x: EncodableTypes.encode_sint(x, little_endian = True, length = 4)),
		("sint64",		lambda x: EncodableTypes.encode_sint(x, little_endian = True, length = 8)),
		("sint16-be",	lambda x: EncodableTypes.encode_sint(x, little_endian = False, length = 2)),
		("sint32-be",	lambda x: EncodableTypes.encode_sint(x, little_endian = False, length = 4)),
		("sint64-be",	lambda x: EncodableTypes.encode_sint(x, little_endian = False, length = 8)),
		("str",			lambda x: EncodableTypes.encode_string(x, encoding = "utf-8")),
		("str-lat1",	lambda x: EncodableTypes.encode_string(x, encoding = "latin1")),
		("str-u16-be",	lambda x: EncodableTypes.encode_string(x, encoding = "utf-16-be")),
		("str-u16-le",	lambda x: EncodableTypes.encode_string(x, encoding = "utf-16-le")),
	])

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
