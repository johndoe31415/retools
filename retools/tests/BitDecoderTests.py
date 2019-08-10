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

import unittest
from retools.BitDecoder import BitDecoder

class BitDecoderTests(unittest.TestCase):
	def test_encode_byte_msb_first(self):
		self.assertEqual(BitDecoder.encode_bitstream(""), bytes.fromhex(""))
		self.assertEqual(BitDecoder.encode_bitstream("1010 0010"), bytes.fromhex("a2"))
		self.assertEqual(BitDecoder.encode_bitstream("1010 0010 0"), bytes.fromhex("a2 00"))
		self.assertEqual(BitDecoder.encode_bitstream("1010 0010 01"), bytes.fromhex("a2 40"))
		self.assertEqual(BitDecoder.encode_bitstream("1010 0010 11"), bytes.fromhex("a2 c0"))

	def test_encode_byte_lsb_first(self):
		self.assertEqual(BitDecoder.encode_bitstream("", bitorder = "lsb_first"), bytes.fromhex(""))
		self.assertEqual(BitDecoder.encode_bitstream("1010 0010", bitorder = "lsb_first"), bytes.fromhex("45"))
		self.assertEqual(BitDecoder.encode_bitstream("1010 0010 0", bitorder = "lsb_first"), bytes.fromhex("45 00"))
		self.assertEqual(BitDecoder.encode_bitstream("1010 0010 01", bitorder = "lsb_first"), bytes.fromhex("45 02"))
		self.assertEqual(BitDecoder.encode_bitstream("1010 0010 11", bitorder = "lsb_first"), bytes.fromhex("45 03"))


	def test_bytewise(self):
		bdec = BitDecoder(bytes.fromhex("12 34 56"))
		self.assertEqual(bdec.get_int(8), 0x12)
		self.assertEqual(bdec.get_int(8), 0x34)
		self.assertEqual(bdec.get_int(8), 0x56)

	def test_bitwise(self):
		bdec = BitDecoder(bytes.fromhex("12 ff ff"), bitorder = "msb_first")
		self.assertEqual(bdec.get_bool(), False)
		self.assertEqual(bdec.get_bool(), False)
		self.assertEqual(bdec.get_bool(), False)
		self.assertEqual(bdec.get_bool(), True)

		self.assertEqual(bdec.get_bool(), False)
		self.assertEqual(bdec.get_bool(), False)
		self.assertEqual(bdec.get_bool(), True)
		self.assertEqual(bdec.get_bool(), False)

	def test_lsb_first(self):
		bdec = BitDecoder(bytes.fromhex("12 34 56"), bitorder = "lsb_first")
		self.assertEqual(bdec.get_int(8), 0x48)
		self.assertEqual(bdec.get_int(8), 0x2c)
		self.assertEqual(bdec.get_int(8), 0x6a)

	def test_lsb_first_bitwise(self):
		bdec = BitDecoder(bytes.fromhex("12 ff ff"), bitorder = "lsb_first")
		self.assertEqual(bdec.get_bool(), False)
		self.assertEqual(bdec.get_bool(), True)
		self.assertEqual(bdec.get_bool(), False)
		self.assertEqual(bdec.get_bool(), False)

		self.assertEqual(bdec.get_bool(), True)
		self.assertEqual(bdec.get_bool(), False)
		self.assertEqual(bdec.get_bool(), False)
		self.assertEqual(bdec.get_bool(), False)

	def test_big_endian_msb_first(self):
		bdec = BitDecoder(bytes.fromhex("12 34"), bitorder = "msb_first", byteorder = "big")
		self.assertEqual(bdec.get_int(16), 0x1234)

	def test_little_endian_msb_first(self):
		bdec = BitDecoder(bytes.fromhex("12 34"), bitorder = "msb_first", byteorder = "little")
		self.assertEqual(bdec.get_int(16), 0x3412)

	def test_big_endian_lsb_first(self):
		bdec = BitDecoder(bytes.fromhex("12 34"), bitorder = "lsb_first", byteorder = "big")
		self.assertEqual(bdec.get_int(16), 0x482c)

	def test_little_endian_lsb_first(self):
		bdec = BitDecoder(bytes.fromhex("12 34"), bitorder = "lsb_first", byteorder = "little")
		self.assertEqual(bdec.get_int(16), 0x2c48)

	def test_shifted(self):
		bdec = BitDecoder(BitDecoder.encode_bitstream("0 11111111 0101"))
		self.assertEqual(bdec.get_bool(), False)
		self.assertEqual(bdec.get_int(8), 0xff)
		self.assertEqual(bdec.get_bool(), False)
		self.assertEqual(bdec.get_bool(), True)
		self.assertEqual(bdec.get_bool(), False)
		self.assertEqual(bdec.get_bool(), True)

	def test_shifted_lsb_first(self):
		bdec = BitDecoder(BitDecoder.encode_bitstream("0 11111111 0101", bitorder = "lsb_first"), bitorder = "lsb_first")
		self.assertEqual(bdec.get_bool(), False)
		self.assertEqual(bdec.get_int(8), 0xff)
		self.assertEqual(bdec.get_bool(), False)
		self.assertEqual(bdec.get_bool(), True)
		self.assertEqual(bdec.get_bool(), False)
		self.assertEqual(bdec.get_bool(), True)

	def test_aligned_msb_first(self):
		bdec = BitDecoder(BitDecoder.encode_bitstream("1010 1111 1100 0011"))
		self.assertEqual(bdec.get_int(8), 0b10101111)
		self.assertEqual(bdec.get_int(8), 0b11000011)

	def test_aligned_lsb_first(self):
		bdec = BitDecoder(BitDecoder.encode_bitstream("1010 1111 1100 0011", bitorder = "lsb_first"), bitorder = "lsb_first")
		self.assertEqual(bdec.get_int(8), 0b10101111)
		self.assertEqual(bdec.get_int(8), 0b11000011)

	def test_endianness_little(self):
		bdec = BitDecoder(bytes.fromhex("11 22 33 44"))
		self.assertEqual(bdec.get_int(32), 0x44332211)

	def test_endianness_big(self):
		bdec = BitDecoder(bytes.fromhex("11 22 33 44"), byteorder = "big")
		self.assertEqual(bdec.get_int(32), 0x11223344)
