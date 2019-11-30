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
from retools.EncodableTypes import EncodableTypes, EncodingException

class EncodingTests(unittest.TestCase):
	def test_uint8(self):
		self.assertEqual(EncodableTypes.encode("0", "uint8"), bytes.fromhex("00"))
		self.assertEqual(EncodableTypes.encode("1", "uint8"), bytes.fromhex("01"))
		self.assertEqual(EncodableTypes.encode("171", "uint8"), bytes.fromhex("ab"))
		self.assertEqual(EncodableTypes.encode("255", "uint8"), bytes.fromhex("ff"))
		with self.assertRaises(EncodingException):
			EncodableTypes.encode("256", "uint8")
		with self.assertRaises(EncodingException):
			EncodableTypes.encode("-1", "uint8")

	def test_uint_lengths(self):
		self.assertEqual(EncodableTypes.encode("123", "uint8"), bytes.fromhex("7b"))
		self.assertEqual(EncodableTypes.encode("1234", "uint16"), bytes.fromhex("d2 04"))
		self.assertEqual(EncodableTypes.encode("12345", "uint24"), bytes.fromhex("39 30 00"))

		self.assertEqual(EncodableTypes.encode("123", "uint8-be"), bytes.fromhex("7b"))
		self.assertEqual(EncodableTypes.encode("1234", "uint16-be"), bytes.fromhex("04 d2"))
		self.assertEqual(EncodableTypes.encode("12345", "uint24-be"), bytes.fromhex("00 30 39"))

	def test_sint8(self):
		self.assertEqual(EncodableTypes.encode("0", "sint8"), bytes.fromhex("00"))
		self.assertEqual(EncodableTypes.encode("-1", "sint8"), bytes.fromhex("ff"))
		self.assertEqual(EncodableTypes.encode("-2", "sint8"), bytes.fromhex("fe"))
		self.assertEqual(EncodableTypes.encode("127", "sint8"), bytes.fromhex("7f"))
		self.assertEqual(EncodableTypes.encode("-128", "sint8"), bytes.fromhex("80"))
		with self.assertRaises(EncodingException):
			EncodableTypes.encode("128", "sint8")
		with self.assertRaises(EncodingException):
			EncodableTypes.encode("-129", "sint8")

	def test_str(self):
		self.assertEqual(EncodableTypes.encode("1234", "str"), b"1234")
		self.assertEqual(EncodableTypes.encode("Jöe", "str"), b"J\xc3\xb6e")

	def test_b64(self):
		self.assertEqual(EncodableTypes.encode("Zm9vYmFy", "b64"), b"foobar")

	def test_hex(self):
		self.assertEqual(EncodableTypes.encode("aa bb cc", "hex"), bytes.fromhex("aa bb cc"))
