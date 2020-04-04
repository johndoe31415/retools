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

import unittest
from retools.EncodableTypes import EncodableTypes, EncodingException

class EncodingTests(unittest.TestCase):
	def _encode_values(self, str_repr, str_type):
		encoded_values = list(EncodableTypes.encode(str_repr, str_type))
		result = [ encoded_value.value for encoded_value in encoded_values ]
		if len(result) == 1:
			return result[0]
		else:
			return result

	def test_uint8(self):
		self.assertEqual(self._encode_values("0", "uint8"), bytes.fromhex("00"))
		self.assertEqual(self._encode_values("1", "uint8"), bytes.fromhex("01"))
		self.assertEqual(self._encode_values("171", "uint8"), bytes.fromhex("ab"))
		self.assertEqual(self._encode_values("255", "uint8"), bytes.fromhex("ff"))
		with self.assertRaises(EncodingException):
			self._encode_values("256", "uint8")
		with self.assertRaises(EncodingException):
			self._encode_values("-1", "uint8")

	def test_uint_lengths(self):
		self.assertEqual(self._encode_values("123", "uint8"), bytes.fromhex("7b"))
		self.assertEqual(self._encode_values("1234", "uint16"), bytes.fromhex("d2 04"))
		self.assertEqual(self._encode_values("12345", "uint24"), bytes.fromhex("39 30 00"))

		self.assertEqual(self._encode_values("123", "uint8-be"), bytes.fromhex("7b"))
		self.assertEqual(self._encode_values("1234", "uint16-be"), bytes.fromhex("04 d2"))
		self.assertEqual(self._encode_values("12345", "uint24-be"), bytes.fromhex("00 30 39"))

	def test_sint8(self):
		self.assertEqual(self._encode_values("0", "sint8"), bytes.fromhex("00"))
		self.assertEqual(self._encode_values("-1", "sint8"), bytes.fromhex("ff"))
		self.assertEqual(self._encode_values("-2", "sint8"), bytes.fromhex("fe"))
		self.assertEqual(self._encode_values("127", "sint8"), bytes.fromhex("7f"))
		self.assertEqual(self._encode_values("-128", "sint8"), bytes.fromhex("80"))
		with self.assertRaises(EncodingException):
			self._encode_values("128", "sint8")
		with self.assertRaises(EncodingException):
			self._encode_values("-129", "sint8")

	def test_str(self):
		self.assertEqual(self._encode_values("1234", "str"), b"1234")
		self.assertEqual(self._encode_values("Jöe", "str"), b"J\xc3\xb6e")

		self.assertEqual(self._encode_values("1234", "str-latin1"), b"1234")
		self.assertEqual(self._encode_values("Jöe", "str-latin1"), b"J\xf6e")

		self.assertEqual(self._encode_values("1234", "str-u16-le"), bytes.fromhex("31 00 32 00 33 00 34 00"))
		self.assertEqual(self._encode_values("1234", "str-u16-be"), bytes.fromhex("00 31 00 32 00 33 00 34"))

	def test_b64(self):
		self.assertEqual(self._encode_values("Zm9vYmFy", "b64"), b"foobar")

	def test_hex(self):
		self.assertEqual(self._encode_values("aa bb cc", "hex"), bytes.fromhex("aa bb cc"))
