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

class BitDecoder(object):
	def __init__(self, raw_data, bitorder = "msb_first", byteorder = "little"):
		assert(bitorder in [ "msb_first", "lsb_first" ])
		assert(byteorder in [ "little", "big" ])
		assert(isinstance(raw_data, bytes))
		self._data = raw_data
		self._msb_first = (bitorder == "msb_first")
		self._byteorder = byteorder
		self._pos = 0

	@classmethod
	def encode_bitstream(cls, text, bitorder = "msb_first"):
		assert(bitorder in [ "msb_first", "lsb_first" ])
		result = [ ]
		(next_value, bits_captured) = (0, 0)
		for char in text:
			if char in [ "0", "1" ]:
				bit = int(char == "1")
				if bitorder == "msb_first":
					next_value = (next_value << 1) | bit
				else:
					next_value = (next_value >> 1) | (bit * 0x80)
				bits_captured += 1
				if bits_captured == 8:
					result.append(next_value)
					(next_value, bits_captured) = (0, 0)

		if bits_captured > 0:
			missing_bits = 8 - bits_captured
			if bitorder == "msb_first":
				next_value <<= missing_bits
			else:
				next_value >>= missing_bits
			result.append(next_value)
		return bytes(result)

	@staticmethod
	def _flip_bit_order(byte):
		result = 0
		for i in range(8):
			if (byte >> i) & 1:
				result |= (1 << (7 - i))
		return result

	def get_bit_at(self, pos):
		byte_index = pos // 8
		bit_index = pos % 8
		if self._msb_first:
			bit_index = 7 - bit_index
		return (self._data[byte_index] >> bit_index) & 1

	def get_bool_at(self, pos):
		return bool(self.get_bit_at(pos))

	def get_bool(self):
		value = self.get_bool_at(self._pos)
		self._pos += 1
		return value

	def get_int(self, length):
		assert(isinstance(length, int))
		assert(length > 0)
		shift_index = self._pos % 8
		if shift_index != 0:
			shift_index = 8 - shift_index
#		print("get_int(%d): [%s / %s / %s] pos %d shift %d" % (length, self._data.hex(), "msb_first" if self._msb_first else "lsb_first", self._byteorder, self._pos, shift_index))

		# We first need to determine the correct byte range and carve it out of
		# the data
		start_byte_index = self._pos // 8
		end_byte_index = (self._pos + length + 7) // 8
		int_data = self._data[start_byte_index : end_byte_index]
		if not self._msb_first:
			# For LSB first data, we flip the bitorder in each byte now
			int_data = bytes(self._flip_bit_order(byte) for byte in int_data)
#		print("carved converted data [%d : %d]: %s" % (start_byte_index, end_byte_index, int_data.hex()))

		# Then we shift the value to the right
		int_value = int.from_bytes(int_data, byteorder = "big")
		int_value >>= shift_index
#		print("unmasked shifted int value: 0x%x" % (int_value))

		if self._byteorder == "little":
			# If we're dealing with multi-byte values, we fix endianness at
			# this point
			byte_length = (int_value.bit_length() + 7) // 8
			int_value = int.to_bytes(int_value, byteorder = "big", length = byte_length)
			int_value = int.from_bytes(int_value, byteorder = self._byteorder)

		# Finally mask out the unneeded high-order bits
		mask_value = (1 << length) - 1
		int_value &= mask_value
#		print("mask: 0x%x -> 0x%x" % (mask_value, int_value))
		self._pos += length
		return int_value

	def unpack_from_file(self, f, at_offset = None):
		if at_offset is not None:
			f.seek(at_offset)
		data = f.read(self._struct.size)
		return self.unpack(data)

	def __str__(self):
		return "Bits<%s, pos %#x>" % (self._data.hex(), self._pos)
