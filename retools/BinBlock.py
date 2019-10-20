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

class BinBlock():
	def __init__(self, data = None):
		if data is None:
			self._data = bytearray()
		else:
			self._data = bytearray(data)

	@classmethod
	def allbytes(cls, value, length):
		return cls(data = (value for i in range(length)))

	def _clone(self):
		return BinBlock(self._data)

	@property
	def spcstring(self):
		return " ".join("%02x" % (c) for c in self)

	def __or__(self, other):
		clone = self._clone()
		clone |= other
		return clone

	def __and__(self, other):
		clone = self._clone()
		clone &= other
		return clone

	def __iand__(self, other):
		assert(len(self) == len(other))
		for (index, value) in enumerate(other):
			self._data[index] &= value
		return self

	def __ior__(self, other):
		assert(len(self) == len(other))
		for (index, value) in enumerate(other):
			self._data[index] |= value
		return self

	def __invert__(self):
		negblock = BinBlock()
		negblock._data = bytearray((~value) & 0xff for value in self)
		return negblock

	def __getitem__(self, index):
		return self._data[index]

	def __len__(self):
		return len(self._data)

	def __repr__(self):
		return "<%s>" % (self._data.hex())
