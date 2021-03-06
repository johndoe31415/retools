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

from retools.unpack import Classifier
from retools.NamedStruct import NamedStruct

@Classifier.register
class UBootImageClassifier(Classifier):
	_NAME = "uboot"
	_SUFFIX = ".uboot"
	_UBootHeader = NamedStruct([
		("L", "magic"),
		("L", "hdr_crc"),
		("L", "time"),
		("L", "size"),
		("L", "load_addr"),
		("L", "entry_point"),
		("L", "data_crc"),
		("B", "os"),
		("B", "arch"),
		("B", "img_type"),
		("B", "compression"),
		("32s", "img_name"),
	], struct_extra = ">")

	def scan(self, chunk):
		header = bytes.fromhex("27 05 19 56")
		yield from self._bytes_findall(chunk, header)

	def investigate(self, infile, offset):
		header = self._UBootHeader.unpack_from_file(infile)
		return (offset, self._UBootHeader.size + header.size)

	def extract(self, input_file, start_offset, file_length, destination):
		header = self._UBootHeader.unpack_from_file(input_file, start_offset)
		return self.carve_extract(input_file = input_file, start_offset = start_offset + self._UBootHeader.size, file_length = header.size, destination = destination)
