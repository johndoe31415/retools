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

@Classifier.register
class UBootImageClassifier(MultiFileExtractorClassifier):
	_NAME = "uboot"
	_SUFFIX = ".uboot"
	_HDR_STRUCT = struct.Struct("< L L L L L L L B B B B 32s")
	_HDR_FIELDS = collections.namedtuple("HdrFields", [ "magic", "hdr_crc", "time", "size", "load", "entry_point", "data_crc", "os", "arch", "img_type", "compression", "img_name" ])

	def scan(self, chunk):
		header = bytes.fromhex("27 05 19 56")
		yield from self._bytes_findall(chunk, header)

	def _get_cmdline(self, archive_name):
		print("UBOOT")
		return [ "echo", archive_name ]
#		return [ "unzip", "-n", archive_name ]
