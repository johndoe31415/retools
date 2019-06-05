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

from retools.unpack import Classifier, MultiFileExtractorClassifier
from retools.NamedStruct import NamedStruct

@Classifier.register
class CramFSClassifier(MultiFileExtractorClassifier):
	_NAME = "cramfs"
	_SUFFIX = ".cramfs"
	_CramFSHeader = NamedStruct([
		("L", "magic"),
		("L", "size"),
		("L", "flags"),
		("L", "future"),
		("16s", "signature"),
		("L", "fsid_crc"),
		("L", "fsid_edition"),
		("L", "fsid_blocks"),
		("L", "fsid_files"),
		("16s", "name"),
	], struct_extra = "<")

	def scan(self, chunk):
		header = bytes.fromhex("45 3d cd 28")
		yield from self._bytes_findall(chunk, header)

	def investigate(self, infile, offset):
		header = self._CramFSHeader.unpack_from_file(infile)
		return (offset, self._CramFSHeader.size + header.size)

	def get_extract_cmdline(self, archive_name):
		return [ "uncramfs", archive_name ]
