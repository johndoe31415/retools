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
class SquashFSClassifier(MultiFileExtractorClassifier):
	# TODO: Currently little endian SquashFS only
	_NAME = "squashfs"
	_SUFFIX = ".sqfs"
	_SquashFSHeader = NamedStruct([
		("L", "magic"),
		("L", "inode_count"),
		("l", "modification_time"),
		("L", "block_size"),
		("L", "fragment_entry_count"),
		("H", "compression_id"),
		("H", "block_log"),
		("H", "flags"),
		("H", "id_count"),
		("H", "version_major"),
		("H", "version_minor"),
		("Q", "root_inode_ref"),
		("Q", "bytes_used"),
		("Q", "id_table_start"),
		("Q", "xattr_id_table_start"),
		("Q", "inode_table_start"),
		("Q", "directory_table_start"),
		("Q", "fragment_table_start"),
		("Q", "export_table_start"),
	], struct_extra = "<")

	def scan(self, chunk):
		header = bytes.fromhex("68 73 71 73")
		yield from self._bytes_findall(chunk, header)

	def investigate(self, infile, offset):
		header = self._SquashFSHeader.unpack_from_file(infile)
		return (offset, self._SquashFSHeader.size + header.bytes_used)

	def get_extract_cmdline(self, archive_name):
		return [ "unsquashfs", archive_name ]

