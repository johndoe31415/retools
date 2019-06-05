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
class PKZIPClassifier(MultiFileExtractorClassifier):
	_NAME = "zip"
	_SUFFIX = ".zip"
	_CentralDirectory = NamedStruct([
		("L", "signature"),
		("H", "version"),
		("H", "version_needed"),
		("H", "flags"),
		("H", "compression"),
		("H", "mod_time"),
		("H", "mod_date"),
		("L", "crc32"),
		("L", "compressed_size"),
		("L", "uncompressed_size"),
	])
	_EndOfCentralDirectory = NamedStruct([
		("L", "signature"),
		("H", "disk_number"),
		("H", "disk_number_with_cd"),
		("H", "disk_entries"),
		("H", "total_entries"),
		("L", "central_directory_size"),
		("L", "offset_of_central_directory"),
		("H", "comment_length"),
	])

	def scan(self, chunk):
		# Search for end of central directory record
		yield from self._bytes_findall(chunk, b"PK\x05\x06")

	def investigate(self, infile, offset):
		eocd = self._EndOfCentralDirectory.unpack_from_file(infile)
		file_end_offset = offset + 0x16 + eocd.comment_length

		cd_offset = offset - eocd.central_directory_size
		cd = self._CentralDirectory.unpack_from_file(infile, cd_offset)
		if cd.signature != 0x2014b50:
			# CD does not precede EOCD
			return None

		file_start_offset = offset - eocd.central_directory_size - eocd.offset_of_central_directory

		file_length = file_end_offset - file_start_offset
		return (file_start_offset, file_length)

	def get_extract_cmdline(self, archive_name):
		return [ "unzip", "-n", archive_name ]
