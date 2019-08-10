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

import subprocess
from retools.NamedStruct import NamedStruct
from retools.unpack import Classifier, StdoutDecompressClassifier
from retools.BitDecoder import BitDecoder

@Classifier.register
class BZIP2Classifier(StdoutDecompressClassifier):
	_NAME = "bz2"
	_COMMANDLINE = [ "bzcat", "--decompress" ]
	_BZ2Header = NamedStruct((
		("h",	"magic"),
		("s",	"version"),
		("s",	"blocksize"),
		("6s",	"compressed_magic"),
		("L",	"crc"),
	))

	def scan(self, chunk):
		header = b"BZh"
		yield from self._bytes_findall(chunk, header)

	def investigate(self, input_file, start_offset):
		header = self._BZ2Header.unpack_from_file(input_file, start_offset)
		if header.compressed_magic != b"1AY&SY":
			return None
		return (start_offset, None)
#		header_bits = BitDecoder(input_file.read(16))
#		randomized = header_bits.get_bool()
#		orig_ptr = header_bits.get_int(24)
#		used_map = header_bits.get_int(16)
#		print(randomized, orig_ptr, used_map)
#		return None
