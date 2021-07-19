#	retools - Reverse engineering toolkit
#	Copyright (C) 2020-2020 Johannes Bauer
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
from retools.unpack import Classifier, TemporaryCarveClassifier

@Classifier.register
class DexClassifier(TemporaryCarveClassifier):
	_NAME = "dex"
	_SUFFIX = ".dex"

	def scan(self, chunk):
		header = b"dex\n"
		yield from self._bytes_findall(chunk, header)

	def investigate(self, infile, offset):
		infile.seek(offset + 4)
		version = infile.read(3)
		version = version.decode("latin1")
		if version.isdigit():
			infile.seek(offset + 0x20)
			length = int.from_bytes(infile.read(4), byteorder = "little")
			return (offset, length)

	def extract_from_temporary_carved_file(self, temp_filename, destination):
		subprocess.check_call([ "dex2jar", "-o", destination, temp_filename ])
