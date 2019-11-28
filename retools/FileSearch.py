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

import collections

class FileSearch():
	_Occurrence = collections.namedtuple("Occurrence", [ "filename", "offset", "pre", "post" ])
	_MIN_CHUNK_SIZE = 1024 * 1024

	def __init__(self, filename, context_size = 32):
		self._filename = filename
		self._context_size = context_size
		pass

	def _read_before(self, f, offset):
		pre_offset = max(0, offset - self._context_size)
		pre_size = offset - pre_offset
		f.seek(pre_offset)
		return f.read(pre_size)

	def _read_after(self, f, offset):
		f.seek(offset)
		return f.read(self._context_size)

	def find_all(self, needle):
		chunk_size = self._MIN_CHUNK_SIZE + len(needle)
		with open(self._filename, "rb") as f:
			file_offset = 0
			while True:
				f.seek(file_offset)
				chunk = f.read(chunk_size)

				# Find all matches
				chunk_offset = 0
				while True:
					match_offset = chunk.find(needle, chunk_offset)
					if match_offset == -1:
						break
					abs_offset = match_offset + file_offset
					pre = self._read_before(f, abs_offset)
					post = self._read_after(f, abs_offset + len(needle))
					yield self._Occurrence(filename = self._filename, offset = abs_offset, pre = pre, post = post)
					chunk_offset = match_offset + 1

				if len(chunk) != chunk_size:
					# End of file
					break

				# Do not advance full chunk size, or we won't catch patterns at
				# the chunk border
				file_offset += self._MIN_CHUNK_SIZE + 1

if __name__ == "__main__":
	fs = FileSearch("/tmp/x")
	for offset in fs.find_all(b"foobar"):
		print(offset)
