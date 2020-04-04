#!/usr/bin/python3
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

import sys
import re
from retools.FriendlyArgumentParser import FriendlyArgumentParser

class FWExtractor():
	_HEX_LINE = re.compile("^:(?P<checksummed_payload>(?P<length>[A-Fa-f0-9]{2})(?P<load_offset>[A-Fa-f0-9]{4})(?P<data_type>[A-Fa-f0-9]{2})(?P<data>[A-Fa-f0-9]+))(?P<checksum>[A-Fa-f0-9]{2})")

	def __init__(self, args):
		self._args = args
		self._addr_high_word = 0
		self._chunks = { }

	@classmethod
	def from_commandline(cls):
		parser = FriendlyArgumentParser()
		parser.add_argument("-x", "--hex-dump", action = "store_true", help = "Show every occurrence as a hex dump.")
		parser.add_argument("-c", "--context", metavar = "bytes", type = int, default = 32, help = "Display this amount of context around occurrences.")
		parser.add_argument("-r", "--recurse", action = "store_true", help = "Recurse into subdirectories.")
		parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Be more verbose. Can be specified multiple times.")
		parser.add_argument("filename", metavar = "filename", type = str, help = "Hex firmware file that should be extracted")
		args = parser.parse_args(sys.argv[1:])
		return cls(args = args)

	def _update_chunk(self, chunk_start_address, new_address, new_chunk):
		current_chunk = self._chunks[chunk_start_address]
		chunk_end_address = chunk_start_address + len(current_chunk)
		if new_address == chunk_end_address:
			# Append at current chunk
			current_chunk += new_chunk
		elif new_address > chunk_end_address:
			# Small gap in the code
			gap_size = new_address - chunk_end_address
			if self._args.verbose >= 2:
				print("Gap detected, new chunk at 0x%x, previous end at 0x%x, gap size %d bytes" % (new_address, chunk_end_address, gap_size))
			current_chunk += bytes(gap_size)
			current_chunk += new_chunk
		elif new_address + len(new_chunk) == chunk_start_address:
			# New start
			replacement_chunk = bytearray(new_chunk) + current_chunk
			del self._chunks[chunk_start_address]
			self._chunks[new_address] = replacement_chunk
		else:
			raise NotImplementedError("Unimplemented: Current chunk at [0x%x len 0x%x] new chunk at [0x%x len 0x%x]" % (chunk_start_address, len(current_chunk), new_address, len(new_chunk)))

	def _interpret_data_chunk(self, address, chunk):
		for (start_address, present_chunk) in self._chunks.items():
			end_address = start_address + len(present_chunk)
			range_min = start_address - 0x100
			range_max = end_address + 0x100
			if range_min <= address <= range_max:
				# Belongs to this chunk!
				self._update_chunk(start_address, address, chunk)
				break
		else:
			# No chunk found.
			self._chunks[address] = bytearray(chunk)

	def _interpret_data(self, match):
		data_type = match["data_type"][0]
		load_offset = int.from_bytes(match["load_offset"], byteorder = "big")
		data = match["data"]
		if data_type == 0x00:
			# Data Record
			address = self._addr_high_word | load_offset
			self._interpret_data_chunk(address, data)
		elif data_type == 0x04:
			# Extended Linear Address Record
			self._addr_high_word = int.from_bytes(data, byteorder = "big") << 16
		elif data_type == 0x05:
			# Start Linear Address Record
			ip = int.from_bytes(data, byteorder = "big")
			if self._args.verbose >= 1:
				print("Entry point at 0x%x" % (ip))
		else:
			raise NotImplementedError("Unspoorted data field 0x%x" % (data_type))

	def _interpret(self, match):
		match = { key: bytes.fromhex(value) for (key, value) in match.items() }
		expected_checksum = (-sum(match["checksummed_payload"])) & 0xff
		if (expected_checksum == match["checksum"][0]) and (len(match["data"]) == match["length"][0]):
			self._interpret_data(match)

	def run(self):
		with open(self._args.filename) as f:
			for line in f:
				line = line.strip("\r\n")
				result = self._HEX_LINE.fullmatch(line)
				if result:
					result = result.groupdict()
					self._interpret(result)

		for (start_address, chunk) in self._chunks.items():
			output_filename = "chunk_%08x.bin" % (start_address)
			with open(output_filename, "wb") as f:
				f.write(chunk)

cmd = FWExtractor.from_commandline()
cmd.run()
