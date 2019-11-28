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

import os
import sys
import collections
from retools.FriendlyArgumentParser import FriendlyArgumentParser
from retools.PreciseFloat import PreciseFloat

def to_hex(data):
	return " ".join("%02x" % (c) for c in data)

class SearchPattern(object):
	InstanciatedPattern = collections.namedtuple("SearchPattern", [ "name", "value" ])

	def __init__(self, expression):
		if expression.startswith("val:"):
			self._values = self._parse_value(expression[4:])
		elif expression.startswith("int:"):
			self._values = self._parse_int(expression[4:])
		elif expression.startswith("float:"):
			self._values = self._parse_float(expression[6:])
		else:
			self._values = self._parse_str(expression)
		self._values = list(self._values)

	def _parse_int(self, value):
		value = int(value)
		for length in [ 1, 2, 4, 8 ]:
			if 0 <= value <= (256 ** length):
				# uintX possible
				if length == 1:
					yield self.InstanciatedPattern(name = "uint%d" % (length * 8), value = value.to_bytes(byteorder = "little", length = length))
				else:
					yield self.InstanciatedPattern(name = "uint%d-LE" % (length * 8), value = value.to_bytes(byteorder = "little", length = length))
					yield self.InstanciatedPattern(name = "uint%d-BE" % (length * 8), value = value.to_bytes(byteorder = "big", length = length))

	def _parse_float(self, value):
		value = PreciseFloat(value)
		print(value)
		raise NotImplementedError("TODO")

	def _parse_str(self, value):
		if value.startswith("latin1:"):
			yield self.InstanciatedPattern(name = "str-latin1", value = value[7:].encode("latin1"))
		elif value.startswith("utf8:"):
			yield self.InstanciatedPattern(name = "str-utf8", value = value[5:].encode("utf-8"))
		elif value.startswith("utf16-be:"):
			yield self.InstanciatedPattern(name = "str-utf16-BE", value = value[9:].encode("utf-16-BE"))
		elif value.startswith("utf16-le:"):
			yield self.InstanciatedPattern(name = "str-utf16-LE", value = value[9:].encode("utf-16-LE"))
		else:
			# Return all of the above
			for prefix in [ "latin1", "utf8", "utf16-be", "utf16-le" ]:
				yield from self._parse_str(prefix + ":" + value)

	def _parse_value(self, value):
		yield from self._parse_int(value)
		yield from self._parse_float(value)

	def __iter__(self):
		return iter(self._values)

parser = FriendlyArgumentParser()
parser.add_argument("-r", "--recurse", action = "store_true", help = "Recurse into subdirectories.")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Be more verbose. Can be specified multiple times.")
parser.add_argument("pattern", metavar = "pattern", type = str, help = "Pattern that should be looked for.")
parser.add_argument("filename", metavar = "filename(s)", nargs = "+", type = str, help = "File(s) that should be searched")
args = parser.parse_args(sys.argv[1:])

def execute_search_file(filename, pattern):
	with open(filename, "rb") as f:
		chunk_size = 1024 * 1024
		while True:
			f.seek(max(0, f.tell() - len(pattern.value)))
			pos = f.tell()
			chunk = f.read(chunk_size)

			start_offset = 0
			while True:
				offset = chunk.find(pattern.value, start_offset)
				if offset == -1:
					break
				start_offset = offset + 1
				file_offset = pos + offset
				print("%s 0x%x %d %s" % (filename, file_offset, file_offset, pattern.value))

			if len(chunk) != chunk_size:
				break

def execute_search_dir(dirname, pattern, recurse):
	for filename in os.listdir(dirname):
		full_filename = dirname + "/" + filename
		try:
			if os.path.isfile(full_filename):
				execute_search_file(full_filename, pattern)
			elif recurse and os.path.isdir(full_filename):
				execute_search_dir(full_filename, pattern, recurse)
		except PermissionError as e:
			print("%s: %s" % (filename, str(e)), file = sys.stderr)

def execute_search(filename, pattern, recurse):
	if os.path.isfile(filename):
		execute_search_file(filename, pattern)
	elif os.path.isdir(filename):
		execute_search_dir(filename, pattern, recurse)

pattern = SearchPattern(args.pattern)
if args.verbose >= 1:
	for pattern_instance in pattern:
		print("%-15s %s" % (pattern_instance.name, to_hex(pattern_instance.value)))

searched = set()
for pattern_instance in pattern:
	if pattern_instance.value in searched:
		if args.verbose >= 2:
			print("Skipped: %s (pattern already included)" % (pattern_instance.name))
		continue
	if args.verbose >= 2:
		print("Searching: %s" % (pattern_instance.name))
	for filename in args.filename:
		execute_search(filename, pattern_instance, recurse = args.recurse)
	searched.add(pattern_instance.value)
