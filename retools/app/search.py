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

#def to_hex(data):
#	return " ".join("%02x" % (c) for c in data)

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
