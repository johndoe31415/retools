#!/usr/bin/python3
#	retools - Reverse engineering toolkit
#	Copyright (C) 2019-2020 Johannes Bauer
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
import collections
from retools.FriendlyArgumentParser import FriendlyArgumentParser
from retools.EncodableTypes import EncodableTypes

parser = FriendlyArgumentParser()
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Be more verbose. Can be specified multiple times.")
parser.add_argument("filename_pattern", metavar = "filename pattern", nargs = "+", type = str, help = "Filename and pattern that should be searched for. Pattern can be either a hex string or a value of type:data where type can be one of %s. E.g, 'uint32:1234' or 'sint16-be:-9'" % (", ".join(EncodableTypes.get_known_types())))
args = parser.parse_args(sys.argv[1:])

if len(args.filename_pattern) % 2 != 0:
	print("Error: Must supply a pattern with each file name, but odd number of positional arguments given.", file = sys.stderr)
	sys.exit(1)

parsed_patterns = [ ]
for (filename, pattern) in zip(args.filename_pattern[::2], args.filename_pattern[1::2]):
	try:
		if ":" in pattern:
			(ptype, pvalue) = pattern.split(":", maxsplit = 1)
			bin_pattern = list(EncodableTypes.encode(pvalue, ptype))[0].value
		else:
			bin_pattern = bytes.fromhex(pattern)
	except ValueError as e:
		print("Invalid pattern: %s (%s)" % (pattern, str(e)), file = sys.stderr)
		sys.exit(1)
	if args.verbose >= 1:
		print("%20s: %s" % (filename, bin_pattern.hex()))

	parsed_patterns.append((filename, bin_pattern))

def findall(haystack, needle):
	occurrences = set()
	start_offset = 0
	while True:
		match_offset = haystack.find(needle, start_offset)
		if match_offset == -1:
			break
		occurrences.add(match_offset)
		start_offset = match_offset + 1
	return occurrences

with open(parsed_patterns[0][0], "rb") as f:
	content = f.read()
	occurrences = findall(content, parsed_patterns[0][1])

if args.verbose >= 2:
	print("After initial processing of %s: %d matches" % (parsed_patterns[0][0], len(occurrences)))

for (filename, bin_pattern) in parsed_patterns[1:]:
	matched_occurrences = set()
	with open(filename, "rb") as f:
		for offset in occurrences:
			f.seek(offset)
			actual_pattern = f.read(len(bin_pattern))
			if actual_pattern == bin_pattern:
				matched_occurrences.add(offset)
	occurrences = matched_occurrences
	if args.verbose >= 2:
		print("After processing of %s: %d matches" % (filename, len(occurrences)))

print("%d occurrences of pattern(s) found." % (len(occurrences)))
for (oid, offset) in enumerate(sorted(occurrences), 1):
	print("Match %-4d: 0x%x (%d)" % (oid, offset, offset))

