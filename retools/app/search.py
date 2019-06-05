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
		yield "x"

	def _parse_value(self, value):
		yield from self._parse_int(value)
		yield from self._parse_float(value)

	def __iter__(self):
		return iter(self._values)

parser = FriendlyArgumentParser()
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Be more verbose. Can be specified multiple times.")
parser.add_argument("pattern", metavar = "pattern", type = str, help = "Pattern that should be looked for.")
parser.add_argument("filename", metavar = "filename(s)", type = str, help = "File(s) that should be searched")
args = parser.parse_args(sys.argv[1:])

pattern = SearchPattern(args.pattern)
if args.verbose >= 1:
	for pattern_instance in pattern:
		print("%-10s %s" % (pattern_instance.name, to_hex(pattern_instance.value)))

