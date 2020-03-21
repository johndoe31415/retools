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

parser = FriendlyArgumentParser()
parser.add_argument("filename", metavar = "filename", type = str, help = "File that should be attempted to unpack")
args = parser.parse_args(sys.argv[1:])

class CharDistAnalysis():
	def __init__(self, args):
		self._args = args
		self._length = 0
		self._histogram = collections.Counter()

	def _print_results(self):
		for i in range(256):
			count = self._histogram.get(i, 0)
			if count != 0:
				print("%3d / %02x: %6d %.1f%% (rnd rel %+.0f%%)" % (i, i, count, count / self._length * 100, (count * 256 / self._length * 100) - 100))

	def _process_chunk(self, chunk):
		self._histogram.update(chunk)

	def run(self):
		with open(self._args.filename, "rb") as f:
			while True:
				chunk = f.read(1024 * 1024)
				if len(chunk) == 0:
					break
				self._process_chunk(chunk)
				self._length += len(chunk)
		self._print_results()

cda = CharDistAnalysis(args)
cda.run()
