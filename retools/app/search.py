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
import argparse
from retools.FriendlyArgumentParser import FriendlyArgumentParser
from retools.PreciseFloat import PreciseFloat
from retools.FileSearch import FileSearch
from retools.EncodableTypes import EncodableTypes, EncodingException

class FileSearcher():
	def __init__(self, args):
		self._args = args

	@classmethod
	def pattern_argument(cls, arg):
		try:
			return EncodableTypes.encode_argument(arg)
		except EncodingException as e:
			raise argparse.ArgumentTypeError(str(e))

	@classmethod
	def from_commandline(cls):
		parser = FriendlyArgumentParser()
		parser.add_argument("-c", "--context", metavar = "bytes", type = int, default = 32, help = "Display this amount of context around occurrences.")
		parser.add_argument("-r", "--recurse", action = "store_true", help = "Recurse into subdirectories.")
		parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Be more verbose. Can be specified multiple times.")
		parser.add_argument("pattern", metavar = "pattern", type = cls.pattern_argument, help = "Pattern that should be looked for.")
		parser.add_argument("filename", metavar = "filename(s)", nargs = "+", type = str, help = "File(s) that should be searched")
		args = parser.parse_args(sys.argv[1:])
		return cls(args = args)

	def _search_file(self, filename, pattern):
		fs = FileSearch(filename, context_size = self._args.context)
		for match in fs.find_all(pattern.value):
			print("%s %x %s %s %s" % (filename, match.offset, match.pre.hex(), pattern.value.hex(), match.post.hex()))

	def _search_dir(self, dirname, pattern):
		for filename in os.listdir(dirname):
			full_filename = dirname + "/" + filename
			try:
				if os.path.isfile(full_filename):
					self._search_file(full_filename, pattern)
				elif self._args.recurse and os.path.isdir(full_filename):
					self._search_dir(full_filename, pattern)
			except PermissionError as e:
				print("%s: %s" % (filename, str(e)), file = sys.stderr)

	def _search(self, filename, pattern):
		if os.path.isfile(filename):
			self._search_file(filename, pattern)
		elif os.path.isdir(filename):
			self._search_dir(filename, pattern)

	def run(self):
		if self._args.verbose >= 1:
			for pattern_instance in pattern:
				print("%-15s %s" % (pattern_instance.name, to_hex(pattern_instance.value)))

		for pattern in self._args.pattern:
			if self._args.verbose >= 2:
				print("Searching: %s" % (pattern.name))
			for filename in self._args.filename:
				self._search(filename, pattern)

cmd = FileSearcher.from_commandline()
cmd.run()
