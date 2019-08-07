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
import gzip
import os
import subprocess
import contextlib
import tempfile
import struct
import collections
from retools.FriendlyArgumentParser import FriendlyArgumentParser
from retools.WorkDir import WorkDir
from retools.unpack import Classifier
from retools.FileTools import FileTools
from retools.Intervals import Interval, Intervals, IntervalConstraintException

parser = FriendlyArgumentParser()
parser.add_argument("-c", "--carve", action = "store_true", help = "Carve out the raw source data in the found files.")
group = parser.add_mutually_exclusive_group()
group.add_argument("-n", "--noextract", action = "store_true", help = "Do not extract contents if they contain inner data (e.g., if a ZIP file is found, this option will cause its contents not to be unzipped).")
group.add_argument("-r", "--recurse", action = "store_true", help = "Recursively try to extract data.")
parser.add_argument("--recurse-multifiles", action = "store_true", help = "Also recursively try to extract contents of a multi-file. For example, if a ZIP file is found that contains 100 files in it, recurse through all those 100 files as well.")
parser.add_argument("-d", "--destination", metavar = "path", type = str, default = "unpacked", help = "Gives the output path. Defaults to %(default)s.")
parser.add_argument("-l", "--archive-limit", metavar = "bytes", type = int, help = "When trying to extract inner archives, limit the size of the archives to this value. Can be useful when working with large archives.")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Be more verbose. Can be specified multiple times.")
parser.add_argument("filename", metavar = "filename", type = str, help = "File that should be attempted to unpack")
args = parser.parse_args(sys.argv[1:])

class FileUnpacker():
	def __init__(self, args):
		self._args = args
		self._active_classifiers = [ classifier_class(args = self._args) for classifier_class in Classifier.get_all() ]
		self._overlap_bytes = 64 * 1024
		self._chunksize_bytes = 1024 * 1024

	def unpack_all(self, filename, destination):
		if os.path.isfile(filename):
			return self.unpack(filename, destination)
		else:
			if not self._args.recurse_multifiles:
				return
			for (basedir, subdirs, files) in os.walk(filename):
				for filename in files:
					full_filename = basedir + "/" + filename
					destination = full_filename + "_content"
					self.unpack(full_filename, destination)

	def unpack(self, filename, destination):
		found_blobs = Intervals(allow_overlapping = False, allow_identical = False)
		with open(filename, "rb") as f:
			for classifier in self._active_classifiers:
				f.seek(0)
				if self._args.verbose >= 1:
					print("Checking for content of type %s" % (classifier.name))

				while True:
					base_offset = f.tell()
					chunk = f.read(self._chunksize_bytes)
					if len(chunk) == 0:
						break

					# First run through the file and find all quick matches
					for offset in classifier.scan(chunk):
						# For each quick match, determine if it's a real match
						# or a false positive
						abs_offset = base_offset + offset
						f.seek(abs_offset)
						match = classifier.investigate(f, abs_offset)

						if match is None:
							continue

						(start_offset, file_length) = match
						if file_length is not None:
							found_blob = Interval.begin_length(start_offset, file_length)
							try:
								found_blobs.add(found_blob)
							except IntervalConstraintException:
								print("%s: %s found at %#x length %d bytes, but discarded because contained/overlapping with different blob." % (filename, classifier.name, start_offset, file_length))
								continue

						if self._args.verbose >= 1:
							if file_length is not None:
								print("%s: %s found at %#x length %d bytes" % (filename, classifier.name, start_offset, file_length))
							else:
								print("%s: %s found at %#x with indeterminate length" % (filename, classifier.name, start_offset))

						# If it's not extactible, then we carve by default
						if self._args.carve or (not classifier.contains_payload) and (file_length is not None):
							carve_destination = "%s/carved_%#010x.%s" % (destination, start_offset, classifier.name)
							print("Carving: %s [ %#x len %#x] -> %s" % (filename, start_offset, file_length, carve_destination))
							with contextlib.suppress(FileExistsError):
								os.makedirs(destination)
							f.seek(start_offset)
							with open(carve_destination, "wb") as dest_file:
								FileTools.carve(f, dest_file, file_length)

						# If it's extractable and extraction is wanted, extract.
						if (not self._args.noextract) and classifier.contains_payload:
							extract_destination = "%s/payload_%#010x.%s" % (destination, start_offset, classifier.name)
							if file_length is not None:
								print("Extracting: %s [ %#x len %#x] -> %s" % (filename, start_offset, file_length, extract_destination))
							else:
								print("Extracting: %s [ %#x len N/A] -> %s" % (filename, start_offset, extract_destination))
							f.seek(start_offset)
							extraction_success = classifier.extract(f, start_offset, file_length, extract_destination)
							if extraction_success and self._args.recurse:
								recurse_into = extract_destination
								recurse_destination = "%s/content_%#010x.%s" % (destination, start_offset, classifier.name)
								self.unpack_all(recurse_into, recurse_destination)
								print("Recursing %s into: %s" % (recurse_into, recurse_destination))

					new_offset = base_offset + self._chunksize_bytes - self._overlap_bytes
					f.seek(new_offset)

fup = FileUnpacker(args)
fup.unpack(args.filename, args.destination)
