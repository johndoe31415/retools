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

parser = FriendlyArgumentParser()
parser.add_argument("-r", "--recurse", action = "store_true", help = "Recursively try to extract archives")
parser.add_argument("--recurse-multifiles", action = "store_true", help = "Also recursively try to extract contents of a multi-file. For example, if a ZIP file is found that contains 100 files in it, recurse through all those 100 files as well.")
parser.add_argument("-d", "--destination", metavar = "path", type = str, default = "unpacked", help = "Gives the output path. Defaults to %(default)s.")
parser.add_argument("-l", "--archive-limit", metavar = "bytes", type = int, help = "When trying to extract inner archives, limit the size of the archives to this value. Can be useful when working with large archives.")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Be more verbose. Can be specified multiple times.")
parser.add_argument("filename", metavar = "filename", type = str, help = "File that should be attempted to unpack")
args = parser.parse_args(sys.argv[1:])

class Classifier():
	_NAME = None
	_KNOWN_CLASSIFIERS = { }
	_CLASSIFIER_PRIORITY = { name: cid for (cid, name) in enumerate(reversed([
		"uboot",
		"cramfs",
		"tar",
		"zip",
		"gzip",
	]), 1)}

	def __init__(self, args):
		self._args = args

	@property
	def name(self):
		return self._NAME

	def _read_until_limit(self, f):
		if self._args.archive_limit is None:
			return f.read()
		else:
			return f.read(self._args.archive_limit)

	@staticmethod
	def _bytes_findall(haystack, needle):
		start_offset = 0
		while True:
			match_offset = haystack.find(needle, start_offset)
			if match_offset == -1:
				break
			yield match_offset
			start_offset = match_offset + 1

	@staticmethod
	def _mkdir(path):
		with contextlib.suppress(FileExistsError):
			os.makedirs(path)

	@classmethod
	def register(cls, classifier_class):
		cls._KNOWN_CLASSIFIERS[classifier_class._NAME] = classifier_class
		return classifier_class

	@classmethod
	def get_all(cls):
		classifier_list = [ (cls._CLASSIFIER_PRIORITY.get(name, 0), name, classifier_class) for (name, classifier_class) in cls._KNOWN_CLASSIFIERS.items() ]
		classifier_list.sort(reverse = True)
		return [ classifier_class for (priority, name, classifier_class) in classifier_list ]

class StdoutDecompressClassifier(Classifier):
	_SUCCESS_RETURNCODES = [ 0 ]
	_COMMANDLINE = None

	def extract(self, input_file, destination):
		compressed_data = self._read_until_limit(input_file)
		process = subprocess.run(self._COMMANDLINE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, input = compressed_data)
		if self._args.verbose >= 3:
			print("%s extraction (potential target %s) returned with status code %d." % (self.name, destination, process.returncode))

		if process.returncode in self._SUCCESS_RETURNCODES:
			decompressed_data = process.stdout
			self._mkdir(os.path.dirname(destination))
			with open(destination, "wb") as f:
				f.write(decompressed_data)
			return destination
		else:
			return None

@Classifier.register
class GZClassifier(StdoutDecompressClassifier):
	_NAME = "gzip"
	_SUCCESS_RETURNCODES = [ 0, 2 ]
	_COMMANDLINE = [ "gunzip" ]

	def quick_find(self, chunk):
		header = bytes.fromhex("1f 8b")
		yield from self._bytes_findall(chunk, header)

@Classifier.register
class ZLIBClassifier(StdoutDecompressClassifier):
	_NAME = "zlib"
	_COMMANDLINE = [ "zlib-flate", "-uncompress" ]

	def quick_find(self, chunk):
		header = bytes.fromhex("78")
		for offset in self._bytes_findall(chunk, header):
			following = chunk[offset + 1]
			if following in [ 0x01, 0x9c, 0xda ]:
				yield offset

@Classifier.register
class XZClassifier(StdoutDecompressClassifier):
	_NAME = "xz"
	_COMMANDLINE = [ "xzcat", "--single-stream" ]

	def quick_find(self, chunk):
		header = bytes.fromhex("fd 37 7a 58 5a 00")
		yield from self._bytes_findall(chunk, header)

@Classifier.register
class BZIP2Classifier(StdoutDecompressClassifier):
	_NAME = "bz2"
	_COMMANDLINE = [ "bzcat", "--decompress" ]

	def quick_find(self, chunk):
		header = b"BZh"
		yield from self._bytes_findall(chunk, header)

class MultiFileExtractorClassifier(Classifier):
	_SUFFIX = None

	def _get_cmdline(self, archive_name):
		raise NotImplementedError()

	def extract(self, input_file, destination):
		compressed_data = self._read_until_limit(input_file)
		self._mkdir(destination)
		with WorkDir(destination), tempfile.NamedTemporaryFile(suffix = self._SUFFIX) as zipfile:
			zipfile.write(compressed_data)
			zipfile.flush()
			process = subprocess.run(self._get_cmdline(zipfile.name), stdout = subprocess.PIPE, stderr = subprocess.PIPE)
			if self._args.verbose >= 3:
				print("%s extraction (potential target %s) returned with status code %d." % (self.name, destination, process.returncode))
		if process.returncode == 0:
			return destination
		else:
			with contextlib.suppress(OSError):
				os.rmdir(destination)

@Classifier.register
class TarClassifier(MultiFileExtractorClassifier):
	_NAME = "tar"
	_SUFFIX = ".tar"

	def quick_find(self, chunk):
		header = b"ustar"
		for offset in self._bytes_findall(chunk, header):
			yield offset - 0x101

	def _get_cmdline(self, archive_name):
		return [ "tar", "-x", "-f", archive_name ]

@Classifier.register
class PKZIPClassifier(MultiFileExtractorClassifier):
	_NAME = "zip"
	_SUFFIX = ".zip"

	def quick_find(self, chunk):
		header = b"PK"
		yield from self._bytes_findall(chunk, header)

	def _get_cmdline(self, archive_name):
		return [ "unzip", "-n", archive_name ]

@Classifier.register
class UBootImageClassifier(MultiFileExtractorClassifier):
	_NAME = "uboot"
	_SUFFIX = ".uboot"
	_HDR_STRUCT = struct.Struct("< L L L L L L L B B B B 32s")
	_HDR_FIELDS = collections.namedtuple("HdrFields", [ "magic", "hdr_crc", "time", "size", "load", "entry_point", "data_crc", "os", "arch", "img_type", "compression", "img_name" ])

	def quick_find(self, chunk):
		header = bytes.fromhex("27 05 19 56")
		yield from self._bytes_findall(chunk, header)

	def _get_cmdline(self, archive_name):
		print("UBOOT")
		return [ "echo", archive_name ]
#		return [ "unzip", "-n", archive_name ]

@Classifier.register
class CramFSClassifier(MultiFileExtractorClassifier):
	_NAME = "cramfs"
	_SUFFIX = ".cramfs"

	def quick_find(self, chunk):
		header = bytes.fromhex("45 3d cd 28")
		yield from self._bytes_findall(chunk, header)

	def extract(self, infilename, abs_offset, infile, outfilename):
		pass

#	def _get_cmdline(self, archive_name):
#		print("UNCRAM")
#		return [ "echo", archive_name ]
#		return [ "unzip", "-n", archive_name ]

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
		with open(filename, "rb") as f:
			while True:
				base_offset = f.tell()
				chunk = f.read(self._chunksize_bytes)
				if len(chunk) == 0:
					break

				for classifier in self._active_classifiers:
					for offset in classifier.quick_find(chunk):
						abs_offset = base_offset + offset
						f.seek(abs_offset, os.SEEK_SET)
						chunk_destination = "%s/%#x_%s" % (destination, abs_offset, classifier.name)
						result = classifier.extract(f, chunk_destination)
						if (result is not None) and (self._args.verbose >= 1):
							print("Successfully extracted %s from %s at offset %#x" % (classifier.name, filename, abs_offset))
						if (result is not None) and (self._args.recurse):
							# Extraction was successful. Recurse.
							self.unpack_all(result, chunk_destination + "_content")

				new_offset = base_offset + self._chunksize_bytes - self._overlap_bytes
				f.seek(new_offset, os.SEEK_SET)

fup = FileUnpacker(args)
fup.unpack(args.filename, args.destination)
