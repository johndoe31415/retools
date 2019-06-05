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

import contextlib
import os
import tempfile
import subprocess
from retools.FileTools import FileTools
from retools.WorkDir import WorkDir

class Classifier():
	_NAME = None
	_KNOWN_CLASSIFIERS = { }
	_CONTAINS_PAYLOAD = True
	_CLASSIFIER_PRIORITY = { name: cid for (cid, name) in enumerate(reversed([
		"uboot",
		"squashfs",
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

	@property
	def contains_payload(self):
		return self._CONTAINS_PAYLOAD

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

	def carve_extract(self, input_file, start_offset, file_length, destination):
		self._mkdir(os.path.dirname(destination))
		with open(destination, "wb") as output_file:
			input_file.seek(start_offset)
			FileTools.carve(input_file, output_file, file_length)
		return True

	def extract(self, input_file, start_offset, file_length, destination):
		raise NotImplementedError()

	def scan(self, chunk):
		raise NotImplementedError()

	def investigate(self, infile, offset):
		raise NotImplementedError()

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
			return True
		else:
			return False

class TemporaryCarveClassifier(Classifier):
	_SUFFIX = None

	def extract_from_temporary_carved_file(self, temp_filename, destination):
		raise NotImplementedError()

	def extract(self, input_file, start_offset, file_length, destination):
		self._mkdir(destination)
		with WorkDir(destination), tempfile.NamedTemporaryFile(suffix = self._SUFFIX) as archive_file:
			input_file.seek(start_offset)
			FileTools.carve(input_file, archive_file, file_length)
			archive_file.flush()
			return self.extract_from_temporary_carved_file(archive_file.name, destination)

class MultiFileExtractorClassifier(TemporaryCarveClassifier):
	_SUFFIX = None

	def get_extract_cmdline(self, archive_name):
		raise NotImplementedError()

	def extract_from_temporary_carved_file(self, temp_filename, destination):
		cmdline = self.get_extract_cmdline(temp_filename)
		process = subprocess.run(cmdline, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
		if self._args.verbose >= 3:
			print("%s extraction (potential target %s) returned with status code %d." % (self.name, destination, process.returncode))

		if process.returncode == 0:
			return True
		else:
			with contextlib.suppress(OSError):
				os.rmdir(destination)
			return False
