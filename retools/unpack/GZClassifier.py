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

import subprocess
from retools.unpack import Classifier, StdoutDecompressClassifier

@Classifier.register
class GZClassifier(StdoutDecompressClassifier):
	_NAME = "gzip"
	_SUCCESS_RETURNCODES = [ 0, 2 ]
	_COMMANDLINE = [ "gunzip" ]

	def scan(self, chunk):
		header = bytes.fromhex("1f 8b")
		yield from self._bytes_findall(chunk, header)

	def investigate(self, infile, offset):
		proc = subprocess.Popen([ "gunzip", "-l" ], stdin = infile, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
		(stdout, stderr) = proc.communicate()
		if proc.returncode != 0:
			# No gzip data found
			return None
		else:
			return (offset, None)
