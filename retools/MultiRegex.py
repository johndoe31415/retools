#!/usr/bin/python3
#
#	MultiRegex - Match against multiple possible regular expressions
#	Copyright (C) 2019-2019 Johannes Bauer
#
#	This file is part of pycommon.
#
#	pycommon is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	pycommon is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with pycommon; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>
#
#	File UUID 6c13ccee-e13b-4c05-81b9-1c4bff5047e1

class NoRegexMatchedException(Exception): pass
class NoCallbackFoundException(Exception): pass

class MultiRegex():
	def __init__(self, regex_dict):
		self._dict = regex_dict

	def fullmatch(self, pattern, callback, callback_prefix = "_match_", groupdict = False):
		for (name, regex) in self._dict.items():
			match = regex.fullmatch(pattern)
			if match is not None:
				callback_name = callback_prefix + name
				callback = getattr(callback, callback_name, None)
				if callback is None:
					raise NoCallbackFoundException("Callback '%s' not present for match %s." % (callback_name, name))
				if groupdict:
					match = match.groupdict()
				return callback(pattern, name, match)
		raise NoRegexMatchedException("No regex matched: %s" % (pattern))
