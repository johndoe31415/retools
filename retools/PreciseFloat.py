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

import re
import fractions

class PreciseFloat():
	_FLOAT_RE = re.compile(r"(?P<sign>-)?\s*(?P<whole>\d+)?(\.(?P<fract>\d+))?([eE](?P<exp>-?\d+))?")

	def __init__(self, text):
		self._value = self._parse(text)

	@staticmethod
	def _digit_count(value):
		digits = 0
		while value > 0:
			value //= 10
			digits += 1
		return digits

	def _parse(self, text):
		result = self._FLOAT_RE.fullmatch(text)
		if result is None:
			raise ValueError("Cannot parse as float: %s" % (text))
		result = result.groupdict()

		result_value = fractions.Fraction(0, 1)
		if result["whole"] is not None:
			result_value += int(result["whole"])

		if result["fract"] is not None:
			fract = int(result["fract"])
			digits = self._digit_count(fract)
			result_value += fractions.Fraction(fract, 10 ** digits)

		if result["exp"] is not None:
			result_value *= 10 ** int(result["exp"])

		if result["sign"] is not None:
			result_value = -result_value
		return result_value

	def __float__(self):
		return float(self._value)

	def __str__(self):
		return str(self._value)

if __name__ == "__main__":
	for floatstr in [
			"1",
			"0",
			".1",
			".0",
			"-0",
			"1.2345",
			"-1.9999",
			"-.9876",
			"1e10",
			"1e-9",
			"1.234e-9",
			"0e10",
		]:
		precise = PreciseFloat(floatstr)
		print("%-10s %-20s %e" % (floatstr, precise, float(precise)))
		assert(abs(float(precise) - float(floatstr)) < 1e-6)

