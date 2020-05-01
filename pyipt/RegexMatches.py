#	firewalld - Linux firewall daemon with time-based capabilities
#	Copyright (C) 2020-2020 Johannes Bauer
#
#	This file is part of firewalld.
#
#	firewalld is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	firewalld is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with firewalld; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import re
from pyipt.Exceptions import UnknownTypeError

class RegexMatch():
	_REGEX = None
	_CONVERSIONS = None

	def __init__(self, regex_str):
		match = self._REGEX.fullmatch(regex_str)
		if match is None:
			raise UnknownTypeError("The value provided does not fulfill the regex of %s." % (self.__class__.__name__))

		self._values = match.groupdict()
		if self._CONVERSIONS is not None:
			for (key, convertor) in self._CONVERSIONS.items():
				if self._values[key] is not None:
					self._values[key] = convertor(self._values[key])

	def __getitem__(self, key):
		return self._values[key]

class PortforwardTarget(RegexMatch):
	_REGEX = re.compile(r"(?P<hostname>[a-zA-Z][.0-9a-zA-Z]*)(:(?P<port>(?P<relative>[+-])?\d+))?")
	_CONVERSIONS = {
		"port":			int,
	}
