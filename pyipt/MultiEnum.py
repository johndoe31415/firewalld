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

import enum
from pyipt.Tools import multisplit

class MultiEnum():
	_HANDLER_CLASS = None
	_ITER_TRANSLATION = None

	def __init__(self, multienum_str):
		self._values = [ self._HANDLER_CLASS(option) for option in multisplit(multienum_str) ]

	def __iter__(self):
		if self._ITER_TRANSLATION is None:
			return iter(self._values)
		else:
			for value in self._values:
				yield self._ITER_TRANSLATION[value]

class ICMPType(MultiEnum):
	class ICMPTypeEnum(enum.Enum):
		Ping = "ping"
		Pong = "pong"
		DestinationUnreachable = "dest-unreachable"
		TimeExceeded = "time-exceeded"
		Traceroute = "traceroute"
	_HANDLER_CLASS = ICMPTypeEnum

	_ITER_TRANSLATION = {
		ICMPTypeEnum.Ping:						"echo-request",
		ICMPTypeEnum.Pong:						"echo-reply",
		ICMPTypeEnum.DestinationUnreachable:	"3",
		ICMPTypeEnum.TimeExceeded:				"11",
		ICMPTypeEnum.Traceroute:				"30",
	}
