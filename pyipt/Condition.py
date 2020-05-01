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

from pyipt.TimeWindow import TimeWindow

class Condition():
	def __init__(self, condition_dict):
		self._conditions = [ ]
		if "timewindow" in condition_dict:
			time_window = TimeWindow.parse(condition_dict["timewindow"])
			self._conditions.append(lambda meta: time_window.satisfied(meta["now"]))

	def satisfied(self, metadata):
		for condition in self._conditions:
			if not condition(metadata):
				return False
		return True
