#	firewalld - Linux firewall daemon with time-based capabilities
#	Copyright (C) 2020-2021 Johannes Bauer
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
import datetime
from pyipt.Exceptions import InvalidTimeWindowException

class TimeWindow():
	_WEEKDAYS = {
		"mon":	0,
		"tue":	1,
		"wed":	2,
		"thu":	3,
		"fri":	4,
		"sat":	5,
		"sun":	6,
	}
	_TIME_RE = re.compile(r"(?P<inv>!)?\s*(?P<from_weekday>mon|tue|wed|thu|fri|sat|sun)?\s*(?P<from_hour>\d{1,2})(:(?P<from_minute>\d{2})(:(?P<from_second>\d{2}))?)?\s*-\s*(?P<to_weekday>mon|tue|wed|thu|fri|sat|sun)?\s*(?P<to_hour>\d{1,2})(:(?P<to_minute>\d{2})(:(?P<to_second>\d{2}))?)?", flags = re.IGNORECASE)

	def __init__(self, second_ranges):
		self._second_ranges = second_ranges

	@classmethod
	def parse(cls, text):
		ranges = [ ]
		for range_text in text.split(","):
			range_text = range_text.strip()
			result = cls._TIME_RE.fullmatch(range_text)
			if result is None:
				raise InvalidTimeWindowException("Invalid time window given, cannot parse: %s (part of '%s')" % (range_text, text))
			result = result.groupdict()
			if (result["from_weekday"] is None) and (result["to_weekday"] is None):
				# Daytime match
				from_sec = (int(result["from_hour"]) * 3600) + (int(result["from_minute"] or "0") * 60) + int(result["from_second"] or "0")
				to_sec = (int(result["to_hour"]) * 3600) + (int(result["to_minute"] or "0") * 60) + int(result["to_second"] or "0")
				if result["inv"] is not None:
					(from_sec, to_sec) = (to_sec, from_sec)
				ranges.append((True, from_sec, to_sec))
			elif (result["from_weekday"] is not None) and (result["to_weekday"] is not None):
				# Weekday match
				from_sec = (cls._WEEKDAYS[result["from_weekday"].lower()] * 86400) + (int(result["from_hour"]) * 3600) + (int(result["from_minute"] or "0") * 60) + int(result["from_second"] or "0")
				to_sec = (cls._WEEKDAYS[result["to_weekday"].lower()] * 86400) + (int(result["to_hour"]) * 3600) + (int(result["to_minute"] or "0") * 60) + int(result["to_second"] or "0")
				if result["inv"] is not None:
					(from_sec, to_sec) = (to_sec, from_sec)
				ranges.append((False, from_sec, to_sec))
			else:
				raise InvalidTimeWindowException("Invalid time window given, cannot parse: %s -- either both from and to need to specify a weekday or neither (part of '%s')" % (range_text, text))

		return cls(ranges)

	def _second_satisfied(self, daytime_sec, weekday_sec):
		for (daytime_match, from_sec, to_sec) in self._second_ranges:
			sec = daytime_sec if daytime_match else weekday_sec
			if from_sec <= to_sec:
				# Non-inverted match
				if from_sec <= sec <= to_sec:
					return True
			else:
				# Inverted match
				if not (to_sec <= sec <= from_sec):
					return True
		return False

	def satisfied(self, timestamp):
		daytime_sec = (timestamp.hour * 3600) + (timestamp.minute * 60) + timestamp.second
		weekday_sec = (86400 * timestamp.weekday()) + daytime_sec
		return self._second_satisfied(daytime_sec, weekday_sec)

	def now_satisfied(self):
		return self.satisfied(datetime.datetime.now())

if __name__ == "__main__":
	tw = TimeWindow.parse("mon8-tue9:30,15-16")
	print(tw.now_satisfied())
