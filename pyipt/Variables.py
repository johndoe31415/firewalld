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

class Variables():
	_SUBSTITUTION_REGEX = re.compile(r"\${(?P<name>[-a-zA-Z0-9]+)}")

	def __init__(self, variable_dict):
		self._raw_variable_dict = variable_dict
		self._resolved_vars = { }
		self._resolve_all()

	def _substitute(self, text):
		def replacement(match):
			match = match.groupdict()
			name = match["name"]
			value = self._resolve_var(name)
			return value
		text = self._SUBSTITUTION_REGEX.sub(replacement, text)
		return text

	def _resolve_var(self, name):
		if name in self._resolved_vars:
			return self._resolved_vars[name]
		value = self._raw_variable_dict[name]
		if isinstance(value, str):
			text = value
		elif isinstance(value, dict):
			dicttype = value.get("type")
			if dicttype == "join-list":
				text = ",".join(value["items"])
			else:
				raise NotImplementedError(dicttype)
		text = self._substitute(text)
		self._resolved_vars[name] = text
		return text

	def _resolve_all(self):
		for key in self._raw_variable_dict:
			self._resolve_var(key)

	def dump(self):
		for (key, value) in sorted(self._resolved_vars.items()):
			print("%s = %s" % (key, value))

if __name__ == "__main__":
	v = Variables({
		"foo":	"FOO",
		"a":	"A",
		"bar":	"B${a}R",
		"moo":	"foobar => ${foo}${bar} <= foobar",
		"list":	{
			"type":	"join-list",
			"items":	[ "foo", "bar", "moo", "koo" ]
		},
	})
	v.dump()
