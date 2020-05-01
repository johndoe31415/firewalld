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

class Chain():
	def __init__(self, table, chain):
		self._table = table
		self._chain = chain

	@property
	def table(self):
		return self._table

	@property
	def chain(self):
		return self._chain

	@classmethod
	def parse(cls, text):
		if "." in text:
			(table, chain) = text.split(".", maxsplit = 1)
			return cls(table, chain)
		else:
			return cls("mangle", text)

	def command(self, option):
		if self.table == "mangle":
			return (option, self.chain.upper())
		else:
			return ("-t", self.table.lower(), option, self.chain.upper())

	def iptables_append(self):
		return self.command("-A")

	def iptables_flush(self):
		return self.command("-F")

	def iptables_policy(self):
		return self.command("-P")

	def __str__(self):
		return "%s.%s" % (self.table.lower(), self.chain.upper())
