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

class PortMap():
	def __init__(self):
		self._ports = set()
		self._ranges = None
		self._single = None

	@property
	def port_count(self):
		return len(self._ports)

	@property
	def span_count(self):
		return len(self.single) + len(self.ranges)

	def add(self, port):
		assert(self._single is None)
		self._ports.add(port)

	def add_range(self, from_port, to_port):
		for port in range(from_port, to_port + 1):
			self.add(port)

	def _finalize(self):
		if self._single is not None:
			return
		self._ranges = [ ]
		self._single = set()

		def add_range(range_start, range_end):
			if range_start is None:
				return
			if range_start == range_end:
				self._single.add(range_start)
			else:
				self._ranges.append((range_start, range_end))

		range_start = None
		range_end = None
		self._ports = list(sorted(self._ports))
		for port in self._ports:
			if range_start is None:
				(range_start, range_end) = (port, port)
			elif range_end + 1 == port:
				range_end = port
			else:
				add_range(range_start, range_end)
				(range_start, range_end) = (port, port)
		add_range(range_start, range_end)

	@property
	def ranges(self):
		self._finalize()
		return self._ranges

	@property
	def single(self):
		self._finalize()
		return self._single

	def __getitem__(self, index):
		self._finalize()
		return self._ports[0]

	def __str__(self):
		return "Ports<%s>" % (", ".join("%d" % (port) for port in sorted(self._ports)))

if __name__ == "__main__":
	pm = PortMap()
	pm.add(50)
	pm.add(52)
	pm.add(54)
	pm.add(55)
	pm.add(51)
	pm.add_range(100, 150)
	pm.add(151)
	print(pm.ranges, pm.single)
