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

import sys
import socket
from pyipt.Tools import multisplit

class Hostname():
	def __init__(self, hostname_str, config):
		self._addresses = set()
		if hostname_str in config.get("hosts", { }):
			if isinstance(config["hosts"][hostname_str], list):
				self._addresses = set(config["hosts"][hostname_str])
			else:
				self._addresses.add(config["hosts"][hostname_str])
		else:
			for hostname in multisplit(hostname_str):
				try:
					(name, aliaslist, addresslist) = socket.gethostbyname_ex(hostname)
					self._addresses |= set(addresslist)
				except socket.gaierror as e:
					print("Warning: Unable to resolve hostname %s: %s" % (hostname, str(e)), file = sys.stderr)
		self._addresses = sorted(self._addresses)

	def __getitem__(self, index):
		return self._addresses[index]

	def __len__(self):
		return len(self._addresses)

	def __iter__(self):
		yield from self._addresses
