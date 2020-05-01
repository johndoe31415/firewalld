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
import sys
import os
import subprocess
from pyipt.Tools import multisplit
from pyipt.Exceptions import UnknownInterfaceException

class Interface():
	_IP_ADDRESS_RE = re.compile(r"^\s+(?P<proto>[a-z]+) (?P<addr>[^/]+)/(?P<cidr>\d+)", flags = re.MULTILINE)

	def __init__(self, interface_str, config):
		self._config = config
		self._interface_str = interface_str
		self._interfaces = set()
		for interface_name in multisplit(interface_str):
			self._add_interface_name(interface_name)
		self._interfaces = sorted(list(self._interfaces))

	def _add_interface_name(self, interface_str):
		if interface_str.startswith("!"):
			have_excluded = False
			exclude_interface_name = interface_str[1:]
			for (interface, interface_name) in self.interfaces:
				if interface_name != exclude_interface_name:
					self._interfaces.add(interface)
				else:
					have_excluded = True
			if not have_excluded:
				print("Warning: Excluded interface '%s' not in list of interfaces at all (spec: %s)" % (exclude_interface_name, self._interface_str), file = sys.stderr)
		else:
			interface_name = interface_str
			if interface_name not in self._config["interfaces-rev"]:
				raise UnknownInterfaceException("Unknown interface: %s" % (interface_str))
			self._interfaces.add(self._config["interfaces-rev"][interface_name])

	@property
	def interfaces(self):
		return self._config["interfaces"].items()

	def _get_ifaddress(self, ifname):
		try:
			ip_output = None
			if "mock_interfaces" in self._config.get("options", { }):
				mock_file = "%s/ip_addr_show_%s.txt" % (self._config["options"]["mock_interfaces"], ifname)
				try:
					with open(mock_file, "rb") as f:
						ip_output = f.read()
				except FileNotFoundError:
					pass
			if ip_output is None:
				ip_output = subprocess.check_output([ "ip", "addr", "show", ifname ], stderr = subprocess.DEVNULL)
			ip_output = ip_output.decode("ascii")
			for match in self._IP_ADDRESS_RE.finditer(ip_output):
				match = match.groupdict()
				if match["proto"] == "inet":
					yield (match["addr"], int(match["cidr"]))
				else:
					print("Ingnoring network address of %s, unknown protocol %s: %s" % (ifname, match["proto"], str(match)), file = sys.stderr)
		except subprocess.CalledProcessError:
			raise UnknownInterfaceException("Unknown interface %s, cannot determine network address." % (ifname))

class InterfaceNetwork(Interface):
	def __iter__(self):
		for ifname in self._interfaces:
			for (ifaddress, cidr) in self._get_ifaddress(ifname):
				ip_int = int.from_bytes(bytes(int(x) for x in ifaddress.split(".")), byteorder = "big")
				netmask_int = ((1 << cidr) - 1) << (32 - cidr)
				network_int = ip_int & netmask_int
				network = ".".join(str(x) for x in int.to_bytes(network_int, byteorder = "big", length = 4))
				yield "%s/%d" % (network, cidr)

class InterfaceAddress(Interface):
	def __iter__(self):
		for ifname in self._interfaces:
			for (ifaddress, cidr) in self._get_ifaddress(ifname):
				yield ifaddress

class InterfaceName(Interface):
	def __iter__(self):
		yield from self._interfaces
