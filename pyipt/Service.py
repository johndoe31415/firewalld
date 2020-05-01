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
import collections
from pyipt.PortMap import PortMap
from pyipt.Tools import multisplit
from pyipt.Exceptions import MalformedServiceException, UnknownServiceException, ProtocolOmittedException, AmbiguousServiceException

class Service():
	_SERVICE_RE = re.compile(r"(?P<name>[-a-z0-9]+)\s+(?P<port>\d+)/(?P<proto>[a-z]+)(\s+(?P<aliases>[^#]+))?")
	_SERVICE_RANGE_RE = re.compile(r"((?P<name>[a-z][-a-z0-9]*)|((?P<port>\d+))(-(?P<end_port>\d+))?)(/(?P<proto>[a-z+]+|\*))?")
	_PROTO_ALIASES = {
		"dhcps":		"bootps",
		"dns":			"domain",
	}
	_KNOWN_SERVICES = None

	def __init__(self, service_str):
		if self._KNOWN_SERVICES is None:
			self._KNOWN_SERVICES = self._parse_known_services()
		self._service_str = service_str
		self._port_maps = collections.defaultdict(PortMap)
		for single_service in multisplit(service_str):
			for (start_port, end_port, proto) in self._parse_single_service(single_service):
				self._port_maps[proto].add_range(start_port, end_port)

	def _parse_single_service(self, single_service):
		match = self._SERVICE_RANGE_RE.fullmatch(single_service)
		if match is None:
			raise MalformedServiceException("Service does not match the service regex: %s (as part of %s)" % (single_service, self._service_str))
		match = match.groupdict()

		if match["name"] is not None:
			# Named service
			name = match["name"]
			if name in self._PROTO_ALIASES:
				name = self._PROTO_ALIASES[name]
			if name not in self._KNOWN_SERVICES:
				raise UnknownServiceException("Service %s is not known: %s" % (name, single_service))

			catalog = self._KNOWN_SERVICES[name]
			specified_proto = match["proto"]
			if (specified_proto == "*") or ((specified_proto is None) and (len(catalog) == 1)):
				for (proto_name, port) in catalog.items():
					yield (port, port, proto_name)
			else:
				raise AmbiguousServiceException("Service is ambiguous: %s" % (match["name"]))
		else:
			if match["proto"] is None:
				raise ProtocolOmittedException("When specifying an explicit service port, you need to specify the protocol(s) as well: %s" % (single_service))
			protos = multisplit(match["proto"], "+")
			start_port = int(match["port"])

			for proto in protos:
				if match["end_port"] is None:
					yield (start_port, start_port, proto)
				else:
					yield (start_port, int(match["end_port"]), proto)

	def _parse_known_services(self):
		services = { }
		with open("/etc/services") as f:
			for line in f:
				result = self._SERVICE_RE.match(line)
				if result is None:
					continue
				result = result.groupdict()
				service_names = [ result["name"] ]
				if result["aliases"] is not None:
					aliases = result["aliases"].strip().split()
					service_names += aliases
				for service_name in service_names:
					if service_name not in services:
						services[service_name] = { }
					services[service_name][result["proto"]] = int(result["port"])
		return services

	def __iter__(self):
		yield from sorted(self._port_maps.items())
