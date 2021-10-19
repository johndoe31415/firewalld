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

import enum
from pyipt.Tools import multisplit

class CriterionType(enum.Enum):
	State = "state"
	DNSBlock = "dns-block"

class Criterion():
	def __init__(self, criterion_dict):
		self._criterion = criterion_dict
		self._type = CriterionType(self._criterion["type"])

	def apply(self, rule):
		if self._type == CriterionType.State:
			if self._criterion["state"] == "established/related":
				rule.add_fixed(("--match", "state", "--state", "ESTABLISHED,RELATED"))
			else:
				raise NotImplementedError(self._criterion["state"])
		elif self._type == CriterionType.DNSBlock:
			hostname_str = self._criterion["dns-name"]
			group = rule.add_group("layer7 DNS blocking")
			for hostname in multisplit(hostname_str):
				labels = hostname.split(".")
				dns_pkt_data = bytearray()
				for label in labels:
					label = label.encode("ascii")
					dns_pkt_data.append(len(label))
					dns_pkt_data += label
				group.append(("--match", "string", "--hex-string", "|%s|" % (dns_pkt_data.hex()), "--algo", "bm", "--icase"))
		else:
			raise NotImplementedError(self._type)
