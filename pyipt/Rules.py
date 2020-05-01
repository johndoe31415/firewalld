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

import os
import itertools
import datetime
from pyipt.CmdlineEscape import CmdlineEscape

class Rule():
	"""The Rule is the most basic abstraction, only slightly above a single
	iptables rule. The difference is that the cross product of different
	components can be used, e.g., when trying to create a filter that blocks
	both UDP and TCP port 1234, a rule could cover both by combining, as an example:

	[ [ "-p", "tcp" ], [ "-p", "udp" ] ], [ "-j", "REJECT" ]

	The cross product of all components is then used to create iptables rules.
	"""
	def __init__(self):
		self._component_names = [ ]
		self._components = [ ]

	@property
	def has_empty_group(self):
		for component in self._components:
			if len(component) == 0:
				return True
		return False

	def add_fixed(self, *fixed_parts):
		for fixed_part in fixed_parts:
			self._component_names.append(None)
			self._components.append((fixed_part, ))

	def add_group(self, name, members = None):
		self._component_names.append(name)
		group = [ ]
		self._components.append(group)
		if members is not None:
			group += members
		return group

	def generate_commands(self):
		for permutation in itertools.product(*self._components):
			command = [ ]
			for component in permutation:
				command += component
			yield command

	def dump(self, prefix = "", file = None):
		for (cid, (component_name, components)) in enumerate(zip(self._component_names, self._components)):
			print("%s%d: %s" % (prefix, cid, component_name or "(static)"), file = file)
			for component in components:
				print("%s    -> %s" % (prefix, str(component)), file = file)

	def __str__(self):
		return "Rule<%s>" % (str(self._components))

class Rules():
	"""Every entry in the JSON configuration corresponds to one Rules instance.
	For example, a port forwarding entry might contain rules for different
	chains (e.g., FORWARD and nat.PREROUTING)."""
	def __init__(self, name):
		self._name = name
		self._rules = [ ]

	@property
	def name(self):
		return self._name

	def new(self):
		rule = Rule()
		self._rules.append(rule)
		return rule

	def __iter__(self):
		return iter(self._rules)

	def __str__(self):
		return " + ".join(str(rule) for rule in self._rules)

class Ruleset():
	"""The Ruleset is the whole firewall configuration, i.e., contains all
	commands that are passed down to iptables."""
	def __init__(self, metadata):
		self._datapoints = [ ]
		self._rules = [ ]
		self._metadata = metadata

	@property
	def metadata(self):
		return self._metadata

	def add_datapoint(self, name, data):
		self._datapoints.append((name, data))

	def add_stat(self, datapoint_name, filename):
		mtime = round(os.stat(filename).st_mtime * 1000000)
		self.add_datapoint(datapoint_name, str(mtime))

	def add_rules(self, rules):
		self._rules.append(rules)

	def write_script(self, f, verbose = False):
		cle = CmdlineEscape()
		print("#!/bin/bash", file = f)
		print("# firewall ruleset generated %s UTC by firewalld. DO NOT EDIT MANUALLY" % (datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")), file = f)
		print(file = f)
		for rules in self._rules:
			print("# %s" % (rules.name), file = f)
			for rule in rules:
				if rule.has_empty_group:
					print("# Warning: rule contains empty group and therefore no choices.", file = f)
					rule.dump(prefix = "# ", file = f)
				elif verbose:
					rule.dump(prefix = "# ", file = f)
				for command in rule.generate_commands():
					command = [ "iptables" ] + command
					print(cle.cmdline(command), file = f)
			print(file = f)

	def apply(self):
		pass
