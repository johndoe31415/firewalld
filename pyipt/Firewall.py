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

import json
import sys
import datetime
import enum
from pyipt.Protocol import Protocol
from pyipt.Rules import Rules, Ruleset
from pyipt.Service import Service
from pyipt.Interface import InterfaceNetwork, InterfaceAddress, InterfaceName
from pyipt.Hostname import Hostname
from pyipt.MultiEnum import ICMPType
from pyipt.Condition import Condition
from pyipt.RegexMatches import PortforwardTarget
from pyipt.Chain import Chain
from pyipt.Exceptions import IncompatibleOptionsException, UnknownTypeError, FirewallRulesetException
from pyipt.Criterion import Criterion

class RuleType(enum.Enum):
	Accept = "accept"
	Reject = "reject"
	Drop = "drop"
	Log = "log"
	Masquerade = "masquerade"
	PortForward = "port-forward"

class HighlevelRule():
	_SIMPLE_PARSE_CLASSES = {
		"action":			RuleType,
		"proto":			Protocol,
		"criterion":		Criterion,
		"comment":			str,
		"dest-service":		Service,
		"src-service":		Service,
		"icmp-type":		ICMPType,
		"cond":				Condition,
		"forward-to":		PortforwardTarget,
		"msg":				str,
	}
	_COMPLEX_PARSE_CLASSES = {
		"dest-host":		Hostname,
		"src-host":			Hostname,
		"dest-net":			InterfaceNetwork,
		"src-net":			InterfaceNetwork,
		"dest-ifaddr":		InterfaceAddress,
		"src-ifaddr":		InterfaceAddress,
		"dest-if":			InterfaceName,
		"src-if":			InterfaceName,
	}

	def __init__(self, rule_src, config):
		self._rule_src = rule_src
		self._config = config
		self._parsed = { }
		for (key, value) in self._rule_src.items():
			if key.startswith("_"):
				continue
			if key in self._SIMPLE_PARSE_CLASSES:
				self._parsed[key] = self._SIMPLE_PARSE_CLASSES[key](value)
				continue
			if key in self._COMPLEX_PARSE_CLASSES:
				self._parsed[key] = self._COMPLEX_PARSE_CLASSES[key](value, self._config)
				continue
			raise UnknownTypeError("Do not know how to parse: %s (in rule '%s')" % (key, str(self._rule_src)))

		self._sanity_check()

	@property
	def action(self):
		return self._parsed["action"]

	@property
	def comment(self):
		if "comment" in self._parsed:
			return self._parsed["comment"]
		else:
			return str(self._rule_src)

	def _sanity_check(self):
		if "action" not in self._parsed:
			raise IncompatibleOptionsException("'action' is not defined in rule: %s" % (str(self._rule_src)))
		if ("service" in self._parsed) and ("proto" in self._parsed):
			raise IncompatibleOptionsException("'service' and 'proto' are mutually exclusive in rule: %s" % (str(self._rule_src)))
		if ("icmp-type" in self._parsed) and ("proto" in self._parsed):
			raise IncompatibleOptionsException("'icmp-type' and 'proto' are mutually exclusive in rule: %s" % (str(self._rule_src)))
		if self.action == RuleType.PortForward:
			if "dest-ifaddr" not in self._parsed:
				raise IncompatibleOptionsException("port forwarding requires 'dest-ifaddr' in rule: %s" % (str(self._rule_src)))
			if "dest-service" not in self._parsed:
				raise IncompatibleOptionsException("port forwarding requires 'dest-service' in rule: %s" % (str(self._rule_src)))
			if "forward-to" not in self._parsed:
				raise IncompatibleOptionsException("port forwarding requires 'forward-to' in rule: %s" % (str(self._rule_src)))
			if (not self._parsed["forward-to"]["relative"]) and (self._parsed["forward-to"]["port"] is not None) and (any((portmap.span_count > 1) for (proto, portmap) in self._parsed["dest-service"])):
				raise IncompatibleOptionsException("port forwarding requires relative port mapping when more than one span is defined in rule: %s" % (str(self._rule_src)))
			hostname = Hostname(self._parsed["forward-to"]["hostname"], self._config)
			if len(hostname) != 1:
				raise IncompatibleOptionsException("port forwarding requires exactly one match for hostname, but found %d (%s) in rule: %s" % (len(hostname), ", ".join(hostname), str(self._rule_src)))

	def insert(self, chain_name, ruleset):
		if "cond" in self._parsed:
			if not self._parsed["cond"].satisfied(ruleset.metadata):
				return

		chain = Chain.parse(chain_name)

		rules = Rules(self.comment)
		rule = rules.new()
		rule.add_fixed(chain.iptables_append())

		if "proto" in self._parsed:
			group = rule.add_group("proto")
			for proto in self._parsed["proto"]:
				group.append([ "-p", proto ])

		if "icmp-type" in self._parsed:
			group = rule.add_group("icmp-type")
			for icmp_type in self._parsed["icmp-type"]:
				group.append([ "-p", "icmp", "--icmp-type", icmp_type ])

		for srcdest in [ "src", "dest" ]:
			if srcdest + "-if" in self._parsed:
				option = {
					"src":	"-i",
					"dest":	"-o",
				}[srcdest]
				group = rule.add_group(srcdest + "-if")
				for ifname in self._parsed[srcdest + "-if"]:
					group.append([ option, ifname ])
			if srcdest + "-net" in self._parsed:
				option = {
					"src":	"-s",
					"dest":	"-d",
				}[srcdest]
				group = rule.add_group(srcdest + "-net")
				for network in self._parsed[srcdest + "-net"]:
					group.append([ option, network ])
			if srcdest + "-service" in self._parsed:
				group = rule.add_group(srcdest + "-service")
				if (srcdest == "dest") and self._parsed["action"] == RuleType.PortForward:
					# For port forwarding/DNAT target, the syntax is different
					def dnat_target(incoming_port, forward_to):
						hostname = Hostname(forward_to["hostname"], self._config)
						result = [ "-j", "DNAT", "--to" ]
						if len(hostname) == 0:
							print("Warning: For DNAT/port forwarding, a target is required, but %s could not be resolved successfully." % (forward_to["hostname"]))
						elif len(hostname) != 1:
							print("Warning: For DNAT/port forwarding, a single target is required, but %d were found. Arbitrarily picking the first one." % (len(hostname)))
						if forward_to["port"] is None:
							result.append(hostname[0])
						else:
							if forward_to["relative"]:
								result.append("%s:%d" % (hostname[0], incoming_port + forward_to["port"]))
							else:
								result.append("%s:%d" % (hostname[0], forward_to["port"]))
						return result

					for (proto, port_map) in self._parsed[srcdest + "-service"]:
						for single_port in port_map.single:
							group.append([ "-p", proto, "--dport", str(single_port) ] + dnat_target(single_port, self._parsed["forward-to"]))
						for (begin_range, end_range) in port_map.ranges:
							group.append([ "-p", proto, "--dport", "%d:%d" % (begin_range, end_range) ] + dnat_target(begin_range, self._parsed["forward-to"]))
				else:
					# Not port forwarding (simple ACCEPT/REJCECT/etc.)
					option = {
						"src":	"s",
						"dest":	"d",
					}[srcdest]
					for (proto, port_map) in self._parsed[srcdest + "-service"]:
						if port_map.port_count == 1:
							group.append([ "-p", proto, "--%sport" % (option), str(port_map[0]) ])
						else:
							if len(port_map.single) > 1:
								group.append([ "-p", proto, "--match", "multiport", "--%sports" % (option), ",".join(str(port) for port in port_map.single) ])
							for (begin_range, end_range) in port_map.ranges:
								group.append([ "-p", proto, "--match", "multiport", "--%sports" % (option), "%d:%d" % (begin_range, end_range) ])
			if srcdest + "-ifaddr" in self._parsed:
				option = {
					"src":	"-s",
					"dest":	"-d",
				}[srcdest]
				group = rule.add_group(srcdest + "-ifaddr")
				for address in self._parsed[srcdest + "-ifaddr"]:
					group.append([ option, address ])
			if srcdest + "-host" in self._parsed:
				option = {
					"src":	"-s",
					"dest":	"-d",
				}[srcdest]
				group = rule.add_group(srcdest + "-host")
				for address in self._parsed[srcdest + "-host"]:
					group.append([ option, address ])

		if "criterion" in self._parsed:
			self._parsed["criterion"].apply(rule)

		if self._parsed["action"] in (RuleType.Accept, RuleType.Reject, RuleType.Drop, RuleType.Masquerade, RuleType.Log):
			rule.add_fixed(("-j", self._parsed["action"].value.upper()))
		elif self._parsed["action"] == RuleType.PortForward:
			# We're in nat.PREROUTING
			pass
		else:
			raise NotImplementedError(self._parsed["action"])

		if self._parsed["action"] == RuleType.Log:
			if "msg" in self._parsed:
				rule.add_fixed(("--log-prefix", self._parsed["msg"] + ": "))

		if "comment" in self._parsed:
			rule.add_fixed(("-m", "comment", "--comment", self._parsed["comment"]))

		ruleset.add_rules(rules)

class Firewall():
	def __init__(self, ruleset_filename, args):
		self._ruleset_filename = ruleset_filename
		self._args = args

	def _parse_chain(self, ruleset, chain_name, content):
		if "rules" in content:
			for rulesrc in content["rules"]:
				try:
					hl_rule = HighlevelRule(rulesrc, ruleset.metadata["source"])
					hl_rule.insert(chain_name, ruleset)
				except FirewallRulesetException as e:
					if not self._args.ignore_errors:
						raise
					else:
						print("Continuing in spite of error: %s (%s)" % (str(e), str(rulesrc)), file = sys.stderr)

	def _initialize_chains(self, ruleset):
		rules = Rules("initializing all chains")

		for (chain_name, content) in ruleset.metadata["source"]["chains"].items():
			chain = Chain.parse(chain_name)
			if "default" in content:
				rule = rules.new()
				rule.add_fixed(chain.iptables_policy(), (content["default"].upper(), ))

			rule = rules.new()
			rule.add_fixed(chain.iptables_flush())
		ruleset.add_rules(rules)

	def _parse_ruleset(self, ruleset):
		self._initialize_chains(ruleset)
		for (chain_name, content) in ruleset.metadata["source"]["chains"].items():
			self._parse_chain(ruleset, chain_name, content)

	def generate(self):
		with open(self._ruleset_filename) as f:
			source = json.load(f)
		source["interfaces-rev"] = { value: key for (key, value) in source["interfaces"].items() }
		metadata = {
			"now":		datetime.datetime.now(),
			"source":	source,
		}
		ruleset = Ruleset(metadata)
		ruleset.add_stat("ruleset_mtime", self._ruleset_filename)
		self._parse_ruleset(ruleset)
		return ruleset
