#!/usr/bin/python3
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
import time
from pyipt.FriendlyArgumentParser import FriendlyArgumentParser
from pyipt.Firewall import Firewall

parser = FriendlyArgumentParser(description = "Linux firewall daemon.")
parser.add_argument("-m", "--mode", choices = [ "script", "oneshot", "daemonize" ], default = "script", help = "Mode in which firewalld operates. Can be one of %(choices)s, defaults to %(default)s.")
parser.add_argument("--iteration-time", metavar = "secs", type = float, default = 60, help = "For daemonized mode, gives the iteration time in seconds. Defaults to %(default).0f seconds.")
parser.add_argument("--ignore-errors", action = "store_true", help = "If rules cannot be resolved, e.g., because an interface does not exist, continue. This can be dangerous.")
parser.add_argument("-o", "--output", metavar = "file", type = str, default = "firewall.sh", help = "When writing a script, gives the output filename. Can be '-' for stdout. Defaults to %(default)s.")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increases verbosity. Can be specified multiple times to increase.")
parser.add_argument("ruleset", metavar = "ruleset", type = str, help = "Ruleset JSON file to load.")
args = parser.parse_args(sys.argv[1:])

fw = Firewall(args.ruleset, args)
ruleset = fw.generate()
if args.mode == "script":
	if args.output == "-":
		ruleset.write_script(sys.stdout, verbose = (args.verbose >= 1))
	else:
		with open(args.output, "w") as f:
			ruleset.write_script(f, verbose = (args.verbose >= 1))
	sys.exit(0)
elif (args.mode == "oneshot") or (args.mode == "daemonize"):
	while True:
		ruleset.apply()
		if args.mode == "oneshot":
			sys.exit(0)
		time.sleep(args.iteration_time)
