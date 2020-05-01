# firewalld
firewalld is yet another application that builds a firewall ruleset for
iptables. It uses a fairly expressive JSON syntax that allows much more
flexibility than iptables would itself and decomposes those rules into one (or
sometimes more than one) iptables commands.

The idea is also to allow filtering according to, for example, a specific time
(e.g., disallow access to a specific site after a specific time) and allow
expressive syntax for layer 7 DNS filtering.

## License
GNU GPL-3.
