blocklist-with-ipset
====================
Use at your own risk :)

Create an ipset based blocklist from an text file (downloaded from e.g. blocklist.de)

Changes
--------
V1.0.4: Path to white and blacklist is now set automatically

V1.0.3: Now you can set multiple blocklist sources

V1.0.2: Added a whitelist and blacklist


!!! IMPORTANT !!!!

You will need to install ipset!

Also you will have to specify where your binarys are located. This settings can be made in blocklist.pl .

(You can find out where your binarys are with "which" e.g. "which iptables")


These values need to verified for your system:

my $iptables = "/sbin/iptables";

my $ipset = "/usr/sbin/ipset";

my $grep = "/bin/grep";

my $rm = "/bin/rm";

my $wget = "/usr/bin/wget";

