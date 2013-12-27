blocklist-with-ipset
====================
Use at your own risk :)

Create an ipset based blocklist from an text file (downloaded from e.g. blocklist.de)

!!! IMPORTANT !!!!
You will need to install ipset!

Then open the blocklist.pl with your favorite text Editor and specify why your binarys are located.

(These can be found via "which" e.g. "which iptables")

my $iptables = "/sbin/iptables";

my $ipset = "/usr/sbin/ipset";

my $grep = "/bin/grep";

my $rm = "/bin/rm";

my $wget = "/usr/bin/wget";

