blocklist-with-ipset
====================
Use at your own risk :)

Create an ipset based blocklist from an text file (downloaded from e.g. blocklist.de)

V1.0.2: Added a whitelist and blacklist


!!! IMPORTANT !!!!

You will need to install ipset!


If you want to run the script as an cronjob you will have to specify the absolute path to the whitelist.txt and blacklist.txt in blocklist.pl

my $whiteList = "whitelist.txt";

my $blackList = "blacklist.txt";

to e.g.

my $whiteList = "/scripts/blocklist/whitelist.txt";

my $blackList = "/scripts/blocklist/blacklist.txt"

where /scripts/blocklist/ is the path to the white and blacklist file!


While in blocklist.pl please also specify and verify where your binarys are located.

(These can be found via "which" e.g. "which iptables")

my $iptables = "/sbin/iptables";

my $ipset = "/usr/sbin/ipset";

my $grep = "/bin/grep";

my $rm = "/bin/rm";

my $wget = "/usr/bin/wget";

