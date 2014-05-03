blocklist-with-ipset
====================
Use at your own risk :)

Written and tested on Debian Wheezy!

Create an ipset based blocklist from an url to an blocklist text file e.g. blocklist.de.

As of Version 1.0.3 you can use multiple Sources at once!

Changes
--------
- V1.1.1: short Help (-h) and Cleanup (-c) available. Binary should now be found automatically 
- V1.1.0: blocklist-with-ipset is now IPV6 compatible (Yayyy :) ) 
- V1.0.4: Path to white and blacklist is now set automatically
- V1.0.3: Now you can set multiple blocklist sources
- V1.0.2: Added a whitelist and blacklist

<br>
**!!! IMPORTANT !!!!**

When upgrading from a version lower than 1.1.0 you might have to manually drop duplicated INPUT Rules. 

Also you will have to specify where your binarys are located. This settings can be made in blocklist.pl .

(You can find out where your binarys are with "which" e.g. "which iptables")

## INSTALL ##

1. Make sure you have ipset and the Data::Validate::IP Perl Module installed! If not you can usually install it with your distribution software management tool. E.g. apt for Debian/Ubuntu/Mint.

		apt-get install ipset libdata-validate-ip-perl

2. Download the ZIP, or Clone the repository, to a folder on your system.

3. Open blocklist.pl with your favorite text editor and set up your blocklist urls. Two are included as default. You can enhance or edit as you like. The destination URL should be an direct link to an Text file though.

    	my @listUrl = ("http://lists.blocklist.de/lists/all.txt", "http://www.infiltrated.net/blacklisted");

	*You can for example add an list like this*

		my @listUrl = ("http://lists.blocklist.de/lists/all.txt", "http://www.infiltrated.net/blacklisted", "http://www.superblocksite.org/anotherBlocklist.txt");

4. Create an cronjob. I have mine in /etc/crontab

		0 */1   * * *   root    /usr/bin/perl /path/to/the/script/blocklist.pl > /dev/null

5. Create an logrotate for the logfile. E.g. under /etc/logrotate.d/blocklist

		/var/log/blocklist
		{
		    rotate 4
		    daily
		    missingok
		    notifempty
		    delaycompress
		    compress
		}

6. If you have an ip you definitly want to block just put it in blacklist.txt. If you have an IP you definitly never want to have blocked put it in whitelist.txt. This two files are just text lists seperated by new lines. So for example

		#blacklist.txt
		2.2.2.2
		3.3.3.3 

		#and in whitelist.txt
		4.4.4.4
		5.5.5.5

That's it. If you want to manually run the script just cd to the folder where the script is located and run ./blocklist.pl

## CLEANUP ##

If you want to remove the iptables rules
