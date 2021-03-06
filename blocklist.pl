#!/usr/bin/perl
use strict; 
use warnings;
use FindBin '$Bin';
use Data::Validate::IP qw(is_ipv4 is_ipv6);
use Getopt::Std;
no if ($] >= 5.018), 'warnings' => 'experimental::smartmatch';
################################################################
###### Script to parse a Blocklist list. Block new IP     ######
###### and unblock deleted entrys                         ######
###### Multiple list possible. IPV4 and IPV6 supported    ######
################################################################

## config ##
my @listUrl     = ("http://lists.blocklist.de/lists/all.txt", "http://www.infiltrated.net/blacklisted");
my $tmpDir      = "/tmp";
my $logFile     = "/var/log/blocklist";
my $whiteList   = "$Bin/whitelist.txt";
my $blackList   = "$Bin/blacklist.txt";

## binarys ##
## ! Notice ! Changing these values shouldn't be needed anymore
## I'll leave it here just in case none of the paths below match.
$ENV{'PATH'}    = '/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin';
my $iptables    = "iptables";
my $ip6tables   = "ip6tables";
my $ipset       = "ipset";
my $grep        = "grep";
my $rm          = "rm";
my $wget        = "wget";

## plain variables ##
my($row, $Blocklist, $line, $check, $checkLine, $result, $output, $url, $ipRegex, $message, %opt, $opt);

my ($added, $count, $removed, $skipped);
$added = $count = $removed = $skipped = 0;

## init arrays ##
my @fileArray = ();
my @ipsetArray = ();
my @whiteListArray = ();
my @blackListArray = ();
## init hashes for faster searching
my %whiteListArray;
my $blackListArray;
my %ipsetArray;
my %fileArray;

my $dateTime;
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
my @months = qw( Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec );
my @days = qw(Sun Mon Tue Wed Thu Fri Sat Sun);

&init();

############# init ##################
#### check if we got any options ####
#### and decide where to go      ####
#####################################

sub init {
    $opt = 'hc';
    getopts( "$opt", \%opt );
    usage() if $opt{h};
    cleanupAll() if $opt{c};
    # else start main subroutine
    main();
}
############## end init #############

############ usage ##################
#### Some info about this script ####
#####################################
sub usage() {
    print STDERR << "EOF";
    blocklist-with-ipset
    
    This script downloads and parses Text files with IPs and blocks them. 
    Just run ./blocklist.pl
    
    If you want to clean everything up run
    ./blocklist.pl -c
EOF
    exit;
}
#****************************#
#*********** MAIN ***********#
#****************************#
sub main {
    logging("Starting blocklist refresh");
    &iptablesCheck();
    &getWhiteListArray();
    &getBlackListArray();
    &getFileArray();
    &getIpsetArray();
    &addIpsToBlocklist();
    &remIpsFromBlocklist();
    &cleanup();

    exit;
}
#***** END MAIN *****#


#****************************#
#******* Subroutines ********#
#****************************#



############# iptablesCheck ###############
## checks if all necessary               ##
## iptable/ipset Settings have been set  ##
###########################################

sub iptablesCheck {
    ## Do we have an BLOCKLIST/DROP Chain in iptables?
    if (`$iptables -L -n | $grep BLOCKLIST` =~ m/Chain BLOCKLIST/) {
        # Do nothing...
    } else {
        $message = "Creating Chain BLOCKLIST";
        logging($message);
        `$iptables -N BLOCKLIST`;
        `$iptables -A BLOCKLIST -m limit --limit 2/min -j LOG --log-prefix "Blocklist Dropped: " --log-level 4`;
        `$iptables -A BLOCKLIST -j DROP`;
    }

    ## Do we have an BLOCKLIST/DROP Chain in ip6tables?
    if (`$ip6tables -L -n | $grep BLOCKLIST` =~ m/Chain BLOCKLIST/) {
        # Do nothing...
    } else {
        $message = "Creating Chain BLOCKLIST";
        logging($message);
        `$ip6tables -N BLOCKLIST`;
        `$ip6tables -A BLOCKLIST -m limit --limit 2/min -j LOG --log-prefix "Blocklist Dropped: " --log-level 4`;
        `$ip6tables -A BLOCKLIST -j DROP`;
    }
    ## Do we have an ipset list called blocklist?
    if(`$ipset list -n | $grep blocklist` =~ m/blocklist/ && `$ipset list -n | $grep blocklist` =~ m/blocklist-v6/  ) {
        # Do nothing
    } else {
        `$ipset create blocklist hash:ip hashsize 4096 maxelem 131050`;
        `$ipset create blocklist-v6 hash:ip hashsize 4096 family inet6 maxelem 131050`;
        $message = "Created ipset list blocklist";
        logging($message);
    }
        
    ## Is there an forwarded from INPUT to BLOCKLIST in iptables?
    if (`$iptables -L INPUT | $grep BLOCKLIST`=~ m/BLOCKLIST/ && `$iptables -L INPUT | $grep BLOCKLIST`=~ m/blocklist/) {
        # Do nothing
    } else {
        `$iptables -I INPUT -m set --match-set blocklist src -j BLOCKLIST`;
        $message = "Creating forward to BLOCKLIST chain";
        logging($message);
    }
    ## Is there an forwarded from INPUT to BLOCKLIST in ip6tables?
    if (`$ip6tables -L INPUT | $grep BLOCKLIST`=~ m/BLOCKLIST/ && `$ip6tables -L INPUT | $grep BLOCKLIST`=~ m/blocklist-v6/) {
        # Do nothing
    } else {
        `$ip6tables -I INPUT -m set --match-set blocklist-v6 src -j BLOCKLIST`;
        $message = "Creating forward to BLOCKLIST chain";
        logging($message);
    }

}

######## END iptablesCheck ########


########## getFileArray #############
## downloads the Blocklist.txt and ##
## pushes it into an array         ##
#####################################
sub getFileArray {
    foreach $url (@listUrl) {
        $count++;
        `$wget -q -O $tmpDir/Blocklist_$count $url && echo "Downloaded temp file to $tmpDir/Blocklist_$count" || echo "Can not download file.... stopping"`;

        open(INFO, "$tmpDir/Blocklist_$count") or die("Could not open file.");
        foreach $line (<INFO>) {
            push(@fileArray, $line);
        }

        close(INFO);
    }
    chomp(@fileArray);
    %fileArray = map {$_ => 1 } @fileArray;
}
####### END getFileArray ##########

######### getIpsetArray ##########
## runs ipset list blocklist    ##
## and pushes it into           ##
## array ipsetList              ##
##################################

sub getIpsetArray {
    $output = `$ipset list blocklist`;
    $output .= `$ipset list blocklist-v6`;
    @ipsetArray = split("\n", $output);
    #remove the first 6 Elements of our Array using splice (ipset header info)
    splice @ipsetArray, 0, 6;
    %ipsetArray = map { $_ => 1} split("\n", $output);
}

##### END getIpsetArray #########

######### getWhiteListArray ######
## puts all ips from our        ##
## $whitelist into              ##
## array whiteListArray         ##
##################################

sub getWhiteListArray {
    open(INFO, $whiteList) or die("Could not open Whitelist.");
    foreach $line (<INFO>) {
        push(@whiteListArray, $line);
    }

    close(INFO);
    chomp(@whiteListArray);
}
##### END getWhiteListArray #####

######### getBlackListArray ######
## puts all ips from our        ##
## $whitelist into              ##
## array blackListArray         ##
##################################

sub getBlackListArray {
    open(INFO, $blackList) or die("Could not open Blacklist.");
    foreach $line (<INFO>) {
        push(@blackListArray, $line);
    }

    close(INFO);
    chomp(@blackListArray);
}
##### END getBlackListArray #####

######## addIpsToBlocklist ######
## adds IPs to our blocklist   ##
#################################

sub addIpsToBlocklist {
    foreach $line (uniq(@blackListArray)) {
        if ((exists $ipsetArray{"$line"}) ||    ($line ~~ @whiteListArray)) {
            $skipped++;
        } else {
            if (is_ipv4($line) || is_ipv6($line)) {
                if(is_ipv4($line)) {
                    $result = `$ipset add blocklist $line`;
                } else {
                    $result = `$ipset add blocklist-v6 $line`;
                }
                $added++;
                $message = "added $line";
                logging($message);
            } else {
                $skipped++;
            }
        }
    }
    foreach $line (uniq(@fileArray)) { 
        if ((exists $ipsetArray{"$line"}) || ($line ~~ @whiteListArray)) {
            $skipped++;
        } else {
            if (is_ipv4($line) || is_ipv6($line)) {
                if(is_ipv4($line)) {
                    $result = `$ipset add blocklist $line`;
                } else {
                    $result = `$ipset add blocklist-v6 $line`;
                }
                $added++;
                $message = "added $line";
                logging($message);
            } else {
                $skipped++;
            }
        } 
    } 

}
######## END addIpsToBlocklist ######

########## remIpsFromBlocklist ########
## remove IPs from our blocklist     ##
#######################################
sub remIpsFromBlocklist {
    # remove Ips that are in our whiteList
    foreach $line (@whiteListArray) {
        if ((exists $ipsetArray{"$line"}) && ($line ~~ @whiteListArray)) {
            if (is_ipv4($line) || is_ipv6($line)) {
                if(is_ipv4($line)) {
                    $result = `$ipset del blocklist $line`;
                } else {
                    $result = `$ipset del blocklist-v6 $line`;
                }
                $message = "removed $line";
                logging($message);
                $removed++;
            } else {
            $skipped++;
            }
        }
    }

    foreach $line (@ipsetArray) {
        if ((exists $fileArray{"$line"}) || ($line ~~ @blackListArray)) {
            $skipped++;     
        } else {
            if (is_ipv4($line) || is_ipv6($line)) {
                if(is_ipv4($line)) {
                    $result = `$ipset del blocklist $line`;
                } else {
                    $result = `$ipset del blocklist-v6 $line`;
                }
                $message = "removed $line";
                logging($message);
                $removed++;
            } else {
                $skipped++;
            }
        }
    }
}

######## END remIpsFromBlocklist ########


################## cleanup ###################
#### Cleanup: move tmp file to new place #####
##############################################
sub cleanup {
    for (1..$count) {
        $result = `$rm $tmpDir/Blocklist_$_ && echo "Deleted file $tmpDir/Blocklist_$_" || echo "Can\t delete file $tmpDir/Blocklist_$_"`;
    }
    $message = "We added $added, removed $removed, skipped $skipped Rules";
    logging($message);
}
############### END cleanup ######################

########### cleanupAll #################
#### Remove our Rules from iptables ####
#### and flush our ipset lists      ####
########################################

sub cleanupAll {
    if (`$iptables -n -L | $grep BLOCKLIST` =~ m/Chain BLOCKLIST/) {
        `$iptables -D INPUT -m set --match-set blocklist src -j BLOCKLIST`;
        `$iptables -F BLOCKLIST`;
        `$iptables -X BLOCKLIST`;
        `$ipset destroy blocklist`;
        `$ipset destroy blocklist-v6`;
    }
    if (`$ip6tables -n -L | $grep BLOCKLIST` =~ m/Chain BLOCKLIST/) {
        `$ip6tables -D INPUT -m set --match-set blocklist-v6 src -j BLOCKLIST`;
        `$ip6tables -F BLOCKLIST`;
        `$ip6tables -X BLOCKLIST`;
        `$ipset destroy blocklist`;
        `$ipset destroy blocklist-v6`;
    }

    exit;
}

########################################

###### log #######
## log $message ##
##################
sub logging {
    my ($message) = @_;

    ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();

    open my $fh, ">>", $logFile
        or die "Can't open logfile: $!";
    $dateTime = sprintf("$months[$mon]  %02d %02d:%02d:%02d ", $mday,$hour,$min,$sec);
    print $fh "$dateTime $message\n";
    print "$message\n";

    close($fh);
}
#### end log #####

############## uniq ###############
## Make sure we wont             ##
## add/remove the same ip twice  ##
###################################

sub uniq { my %seen; grep !$seen{$_}++, @_ } # from http://stackoverflow.com/questions/13257095/remove-duplicate-values-for-a-key-in-hash

#### end uniq ####

######### EOF ###########
