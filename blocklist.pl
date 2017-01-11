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
my @listUrl     = ("http://lists.blocklist.de/lists/all.txt");
my $tmpDir      = "/tmp";
my $logFile     = "/var/log/blocklist";
my $whiteList   = "/etc/blocklist/whitelist";
my $blackList   = "/etc/blocklist/blacklist";

## binarys ##
## ! Notice ! Changing these values shouldn't be needed anymore
## I'll leave it here just in case none of the paths below match.
$ENV{'PATH'}    = '/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin';
my $nft         = "nft";
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
    blocklist-with-nftable
    
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
    &nftablesCheck();
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



############# nftablesCheck ###############
## checks if all necessary               ##
## nftable/ipset Settings have been set  ##
###########################################

sub nftablesCheck {
    ## Do we have an ipset list called blocklist?
    if(`$nft list ruleset ip | $grep blocklist` =~ m/blocklist/ && `$nft list ruleset ip6 | $grep blocklist` =~ m/blocklist/  ) {
        # Do nothing
    } else {
	`$nft add table blocklist`;
	`$nft add set blocklist ipv4 { type ipv4_addr\\;}`;
	`$nft add table ip6 blocklist`;
	`$nft add set ip6 blocklist ipv6 { type ipv6_addr\\;}`;
	$message = "Created ipset list blocklist";
	logging($message);
    }
    ## Do we have an INPUT/DROP Chain in nftables?
    if (`$nft list ruleset ip | $grep input` =~ m/chain input/) {
        # Do nothing...
    } else {
        $message = "Creating Chain input";
        logging($message);
        `$nft add chain ip blocklist input {type filter hook input priority 100\\; policy accept\\;}`;
        `$nft add rule ip blocklist input ip saddr \@ipv4 log prefix \\"Blocklist Dropped: \\" drop`;
    }

    ## Do we have an INPUT/DROP Chain in ip6tables?
    if (`$nft list ruleset ip6 | $grep input` =~ m/chain input/) {
        # Do nothing...
    } else {
        $message = "Creating Chain input";
        logging($message);
        `$nft add chain ip6 blocklist input {type filter hook input priority 100\\; policy accept\\;}`;
        `$nft add rule ip6 blocklist input ip6 saddr \@ipv6 log prefix \\"Blocklist Dropped: \\" drop`;
    }
}

######## END nftablesCheck ########


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
    $output = `$nft list set ip blocklist ipv4`;
    $output .= `$nft list set ip6 blocklist ipv6`;
    @ipsetArray = (split /elements = \{ (.*?)\}/, $output)[1,3];
    if ((defined $ipsetArray[0]) && (defined $ipsetArray[1]))
    {
        %ipsetArray = map { $_ => 1} split /, /,$ipsetArray[0].", ".$ipsetArray[1];
    }
    elsif (defined $ipsetArray[0])
    {
	%ipsetArray = map { $_ => 1} split /, /,$ipsetArray[0];
    }
    elsif (defined $ipsetArray[1])
    {
	%ipsetArray = map { $_ => 1} split /, /,$ipsetArray[1];
    }
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
                    $result = `$nft add element ip blocklist ipv4 { $line }`;
                } else {
                    $result = `$nft add element ip6 blocklist ipv6 { $line }`;
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
                    $result = `$nft add element ip blocklist ipv4 { $line }`;
                } else {
                    $result = `$nft add element ip6 blocklist ipv6 { $line }`;
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
                    $result = `$nft delete element ip blocklist ipv4 { $line }`;
                } else {
                    $result = `$nft delete element ip6 blocklist ipv6 { $line }`;
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
                    $result = `$nft delete element ip blocklist ipv4 { $line }`;
                } else {
                    $result = `$nft delete element ip6 blocklist ipv6 { $line }`;
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
#### Remove our Rules from nftables ####
#### and flush our ipset lists      ####
########################################

sub cleanupAll {
    if(`$nft list ruleset ip | $grep blocklist` =~ m/blocklist/ ) {
	`$nft delete table ip blocklist`;
    }
    if(`$nft list ruleset ip6 | $grep blocklist` =~ m/blocklist/  ) {
	`$nft delete table ip6 blocklist`;
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
