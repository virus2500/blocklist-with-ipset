#!/usr/bin/perl
use strict; use warnings;
################################################################
###### Script to check Blocklist.de list. Block new IP    ###### 
###### and unblock deleted entrys                         ###### 
################################################################

## config ##
my $listUrl = "http://lists.blocklist.de/lists/all.txt";
my $fileName = "Blocklist.txt";
my $tmpDir = "/tmp";
my $file = "$tmpDir/$fileName";

## binarys ##
my $iptables = "/sbin/iptables";
my $ipset = "/usr/sbin/ipset";
my $grep = "/bin/grep";
my $rm = "/bin/rm";
my $wget = "/usr/bin/wget";

## plain variables ##
my($row, $Blocklist, $line, $check, $checkLine, $result, $output, $ipRegex);

my ($added, $removed, $skipped); 
$added = $removed = $skipped = 0;

## init arrays ##
my @fileArray = ();
my @ipsetArray = ();

## init hashes for faster searching
my %ipsetArray;
my %fileArray;

#****************************#
#*********** MAIN ***********#
#****************************#
&iptablesCheck();
&getFileArray();
&getIpsetArray();
&addIpsToBlocklist();
&remIpsFromBlocklist();
&cleanup();

exit;
#***** END MAIN *****#


#****************************#
#******* Subroutines ********#
#****************************#



############# iptablesCheck ###############
## checks if all necessary               ##
## iptable/ipset Settings have been set  ##
###########################################

sub iptablesCheck {
    ## Do we have an BLOCKLIST/DROP Chain?
    if (`$iptables -L -n | $grep BLOCKLIST` =~ m/Chain BLOCKLIST/) {
    } else {
        print "Creating Chain BLOCKLIST \n";
        `$iptables -N BLOCKLIST`;
        `$iptables -A BLOCKLIST -m limit --limit 2/min -j LOG --log-prefix "Blocklist Dropped: " --log-level 4`;
        `$iptables -A BLOCKLIST -j DROP`;
    }
    
    ## Do we have an ipset list called blocklist?
    if(`$ipset list -n | $grep blocklist` =~ m/blocklist/) {
    } else {
        `$ipset create blocklist hash:ip hashsize 4096`;
        print "Created ipset list blocklist\n";
    }
    
    ## Is there an forwarded from INPUT to BLOCKLIST?
    if (`$iptables -L INPUT | $grep BLOCKLIST`=~ m/BLOCKLIST/) {
    } else {
        print "Creating forward to BLOCKLIST chain \n";
        `$iptables -I INPUT -m set --match-set blocklist src -j BLOCKLIST`;
    }
}

######## END iptablesCheck ########


########## getFileArray #############
## downloads the Blocklist.txt and ##
## pushes it into an array         ##
#####################################
sub getFileArray {
    `$wget -q -O $tmpDir/$fileName $listUrl && echo "Downloaded temp file to $tmpDir/$fileName" || echo "Can not download file.... stopping"`;

    open(INFO, $file) or die("Could not open file.");
    foreach $line (<INFO>) {
        push(@fileArray, $line);
    }

    close(INFO);
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
    @ipsetArray = split("\n", $output);
#    %ipsetArray = map { $_ => 1} @ipsetArray;
    #remove the first 6 Elements of our Array using splice (ipset header info)
    splice @ipsetArray, 0, 6;
    %ipsetArray = map { $_ => 1} split("\n", $output);
}

##### END getIpsetArray #########

######## addIpsToBlocklist ######
## adds IPs to our blocklist   ##
#################################

sub addIpsToBlocklist {
    foreach $line (@fileArray) { 
        if (exists $ipsetArray{"$line"}) {
            $skipped++;
        } else {
            if ($line eq &isIpv4($line)) { 
                $result = `$ipset add blocklist $line`;
                $added++;
                print "added $line\n"
            } else {
                $skipped++;
            }
        }
    }
}
######## END addIpsToBlocklist ######

########## remIpsFromBlocklist ########
## remove IPs from our blocklist   ##
#####################################
sub remIpsFromBlocklist {
    foreach $line (@ipsetArray) {
        if (exists $fileArray{"$line"}) {
            $skipped++;   
        } else {
            if ($line eq &isIpv4($line)) {
                $result = `$ipset del blocklist $line`;
                print "removed $line\n";
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
    $result = `$rm $tmpDir/$fileName && echo "Deleted file $tmpDir/$fileName" || echo "Can\t delete file $tmpDir/$fileName"`;
    print "\nWe added $added, removed $removed, skipped $skipped Rules\n";
}
############### END cleanup ######################

######## END ipToRegex ########

############ isIpv4 #############
## check if given value looks  ##
## like an ipv4 ip address     ##
#################################
sub isIpv4 {
    my ($isIp) = @_;
    if ($isIp =~ m/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/) {
        #print "It's an IPv4\n";
        return $isIp;
    } else {
        return 0;
    }
}
######### END isIpv4 ##########

######### EOF ###########
