#!/bin/bash
# You are NOT allowed to change the files' names!
domainNames="domainNames.txt"
IPAddresses="IPAddresses.txt"
adblockRules="adblockRules"

tmp_file="/tmp/_out"

function adBlock() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi

    if [ "$1" = "-domains"  ]; then
        # Configure adblock rules based on the domain names of $domainNames file.
        # Write your code here...

        line_count=$(grep -c . $domainNames)
        yeahthiswontwork=()
        while IFS= read -r line
        do
            dig +short $line | grep '^[.0-9]*$' >> $tmp_file &
        done < <(grep . $domainNames)
        wait
        # cat $tmp_file
        
        iptables -N adblock 2>/dev/null
        iptables -C INPUT -j adblock 2>/dev/null
        if [[ $? == 1 ]]
        then
            iptables -A INPUT -j adblock
        fi

        while IFS= read -r line
        do
            iptables -A adblock -s $line -j REJECT
        done < <(grep . $tmp_file)

        rm $tmp_file

        true
            
    elif [ "$1" = "-ips"  ]; then
        # Configure adblock rules based on the IP addresses of $IPAddresses file.
        # Write your code here...
        
        iptables -N adblock 2>/dev/null
        iptables -C INPUT -j adblock 2>/dev/null
        if [[ $? == 1 ]]
        then
            iptables -A INPUT -j adblock
        fi

        while IFS= read -r line
        do
            iptables -A adblock -s $line -j REJECT
        done < <(grep . $IPAddresses)

        true
        
    elif [ "$1" = "-save"  ]; then
        # Save rules to $adblockRules file.
        # Write your code here...
        
        iptables-save -f $adblockRules

        true
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $adblockRules file.
        # Write your code here...
        
        iptables-restore $adblockRules

        true

    elif [ "$1" = "-reset"  ]; then
        # Reset rules to default settings (i.e. accept all).
        # Write your code here...
        
        iptables -F adblock 2>/dev/null
        iptables -D INPUT -j adblock 2>/dev/null
        iptables -X adblock 2>/dev/null

        true

    elif [ "$1" = "-list"  ]; then
        # List current rules.
        # Write your code here...
        
        iptables -S adblock 2>/dev/null

        true
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ips\t\t  Configure adblock rules based on the IP addresses of '$IPAddresses' file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

adBlock $1
exit 0