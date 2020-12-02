#!/bin/bash

key="supper secret key"

if [[ $# -lt 1 ]]; then
    printf "\n\nUsage:\n\t./ransomware.sh [X | -d]\n <number of files>, creates a number of test files and encrypts them simulating the process of a randomware\n"
    printf " -d, decrypt all files that were encryted in this directory\n\n"
    exit 1
fi

if [[ $1 != "-d" ]] ; then
    # ransomware
    re='^[0-9]+$'
    if ! [[ $1 =~ $re ]] ; then
        echo "error: Not a number" >&2
        exit 1
    fi

    for i in $(seq 1 $1); do
        printf "IMPORTANT DATA!\nfile_$i" | tee "file_$i" > /dev/null
        openssl enc -aes-256-ecb -iter 100 -in "file_$i" -out "file_$i.encrypt" -k "$key"
        rm "file_$i"
    done
else
    # decrypt function
    for i in *.encrypt; do
        [ -f "$i" ] || break
        openssl aes-256-ecb -iter 100 -in $i -out "${i%.*}" -d -k "$key"
        rm $i
    done
fi