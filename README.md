# TaticalRecon
TaticalRecon is a bash Tool to find vulnerabilities on websites.

# Version
- 1.2
- Extension to txt
- Bug Fixes

# Help
```
./tatical-recon.sh -h
```
```
TaticalRecon 1.2: Help
-all-apis:      Use -all of subfinder.
-th:      Use theHarvesterTool.
-gen:      Use DnsGen to Recon.
-wilcards:      Recon on Wilcards
-urls:      Recon on Urls

Scans:
-nrich:      CVE Scan on IPS with Nrich
-iis-scan:      Find IIS (Windows Server)
-firebase-scan:      Find Firebase
-js-scan:      Scan JavaScript files with Nuclei
-wp-scan:      Recon on WordPress subdomains and vulnerabilities.
-cpanel-scan:      Recon on cPanel
-nuclei-fuzzer:      Fuzzing on Parameters with Fuzzing-Templates
```

# Usage
```
./tatical-recon.sh site.com <flags>
```

# Tool
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [Subdominator](https://github.com/RevoltSecurities/Subdominator)
- [Sublist3r](https://github.com/aboul3la/Sublist3r)
- [ShodanX](https://github.com/RevoltSecurities/ShodanX)
- [Assetfinder](https://github.com/tomnomnom/assetfinder)
- [Findomain](https://github.com/Findomain/Findomain)
- [Haktrails](https://github.com/hakluke/haktrails)
- [Chaos](https://github.com/projectdiscovery/chaos-client)
- [theHarvester](https://github.com/laramies/theHarvester)
- [DNSGen](https://github.com/AlephNullSK/dnsgen)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Anew](https://github.com/tomnomnom/anew)
- [HTTPX](https://github.com/projectdiscovery/httpx)
- [DnsX](https://github.com/projectdiscovery/dnsx)
- [Naabu](https://github.com/projectdiscovery/naabu)
- [Nrich](https://github.com/retr0-13/nrich)
- [Katana](https://github.com/projectdiscovery/katana)
- [ParamSpider](https://github.com/devanshbatham/ParamSpider)
- [GauPlus](https://github.com/bp0lr/gauplus)
- [WaybacklUrls](https://github.com/tomnomnom/waybackurls)
- [Hakrawler](https://github.com/hakluke/hakrawler)
- [Qsreplace](https://github.com/tomnomnom/qsreplace)
- [Gf](https://github.com/tomnomnom/gf)
- [AiriXSS](https://github.com/ferreiraklet/airixss)
- [ListDomains](https://github.com/yHunterDep/listdomains/)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [Nuclei Old](https://github.com/pikpikcu/nuclei-templates)
- [PikPikCu Templates](https://github.com/pikpikcu/my-nuclei-templates)

# Nuclei Templates Used
https://github.com/projectdiscovery/nuclei-templates<br>
https://github.com/pikpikcu/my-nuclei-templates => ~/nco/pikpikcu: line 190<br>
https://github.com/pikpikcu/nuclei-templates => ~/nco/nucl-ant: line 190

# Ports
`21,22,23,25,53,69,80,88,110,115,123,137,139,143,161,179,194,389,443,445,465,500,546,547,587,636,993,994,995,1025,1080,1194,1433,1434,1521,1701,1723,1812,1813,2049,2222,2375,2376,3306,3389,3690,4443,5432,5800,5900,5938,5984,6379,6667,6881,8080,8443,8880,9090,9418,9999,10000,11211,15672,27017,28017,3030,33060,4848,5000,5433,5672,6666,8000,8081,8444,8888,8905,9000,9042,9160,9990,11210,12201,15674,18080,1965,1978,2082,2083,2086,2087,2089,2096,22611,25565,27018,28015,33389,4369,49152,54321,54322,55117,55555,55672,5666,5671,6346,6347,6697,6882,6883,6884,6885,6886,6887,6888,6889,8088,8089,9001,9415,17089,27019,34443,3659,45557,55556,5673,5674,6370,6891,6892,6893,6894,6895,6896,6897,6898,6899,6900,6901,6902,6903,6904,6905,6906,6907,6908,6909,6910,6911,6912,6913,6914,6915,6916,6917,6918,6919,6920,6921,6922,6923,6924,6925,6926,81,300,591,593,832,981,1010,1311,1099,2095,2480,3000,3128,3333,4242,4243,4567,4711,4712,4993,5104,5108,5280,5281,5601,5985,6543,7000,7001,7396,7474,8001,8008,8014,8042,8060,8069,8083,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8500,8184,8834,8983,9043,9060,9080,9091,9200,9443,9502,9800,9981,10250,11371,12443,16080,17778,18091,18092,20720,32000,55440,22222,32400`
