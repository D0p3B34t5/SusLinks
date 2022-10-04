#!/usr/bin/env python3

import requests
import json
import sys
import time
import urllib.parse as up
import argparse
import os
import subprocess as sp
import ipaddress
import socket
import base64
import re
from art import *

#Banner
tprint("SusLinks",font="sub-zero")

#Checking for API Keys as Environment Variables
try:
    urlapikey = os.environ['URLSCANAPIKEY']
except:
    print("URLSCANAPIKEY Environment Variable not found...")
    exit()
try: 
    vtapikey = os.environ['VTAPIKEY']
except:
    print("VTAPIKEY Environment Variable not found...")
    exit()

#Creating command-line arguments
parser = argparse.ArgumentParser(usage='python3 suslinks.py <scantype> "<url>"')
parser.add_argument('-p', '--public', action="store_const", const="public", help="Public Scan")
parser.add_argument('-u', '--unlisted', action="store_const", const="unlisted", help="Unlisted Scan")
parser.add_argument('-x', '--private', action="store_const", const="private", help="Private Scan")

#Command-line argument error handling
if len(sys.argv) < 3:          
    try:
        sys.argv[1] == True
    except:
        print("Please provide a scan type and URL. See -h or --help for usage.")
        exit()
    if sys.argv[1] == '-h':
        parser.print_help()
        exit()
    if sys.argv[1] == '--help':
        parser.print_help()
        exit()
    try:
        sys.argv[2] == True
    except:
        print("Please provide a valid URL. See -h or --help for usage")
        exit()
elif len(sys.argv) > 3:
    print("Too many arguments. Use -h or --help for usage")
    exit()
else: 
    url = sys.argv[2]
    
#Parse argument to store scan type constant string depending on optional argument
if sys.argv[1] == '-p':
    args = parser.parse_args(['-p'])
elif sys.argv[1] == '-u':
    args = parser.parse_args(['-u'])
elif sys.argv[1] == '-x':
    args = parser.parse_args(['-x'])
else:
    print("Please provide a valid scan type. See -h or --help for usage.")
    exit()

#Setting scan type variable
if args.public:
    scantype = "public"
elif args.unlisted:
    scantype = "unlisted"
elif args.private:
    scantype = "private"    

#Remove the files from the previous scan to make new ones.
if os.path.exists("URLResults.txt"):
    os.remove("URLResults.txt")
else:
    pass
if os.path.exists("URLScanResults.txt"):
    os.remove("URLScanResults.txt")
else:
    pass
if os.path.exists("VTScan.txt"):
    os.remove("VTScan.txt")
else:
    pass    
print("Scan type: " + scantype)

#If protocol is in link, separate protocol to variable
if '://' in url:
    protocol = url.split('://')[0]
    url = url.split('://')[1]
else:
    protocol = "http"

#Parse provided URL to URL encode special characters   
url = up.quote_plus(url)



#Search API Call
print("[+] Searching for URL on URLScan.IO...")
headers = {'API-Key': '{}'.format(urlapikey)}
query = 'https://urlscan.io/api/v1/search/?q=domain:"{}"'.format(url.replace('/', '\/'))
req = requests.get(query, headers=headers)
results = req.json()
total = results['total']

#If there are search results, write each UUID found to file. If no search results, scan URL and write those results to file.
if total != 0:
    uuids = []
    item = results['results']
    print("[+] Results found! Grabbing associated UUID's...")
    time.sleep(1)
    with open("URLResults.txt", 'w') as uuid:        
        for i in range(0, len(item)):
            uid = item[i]['task']['uuid']
            uuid.write(uid + '\n')
            uuids.append(uid)
     
    #Using Results API for each UUID found in Search API results: 
    ips = []
    hashes = []
    print("[+] Calling Results API for each UUID found in Search API Results...")
    for uuid in uuids:
        resulturl = 'https://urlscan.io/api/v1/result/' + uuid
        finalresults = requests.get(resulturl, headers=headers)
        frjson = finalresults.json()
        finalresults_str = json.dumps(finalresults_json, indent=4)
        stats = frjson['stats']['protocolStats']        
        with open('URLResults.txt', 'a') as scanresult:
            scanresult.write("Scan job:" + '\n' + '\n' + json.dumps(frjson['task'], indent=4) + '\n' + '\n')
            scanresult.write("Malicious?: " + str(frjson['verdicts']['urlscan']['malicious']) + '\n' + '\n')
            scanresult.write("Associated Domains:" + '\n' + '\n' + json.dumps(rjson['lists']['domains'], indent=4) + '\n' + '\n')
            scanresult.write("Associated IP's:" + '\n' + '\n') 
            for dictionary in stats:
                for val in dictionary['ips']:
                    scanresult.write(val + '\n')
                    ips.append(val)
                scanresult.write('\n')
                scanresult.write("Associated Hashes:" + '\n' + '\n')
                for item in frjson['lists']['hashes']:
                    scanresult.write(item + '\n')
                    hashes.append(item)
            scanresult.write('\n' * 3)
    print('[+] Scan results saved to file "URLResults.txt" in this scripts PWD')
    time.sleep(1)
else: 
    #Send URL to Submission API for scanning, set response in JSON to 'rj' variable
    print("[+] No results for URL found. Starting URL scan...")
    headers_post = {
        'API-Key': '{}'.format(urlapikey), 
        'Content-Type':'application/json'
        }
    data = {
        'url': '{}'.format(sys.argv[2]), 
        'visibility': '{}'.format(scantype)
        }
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers_post, data=json.dumps(data))
    rj = response.json()
   
    #Setting error messages for Submission API error responses
    print("[+] Checking for Submission API Error responses...")
    try:
        rj['description']
        if "blacklist" in rj['description']:
            print("ERROR: URL is on URLScan.IO's blacklist and won't be scanned...")
            exit()
        if "not resolve domain" in rj['description']:
            print("ERROR: The domain could not be resolved")
            exit()
        if "weird hostname" in rj['description']:
            print("ERROR: Weird hostname. Did you provide the correct URL?")
            exit()
    except KeyError as error:
        pass
        
    #Creating the URL for the Results API from the UUID in the scan API reponse
    uuid = response.json()['uuid']
    resulturl = 'https://urlscan.io/api/v1/result/' + uuid
    
    #Need to learn polling more :D just waiting 60 seconds to ensure results.
    print("[+] Waiting 60 seconds for results...")
    time.sleep(60)
    
    #Results API call
    finalresults = requests.get(resulturl, headers=headers)
    frjson = finalresults.json()
    finalresults_str = json.dumps(frjson, indent=4)
    stats = frjson['stats']['protocolStats']
    
    #Write results to file, create lists of IP's, domains and hashes for VT scan. 
    ips = []
    hashes = []
    with open('URLScanResults.txt', 'w') as scanresult:
        scanresult.write("Scan job:" + '\n' + '\n' + json.dumps(frjson['task'], indent=4) + '\n' + '\n')
        scanresult.write("Malicious?: " + str(frjson['verdicts']['urlscan']['malicious']) + '\n' + '\n')
        scanresult.write("Associated Domains:" + '\n' + '\n' + str(frjson['lists']['domains']) + '\n' + '\n')
        scanresult.write("Associated IP's:" + '\n' + '\n') 
        for dictionary in stats:
            for val in dictionary['ips']:
                scanresult.write(val + '\n')
                ips.append(val)
        scanresult.write('\n')
        scanresult.write("Associated Hashes:" + '\n' + '\n')
        for item in frjson['lists']['hashes']:
            scanresult.write(item + '\n')
            hashes.append(item)
    print('[+] Scan results saved to file "URLScanResults.txt" in this scripts PWD')
    time.sleep(1)
    
#Setting variables for VirusTotal scan
notfound = [] #<----- This variable is for the hashes not found in the VT search API call.
ipv4 = []
ipv6 = [] 
domains = frjson['lists']['domains']
vtheaders = {
    'x-apikey':'{}'.format(vtapikey), 
    'accept':'application/json'
    }
vt_postheaders = {
    'x-apikey':'{}'.format(vtapikey), 
    'accept':'application/json', 
    'content-type':'application/x-www-form-urlencoded'
    }
ipurl = "https://www.virustotal.com/api/v3/ip_addresses/"
domurl = "https://www.virustotal.com/api/v3/domains/"
hashurl = "https://www.virustotal.com/api/v3/files/"
scanurl = "https://www.virustotal.com/api/v3/urls"
analysisurl = "https://www.virustotal.com/api/v3/urls/"

#removing duplicates from IP, domain and hash lists. No order needed so using Set() method.
ips = set(ips)
domains = set(domains)
hashes = set(hashes)

print("[+] Beginning search for associated IP's, hashes and domains on VirusTotal...")
time.sleep(1)

#VirusTotal search on each IP in IPs list from URLScan report
print("     [+] Searching associated IP's on VirusTotal...")
time.sleep(1)
for ip in ips:
    try:
        socket.inet_aton(ip)
        ipv4.append(ip)
    except:
        ipv6.append(ip)
if len(ipv4) > 20:
    print("       More than 20 IPv4 addresses detected...")
    print("       Total IPv4 addresses: " + str(len(ipv4)))
    print("       Estimated time for IP scan: " + str(len(ipv4) // 4) + " minutes")
    cont = input("       Continue with scan? [Y/N]: ")   
    if cont == "Y" or cont == "y": 
        print("     [+] Continuing with IP scan...")
        for ip in ipv4:
                new_ipurl = ipurl + '{}'.format(ip)
                ip_response = requests.get(new_ipurl, headers=vtheaders)
                irjson = ip_response.json()
                with open("VTScan.txt", 'a') as ipreport:            
                    ipreport.write(ip + ': ' + "Malicious: " + str(irjson['data']['attributes']['last_analysis_stats']['malicious']) + ' | ' + 'Harmless: ' + str(irjson['data']['attributes']['last_analysis_stats']['harmless']) + ' | ' + "Suspicious: " + str(irjson['data']['attributes']['last_analysis_stats']['suspicious']) + ' | ' + "Undetected: " + str(irjson['data']['attributes']['last_analysis_stats']['undetected']) + '\n')
                time.sleep(15)    
        with open("VTScan.txt", 'a') as spaces:
                if bool(ipv6):
                    spaces.write('\n' + "Associated IPv6 addresses that were not scanned: " + '\n')
                    for ip in ipv6:
                        spaces.write(str(ip) + '\n')
                    spaces.write('\n' * 2)    
                else:
                    spaces.write('\n' * 2)
    elif cont == "N" or cont == "n":
        pass
else:
    for ip in ips:
        try:
            socket.inet_aton(ip)
            new_ipurl = ipurl + '{}'.format(ip)
            ip_response = requests.get(new_ipurl, headers=vtheaders)
            irjson = ip_response.json()
            with open("VTScan.txt", 'a') as ipreport:            
                ipreport.write(ip + ': ' + "Malicious: " + str(irjson['data']['attributes']['last_analysis_stats']['malicious']) + ' | ' + 'Harmless: ' + str(irjson['data']['attributes']['last_analysis_stats']['harmless']) + ' | ' + "Suspicious: " + str(irjson['data']['attributes']['last_analysis_stats']['suspicious']) + ' | ' + "Undetected: " + str(irjson['data']['attributes']['last_analysis_stats']['undetected']) + '\n')
            time.sleep(15)    
        except:
            ipv6.append(ip)
    with open("VTScan.txt", 'a') as spaces:
            if bool(ipv6):
                spaces.write('\n' + "Associated IPv6 addresses that were not scanned: " + '\n')
                for ip in ipv6:
                    spaces.write(str(ip) + '\n')
                spaces.write('\n' * 2)    
            else:
                spaces.write('\n' * 2)

#VirusTotal search on each hash in Hashes list from URLScan Report
print("     [+] Searching associated hashes on VirusTotal.....")
time.sleep(1)
if len(hashes) > 20:
    print("       More than 20 hashes detected...")
    print("       Total hashes: " + str(len(hashes)))
    print("       Estimated time for hash scan: " + str(len(hashes) // 4) + " minutes")
    cont = input("       Continue with scan? [Y/N]: ")
    if cont == "Y" or cont == "y":
        print("     [+] Continuing with hash scan...")
        with open("VTScan.txt", 'a') as hashreport:
            for single_hash in hashes:
                new_hashurl = hashurl + '{}'.format(single_hash)
                hash_resp = requests.get(new_hashurl, headers=vtheaders)
                hrjson = hash_resp.json()
                try: 
                    "NotFoundError" in hrjson['error']['code']
                    notfound.append(single_hash)
                    time.sleep(15)
                except:
                    hashreport.write(single_hash + ': ' + "Malicious: " + str(hrjson['data']['attributes']['last_analysis_stats']['malicious']) + ' | ' + 'Harmless: ' + str(hrjson['data']['attributes']['last_analysis_stats']['harmless']) + ' | ' + "Suspicious: " + str(hrjson['data']['attributes']['last_analysis_stats']['suspicious']) + ' | ' + "Undetected: " + str(hrjson['data']['attributes']['last_analysis_stats']['undetected']) + '\n')
                    time.sleep(15)
            hashreport.write('\n' * 2)
    elif cont == "N" or cont == "n": 
        pass
else:
    with open("VTScan.txt", 'a') as hashreport:
        for single_hash in hashes:
            new_hashurl = hashurl + '{}'.format(single_hash)
            hash_resp = requests.get(new_hashurl, headers=vtheaders)
            hrjson = hash_resp.json()
            try: 
                "NotFoundError" in hrjson['error']['code']
                notfound.append(single_hash)
                time.sleep(15)
            except:
                hashreport.write(single_hash + ': ' + "Malicious: " + str(hrjson['data']['attributes']['last_analysis_stats']['malicious']) + ' | ' + 'Harmless: ' + str(hrjson['data']['attributes']['last_analysis_stats']['harmless']) + ' | ' + "Suspicious: " + str(hrjson['data']['attributes']['last_analysis_stats']['suspicious']) + ' | ' + "Undetected: " + str(hrjson['data']['attributes']['last_analysis_stats']['undetected']) + '\n')
                time.sleep(15)
        hashreport.write('\n' * 2)
        if len(notfound) > 0:
            hashreport.write("Hashes that returned 0 results on VirusTotal: " + ('\n' * 2))
            for file in notfound:
                hashreport.write(file + '\n')
            hashreport.write('\n' * 2)
            
#VirusTotal search on each associated domain from URLScan Report
print("     [+] Searching associated domains on VirusTotal...")
time.sleep(1)
if len(domains) > 20:
    print("       More than 20 domains detected...")
    print("       Total domains: " + str(len(domains)))
    print("       Estimated time for domain scan: " + str(len(domains) // 4) + " minutes")
    cont = input("       Continue with scan? [Y/N]: ")
    if cont == "Y" or cont == "y":
        print("     [+] Continuing with domain scan...")
        with open("VTScan.txt", 'a') as domreport:
            for domain in domains:
                new_domurl = domurl + domain
                dom_req = requests.get(new_domurl, headers=vtheaders)
                drjson = dom_req.json()
                domreport.write(domain + ': ' + "Malicious: " + str(drjson['data']['attributes']['last_analysis_stats']['malicious']) + ' | ' + 'Harmless: ' + str(drjson['data']['attributes']['last_analysis_stats']['harmless']) + ' | ' + "Suspicious: " + str(drjson['data']['attributes']['last_analysis_stats']['suspicious']) + ' | ' + "Undetected: " + str(drjson['data']['attributes']['last_analysis_stats']['undetected']) + '\n')
                time.sleep(15)
            domreport.write('\n' * 2)
    elif cont == "N" or cont == "n":
        pass
else:
    with open("VTScan.txt", 'a') as domreport:
        for domain in domains:
            new_domurl = domurl + domain
            dom_req = requests.get(new_domurl, headers=vtheaders)
            drjson = dom_req.json()
            domreport.write(domain + ': ' + "Malicious: " + str(drjson['data']['attributes']['last_analysis_stats']['malicious']) + ' | ' + 'Harmless: ' + str(drjson['data']['attributes']['last_analysis_stats']['harmless']) + ' | ' + "Suspicious: " + str(drjson['data']['attributes']['last_analysis_stats']['suspicious']) + ' | ' + "Undetected: " + str(drjson['data']['attributes']['last_analysis_stats']['undetected']) + '\n')
            time.sleep(15)
        domreport.write('\n' * 2)

print('[+] VirusTotal search results saved to "VTScan.txt" in this scripts PWD')
with open("VTScan.txt", 'a') as doc:
    doc.write("VirusTotal URL Scan results:" + ('\n' * 2))
time.sleep(1)

#Scan URL with Virus Total
print("[+] Sending URL to VirusTotal API for scanning...")
payload = 'url={}%3A%2F%2F{}'.format(protocol, url)
req = requests.post(scanurl, data=payload, headers=vt_postheaders)
print("     [+] Waiting 15 seconds for results...")
time.sleep(15)

#Retrieve VirusTotal scan analysis and append to VT Scan results file.
url_id = base64.urlsafe_b64encode('{}'.format(sys.argv[2]).encode()).decode().strip("=")
new_url = analysisurl + url_id
req = requests.get(new_url, headers=vtheaders)
response = req.json()
with open("VTScan.txt", 'a') as results:
    results.write(json.dumps(response, indent=4))
print('[+] Scan analysis appended to "VTScan.txt"...')
time.sleep(1)

print("[+] Scan complete...")
#ezlife
