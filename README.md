# SusLinks
A script written in Python3 that utilizes the URLScan.IO and VirusTotal API's to scan aand provide details for a supplied URL. 


![image](https://user-images.githubusercontent.com/98996357/193865988-71971d46-e8f4-4970-82df-d9473c72d24a.png)


## Why SusLinks?
Are you getting some phishy emails in your inbox that contain SUSpicious links? Well, of course you are! Ever wonder what all happens when you go to the link embedded in the phishing email? Well  don't click it to find out, use SusLinks! 

The goal in mind behind SusLinks was to provide a URL, have it sent for scanning to the URLScan.IO API and pull back all the associated IP's, hashes and domains, use the VirusTotal API to search the verdict (malicious, harmless, suspicious, unidentified) of each item, and then run a VirusTotal URL scan. Then, print all those results to a text file to examine. And well, that's excatly what this script does!


## API Authentication
**NOTE:**
For this script, I have decided to implement environment variables as the means of passing both of your URLScan.IO and VirusTotal API keys. You'll need to manually add these environment variables for this script to work, and I have provided instructions below on how to do so. 

### **Windows**
  - Open the Control Panel
  - Select User Accounts (and then User Accounts again if you're view is set to Category)
  - Select "Change my environment variables" 
  - Create 2 new User Environment Variables (Top box) 
    - 1st Variable Name: URLSCANAPIKEY
      - Value: <urlscan.io api key>
    - 2nd Variable Name: VTAPIKEY
      - Value: <virustotal.com api key>
  - Make sure to click "OK" and not just close out of the window
  - Open CMD and type: 
  
        set PATH=C
  - Close out and open new CMD/PowerShell window
  
### **Linux**
  - Open your primary shells RunCommands script (.bashrc, .zshrc, etc) in your preferred text editor
  - Append the following to the end of the file  
  
        export URLSCANAPIKEY="<insert urlscan api key>"
        export VTAPIKEY="< insert virustotal api key>" 
  - Save the file and run the source command on your RunCommand script
    - Examples:
    
          source ~/.bashrc
          source ~/.zshrc
          
## A few things to note:
  - Due to VirusTotal's free-tier limitation to 4 requets per minute, each search request is set to send 15 seconds apart. I have set the script to alert you if more than 20 IP's, hashes or domains (equivalent to around 5 minutes per scan) are detected, and will provide the total number of each and an estimated scan time. The VirusTotal searches could possibly take up to 15 minutes (or more if you allow a longer scan) if your URL results pull back 20 IP's, hashes and domains.
  - Until I find a good way to handle the text file creation, I currenlty have the script set to remove the previous scans files and create new ones, so I'd advice doing a Save As or moving the text files to a different directory if you want individual copies of results. 
  - The TXT files get created in this scripts PWD
## Requirements: 
**Written and tested on Python version 3.10.7**

The following Python modules are required for this script to run: 
  - art
  
        pip install art
  - requests
  
        pip install requests
        
  ## Usage
        
    python3 suslinks.py <scantype> "<url>"
  For help:
  
    python3 suslinks.py -h
        
  **Note:** 
  
  - This script for now requires you to call Python rather than the script directly when running it. 
  - Wrap your URL in quotes for all shells. 
  
  
  ![image](https://user-images.githubusercontent.com/98996357/193878923-3b73231c-1ae5-400e-a0e1-44dea853de97.png)

  


    
