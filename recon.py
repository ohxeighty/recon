#I don't got time to do yo sanity checks 
#Shell=true wee wooo
from multiprocessing import Process
import subprocess
import os 
from ftplib import FTP

jobs = [] # love me some multiprocessing 

#Linux Pretty Colours
class colors:
    	INFO = "\033[95m[*] "
    	GREEN = "\033[92m[+] "
    	FAIL = "\033[91m[-] "
    	ENDC = "\033[0m"
    	BOLD = "\033[1m"

def metasploit(command):
	print colors.INFO + "Starting metasploit with command %s" % (command) + colors.ENDC
	msfscan = "msfconsole -q -x '%s'" % (command)
	results = subprocess.check_output(msfscan, shell=True)
def enum4linux(ip):
	print colors.INFO + "Starting enum4linux on host %s" % (ip) + colors.ENDC
	enumscan = "enum4linux -a %s" % (ip)
	results = subprocess.check_output(enumscan, shell=True)

def nmap_scan(ip, ports, scripts):
	ports = [x.split("/")[0] for x in ports]
	ports = ",".join(ports)
	print colors.INFO + "Starting NMAP on host %s with scripts %s" % (ip, scripts) + colors.ENDC
	nmapscan = "nmap --script=%s -p %s %s" % (scripts, ports, ip)
	results = subprocess.check_output(nmapscan,shell=True)

def gobuster_scan(ip, ports, wordlist, extensions, serv, out):
	ports = [x.split("/")[0] for x in ports]	
	for port in ports:
		print colors.INFO + "Starting Gobuster Scan on Port: %s" % (port) 
		print "Service: %s" % (serv) + colors.ENDC
		# hack mcgee #2 
		if "ssl" in serv:
			scheme = "https://"
		else:
			scheme = "http://"
		gobusterscan = "gobuster -k -u %s%s -w %s -x %s -o %s" % (scheme, ip+":"+port, wordlist, extensions, os.path.join(out, "%s:%s.gobusterscan.txt"%(ip, port)))
		print gobusterscan
		results = subprocess.check_output(gobusterscan,shell=True) #Suppress normal output
		
def nikto_scan(ip, ports, serv, out):
	ports = [x.split("/")[0] for x in ports]
	ports = ",".join(ports)
	print colors.INFO + "Starting Nikto Scan On Ports: %s" % (ports)
	print "Service: %s" % (serv) + colors.ENDC 
	niktoscan = "nikto -ask no -h %s -p %s -F htm -output %s" % (ip, ports, os.path.join(out, "%s:%s.niktoscan.html" % (ip, serv.replace("/",""))))
	print niktoscan
	results = subprocess.check_output(niktoscan, shell=True) #Suppress normal output

def service_scan(ip, out, intensive=False, wordlist="/usr/share/wordlists/dirb/common.txt", extensions=""):
	ip = ip.strip() 
	results = ""
	if not intensive:
		print colors.INFO + "Initial NMAP Scan For " + ip + colors.ENDC
		scan = "nmap -sC -sV %s -oA '%s/%s.initialnmap'" % (ip, out, ip)
		results = subprocess.check_output(scan, shell=True)	
		print colors.GREEN + "Results For " + ip + colors.ENDC
		print results 
	else:
		print colors.INFO + "Starting Intensive NMAP TCP and UDP Scans For %s - Might take a while" % (ip) + colors.ENDC
		tcpscan = "nmap -v -Pn -sS -A -sC -p- -T 3 -script-args=unsafe=1 %s -oA '%s/%s.tcpnmap'"  % (ip, out, ip)
		udpscan = "nmap -v -sC -sV -sU %s -oA '%s/%s.udpnmap'" % (ip, out,ip)

		tcpresults = subprocess.check_output(tcpscan, shell=True)
		print colors.GREEN + "TCP Results For " + ip + colors.ENDC
		print tcpresults
		udpresults = subprocess.check_output(udpscan, shell=True)
		print colors.GREEN + "UDP Results For " + ip + colors.ENDC
		print udpresults 
		results = tcpresults + udpresults  #2lazy2change slow string results
	serv_dict = {}
	lines = results.split("\n")
	for line in lines:
		ports = []
		line = line.strip()
		if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
			while "  " in line:
				line = line.replace("  "," ") 
			service = line.split(" ")[2] # hack mcgee 
			port = line.split(" ")[0]

			if service in serv_dict:
				ports = serv_dict[service]

			ports.append(port)
			serv_dict[service] = ports 

	print colors.INFO + "Writing found services" + colors.ENDC
	f = open(os.path.join(out,"%s.services.txt"%(ip)),"w")
	f.write("=== Services and Ports for %s ===\n" % (ip) )
	for serv in serv_dict:
		ports = serv_dict[serv]
		print colors.GREEN + "%s\n" % (serv) + colors.ENDC  + "Ports: ",  
		print ', '.join(ports) 
		f.write("[*] %s\nPorts: " % (serv) + ', '.join(ports) + "\n")
		
		#Launch Additional Scans
 		if "ftp" in serv:
			print "[*] FTP Service detected"
		elif serv == "http" or serv == "ssl/http" or "https" in serv or "http" in serv:
			print "[*] Web service detected - Launching Nikto and Gobuster" 
			p = Process(target=nikto_scan, args=(ip, ports, serv, out))
			jobs.append(p)
			p.start()

			p = Process(target=gobuster_scan, args=(ip, ports, wordlist, extensions, serv, out))
			jobs.append(p)
			p.start()
		elif "mysql" in serv:
			print "[*] MySQL service detected"
		elif "microsoft-ds" in serv:
			print "[*] Microsoft Directory Service detected - Launching NMAP SMB Vuln Scan and enum4linux"
			p = Process(target=nmap_scan, args=(ip, ports, "smb-enum-shares.nse,smb-ls.nse,smb-enum-users.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-security-mode.nse,smbv2-enabled.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse,smbv2-enabled.nse"))
			jobs.append(p)
			p.start()

			p = Process(target=enum4linux, args=(ip))
			jobs.append(p)
			p.start()
		elif "ms-sql" in serv:
			print "[*] Microsoft SQL detected - Launching Metasploit Scan" 
			p = Process(target=metasploit, args=("use auxiliary/scanner/mssql/mssql_ping; set RHOSTS %s; run" % (ip)))
			jobs.append(p)
			p.start()
		elif "msdrdp" in serv or "ms-wbt-server" in serv or "microsoft-rdp" in serv:
			print "[*] Microsoft Remote Desktop Protocol service detected"
		elif "msrpc" in serv:
			print "[*] Microsoft Remote Procedure Call service detected - Launching NMAP Enumeration Scan"
			p = Process(target=nmap_scan, args=(ip, ports, "msrpc-enum"))
			jobs.append(p)
			p.start()
			
		elif "smtp" in serv:
			print "[*] SMTP service detected - Launching NMAP Vuln Checks"
			p = Process(target=nmap_scan, args=(ip, ports, "smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764"))
			jobs.append(p)
			p.start()
		elif "snmp" in serv:
			print "[*] SNMP service detected"
		elif "ssh" in serv: 
			print "[*] SSH service detected"
		elif "telnet" in serv:
			print "[*] Telnet service detected"

		#Interesting Services 
		if "squid" in serv:
			print colors.GOOD + "SQUID Proxy Detected!" + colors.ENDC
		
		print "\n"

	f.close()
	




#os check out is not a directory blah blah 
service_scan("127.0.0.1", "/tmp/", False, "/usr/share/wordlists/dirb/common.txt", "php")
	
#for job in jobs:
	#job.join()
