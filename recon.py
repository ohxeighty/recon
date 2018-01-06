#I don't got time to do yo sanity checks 
#Shell=true wee wooo
from multiprocessing import Process
import subprocess
import os 
import argparse 

jobs = [] # love me some multiprocessing 

#Linux Pretty Colours
class colors:
    	INFO = "\033[95m[*] "
    	GREEN = "\033[92m[+] "
    	FAIL = "\033[91m[-] "
    	ENDC = "\033[0m"
    	BOLD = "\033[1m"

def snmp_check(ip, port, out):
	print colors.INFO + "Starting snmp_check on %s:%s" % (ip, port) + colors.ENDC 
	communitystrings = ["public","private","community"]
	for string in communitystrings:
		snmpscan = "snmp-check -t %s -p %s -c %s" % (ip, port, string)
		results = subprocess.check_output(snmpscan, shell=True)
		
		f = open(os.path.join(ip, "%s:%s.snmp_check.txt" % (ip,port)), "w")
		f.write(results)
		f.close()

def metasploit(command, out):
	print colors.INFO + "Starting metasploit with command %s" % (command) + colors.ENDC
	msfscan = "msfconsole -q -x '%s; quit'" % (command)
	results = subprocess.check_output(msfscan, shell=True)
	f = open(out+".mssqlping.txt","w")
	f.write(results)
	f.close()

def enum4linux(ip):
	print colors.INFO + "Starting enum4linux on host %s" % (ip) + colors.ENDC
	enumscan = "enum4linux -a %s" % (ip)
	results = subprocess.check_output(enumscan, shell=True)

def nmap_scan(ip, ports, scripts, serv, out, outtag):
	ports = [x.split("/")[0] for x in ports]
	portlist = ",".join(ports)
	print colors.INFO + "Starting NMAP on host %s with scripts %s" % (ip, scripts) + colors.ENDC
	nmapscan = "nmap --script=%s -p %s %s -oN %s" % (scripts, portlist, ip, os.path.join(out,"%s:%s.nmapscan" % (ip,outtag)))
	print nmapscan
	results = subprocess.check_output(nmapscan,shell=True)
	

def gobuster_scan(ip, ports, wordlist, extensions, serv, out):
	ports = [x.split("/")[0] for x in ports]	
	for port in ports:
		print colors.INFO + "Starting Gobuster Scan on Port: %s" % (port) 
		print "Service: %s" % (serv) + colors.ENDC
		# hack mcgee #2 
		if "ssl" in serv or "https" in serv:
			scheme = "https://"
		else:
			scheme = "http://"
		gobusterscan = "gobuster -k -u %s%s -w %s -x %s -o %s" % (scheme, ip+":"+port, wordlist, extensions, os.path.join(out, "%s:%s.gobusterscan.txt"%(ip, port)))
		print gobusterscan
		results = subprocess.check_output(gobusterscan,shell=True) #Suppress normal output
		
def nikto_scan(ip, ports, serv, out):
	ports = [x.split("/")[0] for x in ports]
	portlist = ",".join(ports)
	print colors.INFO + "Starting Nikto Scan On Ports: %s" % (portlist)
	print "Service: %s" % (serv) + colors.ENDC 
	niktoscan = "nikto -ask no -h %s -p %s -F htm -output %s" % (ip, portlist, out+"%s:%s.niktoscan.html" % (ip, ports[0]))
	print niktoscan
	results = subprocess.check_output(niktoscan, shell=True) #Suppress normal output

def service_scan(ip, out, aggressive=False, wordlist="/usr/share/wordlists/dirb/common.txt", extensions=""):
	ip = ip.strip() 
	results = ""
	if not aggressive:
		print colors.INFO + "Initial NMAP Scan For " + ip + colors.ENDC
		scan = "nmap -sC -sV %s -oA '%s.initialnmap'" % (ip, os.path.join(out,ip))
		results = subprocess.check_output(scan, shell=True)	
		print colors.GREEN + "Results For " + ip + colors.ENDC
		print results 
	else:
		print colors.INFO + "Starting Intensive NMAP TCP and UDP Scans For %s - Might take a while" % (ip) + colors.ENDC
		tcpscan = "nmap -v -Pn -sS -A -sC -p- -T 3 -script-args=unsafe=1 %s -oA '%s.tcpnmap'"  % (ip, os.path.join(out,ip))
		udpscan = "nmap -v -sC -sV -sU %s -oA '%s.udpnmap'" % (ip, os.path.join(out,ip))

		tcpresults = subprocess.check_output(tcpscan, shell=True)
		print colors.GREEN + "TCP Results For " + ip + colors.ENDC
		print tcpresults
		udpresults = subprocess.check_output(udpscan, shell=True)
		print colors.GREEN + "UDP Results For " + ip + colors.ENDC
		print udpresults 
		results = tcpresults + udpresults  #2lazy2change slow string results
	serv_dict = {}
	# Open Recommendation File 
	recommendations = open("%s.recommendations.txt" % (os.path.join(out,ip)),"w")
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
			if "2100" in [x.split("/")[0] for x in ports]:
				print colors.GOOD + "Possible ORACLE XML DB FTP" + colors.ENDC
				recommendations.write("- Possible ORACLE XML DB with FTP access on port 2100. Check https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm for a list of logins.") 
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
			p = Process(target=nmap_scan, args=(ip, ports, "smb-enum-shares,smb-ls,smb-enum-users,smb-mbenum,smb-os-discovery,smb-security-mode,smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-regsvc-dos,", serv, out,"smbvuln"))
			jobs.append(p)
			p.start()

			p = Process(target=enum4linux, args=(ip,))
			jobs.append(p)
			p.start()
		elif "ms-sql" in serv:
			print "[*] Microsoft SQL detected - Launching Metasploit Confirmation Ping"
			print colors.GOOD + "Recommendation: Try Default Login with 'sa:' and 'sa:Password123'" + colors.ENDC 
			p = Process(target=metasploit, args=("use auxiliary/scanner/mssql/mssql_ping; set RHOSTS %s; run" % (ip), out+ip))
			jobs.append(p)
			p.start()
			
		elif "msdrdp" in serv or "ms-wbt-server" in serv or "microsoft-rdp" in serv:
			print "[*] Microsoft Remote Desktop Protocol service detected - Launching NMAP Vuln Check"
			p = Process(target=nmap_scan, args=(ip, ports, "rdp-vuln-ms12-020", serv, out,"rdpvuln"))
			jobs.append(p)
			p.start()
		elif "msrpc" in serv:
			print "[*] Microsoft Remote Procedure Call service detected - Launching NMAP Enumeration Scan"
			p = Process(target=nmap_scan, args=(ip, ports, "msrpc-enum", serv, out,"rpcenum"))
			jobs.append(p)
			p.start()
		elif "mysql" in serv:
			print "[*] MySQL Service Discovered - Launching NMAP Scripts"
			p = Process(target=nmap_scan, args=(ip, ports, "mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122", serv, out,"mysqlvulnenum"))
			jobs.append(p)
			p.start() 
		elif "smtp" in serv:
			print "[*] SMTP service detected - Launching NMAP Vuln Checks"
			p = Process(target=nmap_scan, args=(ip, ports, "smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764", serv, out,"smtpvulnenum"))
			jobs.append(p)
			p.start()
		elif "snmp" in serv:
			print "[*] SNMP service detected - Launching NMAP Enum Scripts and SNMP-Check"
			p = Process(target=nmap_scan, args=(ip, ports, "snmp-netstat,snmp-processes", serv, out,"snmpenum"))
			jobs.append(p)
			p.start()
			for port in [x.split("/")[0] for x in ports]:
				p = Process(target=snmp_check, args=(ip, port, out))
				jobs.append(p)
				p.start()
			
		elif "ssh" in serv: 
			print "[*] SSH service detected"
		elif "telnet" in serv:
			print "[*] Telnet service detected"

		#Interesting Services 
		if "squid" in serv:
			print colors.GOOD + "SQUID Proxy Detected!" + colors.ENDC
			recommendations.write("- SquidProxy detected, see if you can pivot to internal services. (Conduct an NMAP Scan using the squidproxy as a proxy...)")
		#print "\n"	
	f.close()
	recommendations.close()

	

#main 
parser = argparse.ArgumentParser(description="OSCP Recon Script") 
parser.add_argument("target", help="target address")
parser.add_argument("-o", "--output", help="output directory", required=True) 
parser.add_argument("-w", "--wordlist", help="wordlist for directory discovery", required=False, default="/usr/share/wordlists/dirb/common.txt")
parser.add_argument("-x", "--extensions", help="comma seperated extensions for directory discovery e.g. php, txt", required=False, default="php")  
parser.add_argument("-a", "--aggressive", help="aggressive service scanning", required=False, action="store_true")

args = parser.parse_args()

if not os.path.isdir(args.output):
	print colors.FAIL + "Supplied output directory not a directory" + colors.ENDC
	raise SystemExit()



service_scan(args.target, args.output, args.aggressive, args.wordlist, args.extensions)
for job in jobs:
	job.join()


