#I don't got time to do yo sanity checks 
#Shell=true wee wooo
import multiprocessing 
import subprocess
import os 

#Linux Pretty Colours
class colors:
    	INFO = "\033[95m[*] "
    	GREEN = "\033[92m[+] "
    	FAIL = "\033[91m"
    	ENDC = "\033[0m"
    	BOLD = "\033[1m"

def nmap_scan(ip, out, intensive=False):
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
	f = open(os.path.join(out,ip+"services.txt"),"w")
	for serv in serv_dict:
		ports = serv_dict[serv]
		print "[*] %s\nPorts: " % (serv), 
		print ports + "\n"
 


#os check out is not a directory blah blah 

	
