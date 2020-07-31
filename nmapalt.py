#Importing nmap module for python 
import nmap 

#Variable to call nmap PortScanner class
scanner = nmap.PortScanner()

print("This is a nmap alternative tool")
print("<---------------------------------------------------------------------->")

#Input taken from the user
ip_addr = input("Enter IP address to be scanned : ")
print("IP entered is : ", ip_addr)

#Input sanitization
type(ip_addr)

#User input for type of scan to be performed
resp = input(""" \nEnter type of scan:
                 1) SYN ACK Scan
                 2) UDP Scan
                 3) Comprehensive Scan \n""")

print("Selected Option : ",resp)

#Scan Option selection 
if resp == '1':
    print("Nmap Version: ",scanner.nmap_version())

    #Scanning IP using scanner object created. Takes IP address, ports to be scanned and type of scan as parameters (-sS SYN ACK scan)
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    
    #type of services provided
    print(scanner.scaninfo())

    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())

    #Display open port. Function returns all open ports 
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())

elif resp == '2':
    print("Nmap Version: ",scanner.nmap_version())

    #Scanning IP using scanner object created. Takes IP address, ports to be scanned and type of scan as parameters (-sU UDP scan)
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    
    #type of services provided
    print(scanner.scaninfo())

    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())

    #Display open port. Function returns all open ports 
    print("Open Ports: ", scanner[ip_addr]['udp'].keys())

elif resp == '3':
    print("Nmap Version: ",scanner.nmap_version())

    #Scanning IP using scanner object created. Takes IP address, ports to be scanned and type of scan as parameters
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    
    #type of services provided
    print(scanner.scaninfo())

    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())

    #Display open port. Function returns all open ports 
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())

elif resp >= '4':
    print("Please enter valid option")

    