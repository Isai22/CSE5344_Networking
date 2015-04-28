# -*- coding: utf-8 -*-
"""
Created on Tue Mar 31 21:51:43 2015

@author: Isaiah


This program is a simple packet sniffer. It will sniff packets and display
important packet information.
"""

"""
NOTES:
    
    to get the throughput we can have a server running which our program will bind to and
    send a file, we measure the time for it and that will give us the RTT. Also we can store the data
    so that we can then filter through it according to the user. 

    Note to self: Include dealing with IPv6 data packets!
    
    
"""

import socket
import sys
import platform
from struct import *
import re
import time
import matplotlib.pyplot as plt
import Tkinter as Tk

def main() :
    #Determine which operating system is in use: windows or linux
    os = platform.system()
    if(os == 'Linux'):
        sniff_Linux(os)
    elif(os == 'Windows'):
	sniff_packets(os)

#Linux versio of the program
def sniff_Linux(os):    
	#create all the list that will contain the packets, segragated by protocols
	packet_List = []
    	TCP_List = []
    	UDP_List = []
    	ICMP_List = []
    	IGMP_List = []
    	Other_List = []
	ARP_List = []
	IPv6_List = []
	
	"""
	Sniffer Begins here
	"""
	try:
	    	s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
		print "Linux"
		print "\nPacket previews will be displayed, after a specific number of packets it stops sniffing.\n"
	        raw_input('Press Enter to continue')
		limit = 400
		count = 0
        	#loop that will print a small preview of the IP header for the user to see and capture the packets        
        	while(count < limit):
        	    	#receive the data packets of up to size 65565
        	    	packet = s.recvfrom(65565)
        	    	#take the packet data from the tuple provided from call recvfrom which contains (packet, sourde Address)
        	    	packet = packet[0]
			#print the ethernet data
			eth_length, eth_protocol = print_Etho(packet)        	    	
			if(eth_protocol == "0x800"):			
				#allows the user to preview the Ip header info and help in choosing when to stop
        	    		IP_preview_Linux(packet, eth_length)
			else:
				print "ARP Query!"
        	    	#store every packet being sniffed in the appropriate list which will be later placed in a dictionary
        	    	store_data_Linux(packet, packet_List, TCP_List, UDP_List, ICMP_List, IGMP_List, Other_List, ARP_List, IPv6_List)
			count += 1
    	#exception to deal with issues in creation of the socket
    	except socket.error , msg:
        	print 'Socket could not be created. Error code : ' + str(msg[0]) + ' Message ' + msg[1]
        	sys.exit()
    	#exception to catch the command CTRL-C and continue with the program
    	except KeyboardInterrupt :
        	print "\nNo More Sniffing!"

	#assign to a dictionary all the list of different protocols
	dict_Packets = create_Dict(packet_List, TCP_List, UDP_List, ICMP_List, IGMP_List, Other_List, ARP_List)    
	#loop that will print the captured data and give the user flexibility in accessing the data
    	while True:
        	#get an option from the user and display the menu
       		choice = show_Menu()
       		#if and else calls that function as a switch:case for the multiple options
       		#print all the packets captured in order
       		if(choice == '0'):
         		All = dict_Packets['ALL']
			#options is the options selected by the user
			options = attributeOptions(choice)
			#all options are selected under this choice
			userInput = ['1','2','3','4','5','6','7','8']
           		for i in range(0, len(All)):
				eth_length, eth_protocol = print_Etho(All[i])
                   		iphl, protocol = print_IP_Linux(All[i], eth_length)
				if(str(eth_protocol) == '0x806'):
					print "This is an ARP query"
				elif(str(eth_protocol) == '0x86d'):
					print "This is IPv6"
                    		elif(protocol == 6):
                        		print_TCP(All[i], iphl+eth_length, userInput)
                    		elif(protocol == 17):
                       			print_UDP(All[i], iphl+eth_length, userInput)
                   		elif(protocol == 1):
                        		print_ICMP(All[i], iphl+eth_length,userInput)
                    		elif(protocol == 2):
                       			print_IGMP(All[i], iphl+eth_length, userInput)
                    		else:
                       			print "\nUnparsed procotol found!\n"
        	#print only the TCP packets
        	elif(choice == '1'):
			tcp = dict_Packets['TCP']
			if(len(tcp) == 0):
				print "\nNo TCP protocols sniffed!"
			else:
				options = attributeOptions(choice)
				userInput = stringToArr(options)
            			for i in range(0, len(tcp)):
					print "===============ETHERNET=================="
					eth_length, eth_protocol = print_Etho(tcp[i])
					print "==================IP====================="
                    			iphl, protocol = print_IP_Linux(tcp[i], eth_length)
                    			print_TCP(tcp[i], iphl+eth_length, userInput)
		#print only the UDP packets
		elif(choice == '2'):
		    udp = dict_Packets['UDP']
		    if(len(udp) == 0):
			print "\nNo UDP protocols sniffed!"
		    else:
		    	options = attributeOptions(choice)
		    	userInput = stringToArr(options)
		    	for i in range(0, len(udp)):
				print "===============ETHERNET=================="
				eth_length, eth_protocol = print_Etho(udp[i])
				print "==================IP====================="
				iphl, protocol = print_IP_Linux(udp[i], eth_length)
				print_UDP(udp[i], iphl+eth_length, userInput)
		#print only the ICMP packets    
		elif(choice == '3'):
		     icmp = dict_Packets['ICMP']
		     if(len(icmp) == 0):
			print "\nNo ICMP protocols sniffed!"
		     else:
			options = attributeOptions(choice)
		  	userInput = stringToArr(options)
		        for i in range(0, len(icmp)):
				print "===============ETHERNET=================="
				eth_length, eth_protocol = print_Etho(icmp[i])
				print "==================IP====================="
				iphl, protocol = print_IP_Linux(icmp[i], eth_length)
				print_ICMP(icmp[i], iphl+eth_length, userInput)
		#print only the IGMP packets
		elif(choice == '4'):
		    igmp = dict_Packets['IGMP']
		    if(len(igmp) == 0):
			print "\nNo IGMP protocols sniffed!"
		    else:
		    	options = attributeOptions(choice)
		    	userInput = stringToArr(options)
		    	for i in range(0, len(igmp)):
				print "===============ETHERNET=================="
				eth_length, eth_protocol = print_Etho(igmp[i])
				print "==================IP====================="
				iphl, protocol = print_IP_Linux(igmp[i], eth_length)
				print_IGMP(igmp[i], iphl+eth_length, userInput)
		#print all other protocols found
		elif(choice == '5'):
		    other = dict_Packets['OTHER']
		    if(len(other) == 0):
			print "\nNo Other protocols sniffed!"
		    else:
		    	for i in range(0, len(other)):
				print "===============ETHERNET=================="
				eth_length, eth_protocol = print_Etho(other[i])
				print "==================IP====================="
				iphl, protocol = print_IP_Linux(other[i],eth_length)
				print "\nUnparsed protocol found\n!"
		#print all ARP protocols found
		elif(choice == '6'):
		    arp = dict_Packets['ARP']
		    if(len(arp) == 0):
			print "\nNo ARP protocols sniffed!"
		    else:
			options = attributeOptions(choice)		    	
			userInput = stringToArr(options)
		    	for i in range(0, len(arp)):
				print "===============ETHERNET=================="
				eth_length, eth_protocol = print_Etho(arp[i])
				print_ARP(arp[i], eth_length, userInput)
		#exit this part of the program
		elif(choice == '7'):
		    break
		else:
		    print "Invalid option!\n"
		
	#print out the maxsize and the average of the data session    
	max_total(os, dict_Packets['ALL'])
	#s.close()    
	
	"""
	Congestion window will be displayed by code below, it will iterate through all TCP packets to determine window sizes
	"""
	#create a tcp connection to be used to determine the local IP address to be used in finding congestion windows
	temp_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	temp_s.connect(('8.8.8.8', 0))  # connecting to a UDP address doesn't send packets
	local_ip_address = temp_s.getsockname()[0]
	temp_s.close()
	
	"""
	Make the call to diameter to get the diameter of the network using TCP packets
	"""
	print "================DIAMETER================"
	complement, aveComp = diameter(os, dict_Packets['TCP'], local_ip_address)
	print "The Diameter of the Network is: {}\nThe Average Diameter of the Network is: {}\n".format(complement, aveComp)
	
	#ask the user to input whether they want to see the Congestion 
	answer = raw_input("Would you like to see the Congestion Windows? Y | N\n")
	answer = answer.lower()
	#loop only exits accourding to the user input, only 'n' or 'N' will exit
	while True:
		if(answer == 'y'):
			#lists that will be appended to and num is simply to keep track of which packet we have(1,2,3..N)
			list_windows = []
			num_packet = []
			num = 0
			#extrack the tcp list from the dictionary
			tcp = dict_Packets['TCP']
			#search through all tcp packets to find any outgoing, meaning that source IP is this very machine
			for i in range(0, len(tcp)):
				num = congestion_chart(tcp[i], local_ip_address, num, list_windows, num_packet)
			#lines to call the graph to be displayed in a GUI using the Tk packet. After graph the while loop is broken out of
			fig = plt.figure()
			fig.suptitle('Congestion Window', fontsize=12, fontweight='bold')
			ax = fig.add_subplot(111)
			ax.set_xlabel('Packet Number')
			ax.set_ylabel('Window Size')		
			ax.plot(num_packet, list_windows)
			plt.show()
			break
		elif(answer == 'n'):
			break
		else:
			answer = raw_input("Invalid input, try again: Y | N\n")
			answer = answer.lower()
	#ask the user to input whether they want to see the throughput 
	answer = raw_input("Would you like to see the Throughput? Y | N\n")
	answer = answer.lower()
	while True:
		if(answer == 'y'):
			throughput()
		elif(answer == 'n'):
			break
		#if the user gives invalid code, ask again
		else:
			answer = raw_input("Invalid input, try again: Y | N\n")
			answer = answer.lower()
	
	#close the raw socket before ending the program
	s.close()
	sys.exit()

"""
Simple function that returns an array of strings delimited by a space
"""
def stringToArr(string):
	return string.split( )

"""
This function displays the options available when selecting which attributes the user may want to see
It takes in the choice made earlier at the protocol menu
"""
def attributeOptions(protocolChosen):
	print "Which attributes would you like to see?\n"
	#pre-filled lists with all the available options
	optionsTCP = ['Source Port', 'Destination Port', 'Acknowledgement #', 'Sequence #', 'TCP Length', 'Window Size', 'Checksum', 'Flags']
	optionsUDP = ['Source Port','Destination Port','Length','Checksum']
	optionsICMP = ['Type', 'Code', 'Identifier', 'Sequence','Checksum']
	optionsIGMP = ['Type', 'MaxTime', 'Checksum']
	optionsARP = ['Hardware Type', 'Protocol Type', 'Hardware Size', 'Protocol Size', 'Operation', 'MAC Source', 'IP Source', 'MAC Destination', 'IP Destination']
	#switch-case set up for the selection of which menu to display
	# 0 - All protocols and all attributes chosen
	if(protocolChosen == '0'):
		print "All will be printed"
		return '0'
	# 1 - Only TCP attributes displayed
	elif(protocolChosen == '1'):
		for i in range(0, 8):
			print "{}: {}".format(i+1,optionsTCP[i])
	# 2 - Only UDP attribures displayed
	elif(protocolChosen == '2'):
		for i in range(0, 4):
			print "{}: {}".format(i+1,optionsUDP[i])
	# 3 - Only ICMP attribures displayed
	elif(protocolChosen == '3'):
		for i in range(0, 5):
			print "{}: {}".format(i+1,optionsICMP[i])
	# 4 - Only IGMP attributes displayed
	elif(protocolChosen == '4'):
		for i in range(0, 3):
			print "{}: {}".format(i+1,optionsIGMP[i])
	# 6 - Only ARP attributes displayed
	elif(protocolChosen == '6'):
		for i in range(0, 9):
			print "{}: {}".format(i+1,optionsARP[i])
	# 5 - all other protocols that were not handled
	else:
		print "Protocols not Parsed"
		return '5'
	
	userChoice = raw_input("Enter Choices: ")
	return userChoice

"""
This function creates a client TCP server that will be connected to a separate Server on a
different machine and it will send data of 500 different sizes a set number of times and have 
throughput calculated and graphed for the user
"""
def throughput():
	#variables used
	throughArr = []
	timeArr  = []
	totalTime = 0
	totalThroughput = 0
	
	#create the port number 12000 and the serverName set to 'localhost'
	serverPort = 12000
	serverName = '192.168.1.80'
	#create a TCP socket of connection
	clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	clientSocket.connect((serverName, serverPort))
	#initial size of the file
	size = 20
	flag = True
	#loop 500 times with a different file size every time
	for i in range(0, 500):
		data = 'x' * size
		for k in range(0, 100):
			t1 = time.time()
			clientSocket.send(data)
			response = clientSocket.recv(65565)
			t2 = time.time()
			if(flag):
				timeArr.append(t2)
				flag = False
			#totalThroughput is the cumulative throughput of each iteration
			totalThroughput += size/float(t2-t1)
			#totalTime is the cumulative time from time of sending to time of receiving acknowledgement
			totalTime += t2-t1
		#get the average of the throughput and times
		throughArr.append(totalThroughput/100)
		#####timeArr.append(totalTime/100)
		size += 20
		flag = True
	#creates the graph for throughput, adding labels
	fig = plt.figure()
	fig.suptitle('Throughput', fontsize=12, fontweight='bold')
	ax = fig.add_subplot(111)
	ax.set_xlabel('Time')
	ax.set_ylabel('Throughput')
	ax.plot(timeArr, throughArr)
	plt.show()
	clientSocket.close()

	



"""
Scope the diameter of the Network by checking the TTL of a received packet to 64
given that TCP packets have a default TTL of 64 hops
"""
def diameter(os, packet_list, addr):
	if(os == "Linux"):
		start = 14
		stop = start+20	
	elif(os == "Windows"):
		start = 0
		stop = start+20
	total_TTL = 0
	numPacks = 0
	minimumDiam = 1000
	maxDiam = -1
	for i in range(0, len(packet_list)):
		data = packet_list[i]
		ipDatagram = data[start:stop]
		ipHeader = unpack("!BBHHHBBH4s4s",ipDatagram)
		ttl = ipHeader[5]
		source = socket.inet_ntoa(ipHeader[8])
		if(source != addr):
			numPacks += 1
			#cisco
			if(ttl>128):
				diameter = (255-ttl)
				total_TTL += diameter
			#windows
			elif(ttl>64):
				diameter = (128-ttl)
				total_TTL += diameter
			#linux
			else:
				diameter = (64-ttl)
				total_TTL += diameter
			if(minimumDiam > diameter):
				minimumDiam = diameter
			if(maxDiam < diameter):
				maxDiam = diameter
	averageTTL = 0
	if(numPacks > 0):
		averageTTL = (float(total_TTL)/numPacks)
	return maxDiam, averageTTL

"""
Function that will be take the TCP packets and sift through to find any outgoing and append the congestion/receive window
to a list that is passed in as a parameter and the value returned is the number as it is incremented by one
packet = actual packet passed
addr = the IP address of the machine running the code
num = which packet is being appended, it is increasing order(1,2,3,... N)
list_windows = is the list that will contain all the window values
num_packet = the list that holds all the numbers form 1 up to N
"""
def congestion_chart(packet, addr, num, list_windows, num_packet):
	
	eth_length = 14
	ip_length = eth_length+20
	#unpack the IP header data
	ipHeader = packet[eth_length:ip_length]
	ipDatagram = unpack("!BBHHHBBH4s4s",ipHeader)
	source = socket.inet_ntoa(ipDatagram[8])
	#only need to compare the source IP address to the address of this machine 
	if(source == addr):
		num += 1
		tcp_stuff = packet[ip_length:ip_length+20]
		tcp_header = unpack("!HHLLBBHHH",tcp_stuff)
		list_windows.append(tcp_header[6])
		num_packet.append(num)
	return num


"""
Function that will take in a packet as the parameter and then extract the ethernet information and unpack it to
display it to the user. It returns the ethernet length of 14 and the protocol in hexadecimal format
"""
def print_Etho(packet):
	eth_length = 14
	eth_header = packet[:eth_length]
	eth = unpack('!6s6sH', eth_header)
	#eth_protocol = socket.ntohs(eth[2])
	eth_protocol = eth[2]

	print 'Destination MAC: ' + eth_addr(packet[:6]) + ' Source MAC: ' + eth_addr(packet[6:12]) + ' Protocol: ' + hex(eth_protocol) + '\n'

	return eth_length, hex(eth_protocol)

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
	return b


"""
This Function will only print a small preview of the Ip header from the captured packets
so that the user can see live what is being captured. It will be stored and later be able to
navigate through the data dynamically depending on user choices
"""
def IP_preview_Linux(packet, eth_length):
            
            ipHeader = packet[eth_length:eth_length+20]
            #unpack the data found in the ip datagram, there are 10 items
            ipDatagram = unpack("!BBHHHBBH4s4s",ipHeader)
            version_IPHeaderLength = ipDatagram[0]
            ipVer = version_IPHeaderLength >> 4
            #0xF is 15 and the '&' operand copies a bit to the result if it exists
            #in both operands            
            ipHeaderLength = version_IPHeaderLength & 0xF
            #
            iphl = ipHeaderLength * 4
            totalLength = ipDatagram[2]            
            #transport protocol
            protocol = ipDatagram[6]
            sourceIP = socket.inet_ntoa(ipDatagram[8])
            destinationIP = socket.inet_ntoa(ipDatagram[9])
            
            print "Version: \t\t" + str(ipVer)
            print "Length:\t\t\t" + str(totalLength)
            print "Protocol:\t\t" + getProtocol(protocol)
            #print "SourceIP:\t\t" + sourceIP
            #print "DestinationIP:\t\t" + destinationIP
            
            #this will be used to find the max and average size of the packets captured
            return totalLength
            
def print_ARP(packet, eth_length, userInput):
	optionsARP = ['Hardware Type', 'Protocol Type', 'Hardware Size', 'Protocol Size', 'Operation', 'MAC Source', 'IP Source', 'MAC Destination', 'IP Destination']
	ARP_data = packet[eth_length:eth_length+28]
	#unpack the data from the ARP query
	ARP_stuff = unpack("!HHBBH6s4s6s4s", ARP_data)
	hard_type = ARP_stuff[0]
	proto_type = ARP_stuff[1]
	hard_size = ARP_stuff[2]
	proto_size = ARP_stuff[3]
	operation = ARP_stuff[4]
	Mac_source = ARP_stuff[5]
	Ip_source = socket.inet_ntoa(ARP_stuff[6])
	Mac_Destination = ARP_stuff[7]
	Ip_Destination = socket.inet_ntoa(ARP_stuff[8])

	data = [hard_type, proto_type, hard_size, proto_size, operation, Mac_source, Ip_source, Mac_Destination, Ip_Destination]
	print '\n'
	for i in range(0, len(optionsARP)):
		if(str(i+1) in userInput):
			print "{}: {}".format(optionsARP[i], data[i])

	#print "Hardware Type: {}, Protocol Type: {}, Hardware Size: {}, Protocol Size: {} bytes, Operation: {}".format(hard_type, hex(proto_type), hard_size, proto_size, operation)
	#print "Mac Source address: {}, Mac Destination address: {}, IP Source address: {}, IP Destination address: {}".format(eth_addr(Mac_source), eth_addr(Mac_Destination), socket.inet_ntoa(Ip_source), socket.inet_ntoa(Ip_Destination))

"""
This function will print the IP header information, it does the unpacking and deciphering of the data
It only reads the first 20 bytes which include the header
"""
def print_IP_Linux(packet, eth_length):
    ipHeader = packet[eth_length:eth_length+20]
    #unpack the data found in the ip datagram, there are 10 items
    ipDatagram = unpack("!BBHHHBBH4s4s",ipHeader)
    version_IPHeaderLength = ipDatagram[0]
    ipVer = version_IPHeaderLength >> 4
    #0xF is 15 and the '&' operand copies a bit to the result if it exists
    #in both operands            
    ipHeaderLength = version_IPHeaderLength & 0xF
    #
    iphl = ipHeaderLength * 4
    TOS = ipDatagram[1]            
    totalLength = ipDatagram[2]
    ID = ipDatagram[3]
    flags = ipDatagram[4]
    fragments = ipDatagram[4] & 0x1FFF
    #time to live
    ttl = ipDatagram[5]
    #transport protocol
    protocol = ipDatagram[6]
    checksum = ipDatagram[7]
    #source and destination ip addresses
    sourceIP = socket.inet_ntoa(ipDatagram[8])
    destinationIP = socket.inet_ntoa(ipDatagram[9])
   
    print "Version: \t\t" + str(ipVer)
    print "Header Length: \t\t" + str(iphl) + " bytes"
    print "Type of Service: \t" + TypeOfService(TOS)
    print "Length:\t\t\t" + str(totalLength)
    print "ID:\t\t\t" + str(hex(ID)) + '(' +str(ID) + ')'
    print "Flags:\t\t\t" + getFlags(flags)
    print "Fragment Offset:\t" + str(fragments)
    print "TTL:\t\t\t" + str(ttl)
    print "Protocol:\t\t" + getProtocol(protocol)
    print "Checksum:\t\t" + str(checksum)
    print "SourceIP:\t\t" + sourceIP
    print "DestinationIP:\t\t" + destinationIP
    
    #will be used to find where the Transport information begins in methods calling print_IP()
    return iphl, protocol

"""
This function is the one that stores the packets being sniffed. As they are sniffed the IP header
is unpacked and the protocol checked so that it can be filtered and be placed into the
appropriate list which will later be added to a dictionary for easy navigation    
""" 
def store_data_Linux(packet, ALL, TCP, UDP, ICMP, IGMP, Other, ARP, IPv6):
     """
     Will be using a list to store all similar protocols(TCP,UDP,ICMP)
     Each list will be stored in a dictionary where the key is the protocol
     For time being will only use top four seen protocols and a default used for all others
     The data will be stored within a list structure will look as below
     Dict = {'protocol':[[packet data], [packet data], [packet data]]...]}
     """
     eth_length = 14
     ethData = packet[:eth_length]
     eth = unpack("!6s6sH",ethData)
     eth_protocol = hex(eth[2])
     IpData = packet[eth_length:eth_length+20]
     ipDatagram = unpack("!BBHHHBBH4s4s", IpData)
     ALL.append(packet)
     protocol = ipDatagram[6]
     if(str(eth_protocol) == "0x806"):
         ARP.append(packet)
     elif(str(eth_protocol) == '0x86d'):
         IPv6.append(packet)
     elif(protocol == 6):
         TCP.append(packet)
     elif(protocol == 17):
        UDP.append(packet)
     elif(protocol == 1):
         ICMP.append(packet)
     elif(protocol == 2):
         IGMP.append(packet)
     else:
         Other.append(packet)

"""
LINUX
##################################################################################################################################################
WINDOWS
"""





"""
Sniff_Packets is a funtion that will create a socket and then run the necessary while loops for the 
rest of the program to run effectively, It is the main method calling helper methods. Everything will
run from this single parent function
"""
def sniff_packets(os):
    #create all the list that will contain the packets, segragated by protocols
    packet_List = []
    TCP_List = []
    UDP_List = []
    ICMP_List = []
    IGMP_List = []
    Other_List = []
    #grab the name of the host by making this call:getHostbyname()
    HOST = socket.gethostbyname(socket.gethostname())
    #creation of the socket to be used throughout the program
    try :        
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        print 'Successfully Created Raw Socket!\n'
        #bind the host ot an open port
        s.bind((HOST, 0))
     
        #Include IP headers
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        #receive all packages
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        print "\nPacket previews will be displayed, after sniffing begins, press CTRL-C when ready to stop sniffing.\n"
        raw_input('Press Enter to continue')
        #loop that will print a small preview of the IP header for the user to see and capture the packets        
        while True:
            #receive the data packets of up to size 65565
            packet = s.recvfrom(65565)
            #take the packet data from the tuple provided from call recvfrom which contains (packet, sourde Address)
            packet = packet[0]
            #allows the user to preview the Ip header info and help in choosing when to stop
            IP_preview(packet)
            #store every packet being sniffed in the appropriate list which will be later placed in a dictionary
            store_data(packet, packet_List, TCP_List, UDP_List, ICMP_List, IGMP_List, Other_List)
    #exception to deal with issues in creation of the socket
    except socket.error, msg:
        print 'Socket could not be created. Error code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()
    #exception to catch the command CTRL-C and continue with the program
    except KeyboardInterrupt :
        print "\nNo More Sniffing!"

    #print "Number of packets {}, Number of TCP {}".format(len(packet_List), len(TCP_List))
    
    #assign to a dictionary all the list of different protocols
    dict_Packets = create_Dict(packet_List, TCP_List, UDP_List, ICMP_List, IGMP_List, Other_List)    
    #initialize a counter to keep track of how many packets to print at a time and assign a limit    
    keepCount = 0
    limit = 10
    #loop that will print the captured data and give the user flexibility in accessing the data
    while True:
        #get an option from the user and display the menu
        choice = show_Menu()
        #if and else calls that function as a switch:case for the multiple options
        #print all the packets captured in order
        if(choice == '0'):
            All = dict_Packets['ALL']
            for i in range(0, len(All)):
                if(keepCount <= limit):
                    iphl, protocol = print_IP(All[i])
                    if(protocol == 6):
                        print_TCP(All[i], iphl)
                    elif(protocol == 17):
                        print_UDP(All[i], iphl)
                    elif(protocol == 1):
                        print_ICMP(All[i], iphl)
                    elif(protocol == 2):
                        print_IGMP(All[i], iphl)
                    else:
                        print "\nUnparsed procotol found!\n"
                else:
                    raw_input("Press Enter to see next "+ str(limit) +" entries.")
                    keepCount = 0
                keepCount += 1
        #print only the TCP packets
        elif(choice == '1'):
            tcp = dict_Packets['TCP']
            for i in range(0, len(tcp)):
                if(keepCount <= limit):                
                    iphl, protocol = print_IP(tcp[i])
                    print_TCP(tcp[i], iphl)
                else:
                    raw_input("Press Enter to see next "+ str(limit) +" entries.")
                    keepCount = 0
                keepCount += 1
        #print only the UDP packets
        elif(choice == '2'):
            udp = dict_Packets['UDP']
            for i in range(0, len(udp)):
                if(keepCount <= limit):
                    iphl, protocol = print_IP(udp[i])
                    print_UDP(udp[i], iphl)
                else:
                    raw_input("Press Enter to see next "+ str(limit) +" entries.")
                    keepCount = 0
                keepCount += 1
        #print only the ICMP packets    
        elif(choice == '3'):
            icmp = dict_Packets['ICMP']
            for i in range(0, len(icmp)):
                if(keepCount <= limit):
                    iphl, protocol = print_IP(icmp[i])
                    print_ICMP(icmp[i], iphl)
                else:
                    raw_input("Press Enter to see next "+ str(limit) +" entries.")
                    keepCount = 0
                keepCount += 1
        #print only the IGMP packets
        elif(choice == '4'):
            igmp = dict_Packets['IGMP']
            for i in range(0, len(igmp)):
                if(keepCount <= limit):
                    iphl, protocol = print_IP(igmp[i])
                    print_IGMP(igmp[i], iphl)
                else:
                    raw_input("Press Enter to see next "+ str(limit) +" entries.")
                    keepCount = 0
                keepCount += 1
        #print all other protocols found
        elif(choice == '5'):
            other = dict_Packets['OTHER']
            for i in range(0, len(other)):
                if(keepCount <= limit):
                    iphl, protocol = print_IP(other[i])
                    print "\nUnparsed protocol found\n!"
                else:
                    raw_input("Press Enter to see next "+ str(limit) +" entries.")
                    keepCount = 0
                keepCount += 1
        elif(choice == '6'):
            break
        else:
            print "Invalid option!\n"
        

    #server/client code will go here and determine throughput    
    print "Successfully implemented the First Part!"
    #print out the maxsize and the average of the data session    
    max_total(os, packet_List)
    
    # disable promiscuous mode
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    s.close()    

"""
This function will print the IP header information, it does the unpacking and deciphering of the data
It only reads the first 20 bytes which include the header
"""
def print_IP(packet):
    ipHeader = packet[0:20]
    #unpack the data found in the ip datagram, there are 10 items
    ipDatagram = unpack("!BBHHHBBH4s4s",ipHeader)
    version_IPHeaderLength = ipDatagram[0]
    ipVer = version_IPHeaderLength >> 4
    #0xF is 15 and the '&' operand copies a bit to the result if it exists
    #in both operands            
    ipHeaderLength = version_IPHeaderLength & 0xF
    #
    iphl = ipHeaderLength * 4
    TOS = ipDatagram[1]            
    totalLength = ipDatagram[2]
    ID = ipDatagram[3]
    flags = ipDatagram[4]
    fragments = ipDatagram[4] & 0x1FFF
    #time to live
    ttl = ipDatagram[5]
    #transport protocol
    protocol = ipDatagram[6]
    checksum = ipDatagram[7]
    #source and destination ip addresses
    sourceIP = socket.inet_ntoa(ipDatagram[8])
    destinationIP = socket.inet_ntoa(ipDatagram[9])
    
    print "\n\nVersion: \t\t" + str(ipVer)
    print "Header Length: \t\t" + str(iphl) + " bytes"
    #print "Type of Service: \t" + TypeOfService(TOS)
    print "Length:\t\t\t" + str(totalLength)
    #print "ID:\t\t\t" + str(hex(ID)) + '(' +str(ID) + ')'
    print "Flags:\t\t\t" + getFlags(flags)
    #print "Fragment Offset:\t" + str(fragments)
    #print "TTL:\t\t\t" + str(ttl)
    print "Protocol:\t\t" + getProtocol(protocol)
    #print "Checksum:\t\t" + str(checksum)
    print "SourceIP:\t\t" + sourceIP
    print "DestinationIP:\t\t" + destinationIP
    
    #will be used to find where the Transport information begins in methods calling print_IP()
    return iphl, protocol
"""
This function prints the TCP data, it unpacks and deciphers the header data
"""
def print_TCP(packet, iphl, userInput):
    optionsTCP = ['Source Port', 'Destination Port', 'Acknowledgement #', 'Sequence #', 'TCP Length', 'Window Size', 'Checksum']
	
    tcp_header = packet[iphl:iphl+20]
    #unpack the tcp header information                
    tcph = unpack('!HHLLBBHHH', tcp_header)
    source_port = tcph[0]
    destination_port = tcph[1]
    sequence = tcph[2]
    acknowledgment = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    
    #extract all the flags from the tcp header
    #getTCPFlags(tcph[4], tcph[5])     
    #the congestion window
    conge_win = tcph[6]
    checksum = tcph[7]

    data = [source_port, destination_port, acknowledgment, sequence, tcph_length*4, conge_win, checksum]
    print '\n===================TCP===================='
    for i in range(0, 7):
	if(str(i+1) in userInput):
		print "{}: {}".format(optionsTCP[i], data[i])
    if('8' in userInput):
	print "Flags: "
	getTCPFlags(tcph[4], tcph[5])
    print "\n\n"
    #print 'Source Port {}, Destination Port {}, sequence {}'.format(source_port, destination_port, sequence)
    #print 'Acknowledgement {}, TCP Length {}, Congestion Window: {}'.format(acknowledgment, tcph_length*4, conge_win)
    
    header_size = iphl + tcph_length * 4
    data_size = len(packet) - header_size
    data = packet[header_size:]  

"""
This function prints the UDP data, it unpackes and deciphers the UDP header data
"""
def print_UDP(packet, iphl, userInput):
    optionsUDP = ['Source Port','Destination Port','Length','Checksum']

    udpl = 8
    udp_header = packet[iphl:iphl+udpl]
    #unpack the udp header which is much smaller than TCP
    udph = unpack('!HHHH', udp_header)
    #take the wanted information and assing it to variables
    source_port = udph[0]
    destination_port = udph[1]
    length = udph[2]
    checksum = udph[3]

    data = [source_port, destination_port, length, checksum]
    print '\n==================UDP===================='
    for i in range(0, len(optionsUDP)):
	if(str(i+1) in userInput):
		print "{}: {}".format(optionsUDP[i], data[i])
    print "\n\n"
    #print 'Source Port: {}, Destination Port: {}'.format(source_port, destination_port)
    #print 'length: {}, checksum: {}'.format(length, checksum)                
    #not used curretnly but may be useful for some future tasks, contains the data and header_size
    header_size = iphl + udpl
    data = packet[header_size:]

"""
This function prints the ICMP data, it unpacks and deciphers the ICMP header data
"""
def print_ICMP(packet, iphl, userInput):
    optionsICMP = ['Type', 'Code', 'Identifier', 'Sequence','Checksum']

    icmpl = 8
    icmp_header = packet[iphl:iphl+icmpl]
    #unpack the ICMP header which is only 4bytes
    icmp = unpack('!BBHHH',icmp_header)
    icmp_type = icmp[0]
    icmp_code = icmp[1]
    icmp_identifier = icmp[3]
    icmp_sequence = icmp[4]
    icmp_checksum = icmp[2]
    
    data = [icmp_type, icmp_code, icmp_identifier, icmp_sequence, icmp_chescksum]
    print '\n==================ICMP==================='
    for i in range(0, len(optionsICMP)):
	if(str(i+1) in userInput):
		print "{}: {}".format(optionsICMP[i], data[i])
    print "\n\n"
    #print "Type: {}, Code: {}, Checksum: {}".format(icmp_type, icmp_code, icmp_checksum)
    #print "Identifier: {}, Sequence: {}".format(icmp_identifier, icmp_sequence)
"""
This function prints the IGMP data, it unpacks and deciphers the IGMP header data
"""
def print_IGMP(packet, iphl, userInput):
    optionsIGMP = ['Type', 'MaxTime', 'Checksum']

    igmpl = 8
    igmpl_header = packet[iphl:iphl+igmpl]
    #unpack the IGMP header information
    igmp = unpack('!BBHHH',igmpl_header)
    igmp_type = igmp[0]
    igmp_MaxTime = igmp[1]
    igmp_checksum = igmp[2]

    data = [igmp_type, igmp_MaxTime, igmp_checksum]
    print '\n==================IGMP==================='
    for i in range(0, len(optionsIGMP)):
	if(str(i+1) in userInput):
		print "{}: {}".format(optionsIGMP[i], data[i])
    print "\n\n"
    #print "Type: {}, Max Response Time: {}".format(igmp_type, igmp_MaxTime)

"""
Function that displays the menu for the user, offering multiple options when viewing
the captured and stored data packets
"""
def show_Menu():
    numbers = [0,1,2,3,4,5,6,7]
    options = ['ALL','TCP','UDP','ICMP','IGMP','OTHER','ARP','EXIT']
    print "\n\nSelect one of the following\n"
    for i in range(0, len(numbers)):
        if(i == len(numbers)-1):
            print "{}:{}".format(numbers[i], options[i])
        else:
            print "{}:Display {}".format(numbers[i], options[i])
    return raw_input("What would you like to do next?\n")

"""
This function just creates the dictionary to store the different protocols we
want to segregate
"""
def create_Dict(ALL, TCP, UDP, ICMP, IGMP, Other, ARP):
    #initialize an empty dictionary and fill it with the options/lists we want    
    dict_Packets = {}
    dict_Packets["ALL"] = ALL
    dict_Packets["TCP"] = TCP
    dict_Packets["UDP"] = UDP
    dict_Packets["ICMP"] = ICMP
    dict_Packets["IGMP"] = IGMP
    dict_Packets["OTHER"] = Other
    dict_Packets["ARP"] = ARP
    
    return dict_Packets

"""
This Function will only print a small preview of the Ip header from the captured packets
so that the user can see live what is being captured. It will be stored and later be able to
navigate through the data dynamically depending on user choices
"""
def IP_preview(packet):
            
            ipHeader = packet[0:20]
            #unpack the data found in the ip datagram, there are 10 items
            ipDatagram = unpack("!BBHHHBBH4s4s",ipHeader)
            version_IPHeaderLength = ipDatagram[0]
            ipVer = version_IPHeaderLength >> 4
            #0xF is 15 and the '&' operand copies a bit to the result if it exists
            #in both operands            
            ipHeaderLength = version_IPHeaderLength & 0xF
            #
            iphl = ipHeaderLength * 4
            totalLength = ipDatagram[2]            
            #transport protocol
            protocol = ipDatagram[6]
            sourceIP = socket.inet_ntoa(ipDatagram[8])
            destinationIP = socket.inet_ntoa(ipDatagram[9])
            
            print "\n\nVersion: \t\t" + str(ipVer)
            print "Length:\t\t\t" + str(totalLength)
            print "Protocol:\t\t" + getProtocol(protocol)
            #print "SourceIP:\t\t" + sourceIP
            #print "DestinationIP:\t\t" + destinationIP
            
            #this will be used to find the max and average size of the packets captured
            return totalLength
            
"""
Funtion that will add all the total lenghts and keep track of the largest packet size
This will return the largest packet and the total cumulative length of all the packets
"""         
def max_total(os, packetList):
    #check which operating system is being used to know which lenght to use
    os = platform.system()
    if(os == "Linux"):
	start = 14
	headerLength = 14+20
    elif(os == "Windows"):
	start = 0
	headerLength = 20

    totalTTL = 0
    totalsize = 0    
    maxsize = -1
    maxTTL = -1
    numPackets = 0
    for i in range(0, len(packetList)):
	if(os == 'Linux'):
		ethoFrame = packetList[i]
		ethoData = ethoFrame[:start]
		ethoHeader = unpack('!6s6sH', ethoData)
		ethoType = hex(ethoHeader[2])
		if(ethoType == '0x800'):
			numPackets += 1
			maxsize, maxTTL, totalTTL, totalsize = maxAveHelper(packetList[i], start, headerLength, maxsize, maxTTL, totalTTL, totalsize)		
	elif(os == 'Windows'):
            numPackets += 1
            maxsize, maxTTL, totalTTL, totalsize = maxAveHelper(packetList[i], start, headerLength, maxsize, maxTTL, totalTTL, totalsize)
	else:
	    print "Unrecognized Operating System!\n"
	    sys.exit()
    if(numPackets > 0):
	    averageSize = float(totalsize)/numPackets
	    averageTTL = float(totalTTL)/numPackets
	    print "\nThe Maximum sized packet is: {}".format(maxsize)
	    print "The Average packet size for this session is: {}".format(averageSize)
	    #print "The Maximum Time To Live is: {}".format(maxTTL)    
	    #print "The Average Time To Live is: {}".format(averageTTL)
    else:
	    print "No IPv4 Packets read!"
"""
Function that will help reduce redundacy in max_total function, takes in:
packet - is the packet to be unpacked
start - is the start of the IP header
headerLength - is the length is that, header length
maxsize and maxTTL - are the values being aggregated to
"""
def maxAveHelper(packet, start, headerLength, maxsize, maxTTL, totalTTL, totalsize):
	ipdata = packet[start:headerLength]        
	ipheader = unpack("!BBHHHBBH4s4s",ipdata)
	length = ipheader[2]
	ttl = ipheader[5]
	totalTTL += ttl
	totalsize += length
	if(maxsize<length):
	    maxsize = length
	if(maxTTL < ttl):
	    maxTTL = ttl

	return maxsize, maxTTL, totalTTL, totalsize
 
"""
This function is the one that stores the packets being sniffed. As they are sniffed the IP header
is unpacked and the protocol checked so that it can be filtered and be placed into the
appropriate list which will later be added to a dictionary for easy navigation    
""" 
def store_data(packet, ALL, TCP, UDP, ICMP, IGMP, Other):
     """
     Will be using a list to store all similar protocols(TCP,UDP,ICMP)
     Each list will be stored in a dictionary where the key is the protocol
     For time being will only use top four seen protocols and a default used for all others
     The data will be stored within a list structure will look as below
     Dict = {'protocol':[[packet data], [packet data], [packet data]]...]}
     """
     IpData = packet[:20]
     ipDatagram = unpack("!BBHHHBBH4s4s", IpData)
     ALL.append(packet)
     protocol = ipDatagram[6]
     if(protocol == 6):
         TCP.append(packet)
     elif(protocol == 17):
        UDP.append(packet)
     elif(protocol == 1):
         ICMP.append(packet)
     elif(protocol == 2):
         IGMP.append(packet)
     else:
         Other.append(packet)
    
    
#get time of service - 8bits    
def TypeOfService(data):
    #set up the dictionaries that will contain the possible options
    precedence = {0:"Routine", 1:"Priority", 2:"Immediate", 3:"Flash", 4:"Flash Override", 5:"CRITIC/ECP", 6:"Internetwork Contril", 7:"Network Control"}
    delay = {0:"Normal delay", 1:"Low delay"}
    throughput = {0:"Normal Throughput", 1:"High Throughput"}
    reliability = {0:"Normal reliability", 1:"High reliability"}
    cost = {0:"Normal monetary cost", 1:"Minimize monetary cost"}
    
    #D->delay, T->throughput, R->reliability, M->monetary cost
    #the shift done by '>>=' is a bit operator that takes two binary strings and copies any that match
    #while the rest are all set to 0s.
    #0x10 -> 16, 0x8 -> 8, 0x4 ->4, 0x2 -> 2
    D = data & 0x10
    D >>= 4
    T = data & 0x8
    T >>= 3
    R = data & 0x4
    R >>= 2
    M = data & 0x2
    M >>= 1
    #string to format the output with a new line and three tabs
    tabs = '\n\t\t\t'
    TimeOfService = precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + reliability[R] + tabs + cost[M]
    return TimeOfService

#returns the flag options for the IP header in a string format for easy printing    
def getFlags(data):
    #dictionaries with available options initialized
    flagR = {0:"0-Reserved Bit"}
    flagDF = {0:"0-Fragment if Necessary", 1:"1-Do Not Fragment"}
    flagMF = {0:"0-Last Fragment", 1:"1-More Fragments"}
    
    #bit wise operator used to shift decimals
    #0x8000 is 10000000 00000000
    #0x4000 is 01000000 00000000
    #0x2000 is 00100000 00000000
    R = data & 0x8000
    R >>= 15
    DF = data & 0x4000
    DF >>= 14
    MF = data & 0x2000
    MF >>= 13
    #string to format the output
    tabs = '\n\t\t\t'
    flags = flagR[R] + tabs + flagDF[DF] + tabs + flagMF[MF]
    return flags
#function that returns the protocol used at the transport layer
def getProtocol(data):
    #open file containing all possible protocols
    protocolFile = open('Protocols.txt', 'r')
    #reads the data in opened file
    protocolData = protocolFile.read()
    #returns all strings that match the patter described, \n + data + ending character
    protocol = re.findall(r'\n' + str(data) + ' (?:.)+\n', protocolData)
    #finds matching protocol on file and returns if one is found
    if protocol:
        protocol = protocol[0]
        protocol = protocol.replace('\n', '')
        protocol = protocol.replace(str(data), '')
        protocol = protocol.lstrip()
        return protocol
    else:
        return "No Such Protocol Found"
        
def getTCPFlags(reserved, flags) :
    
    #reserved flags
    NS_flag = reserved & 0x1
    
    #congestion Window Reduced
    CWR_flag = flags >> 7
    #ECN-Echo, if SYN = 1 TCP peer is ECN capable, if SYN = 0 packet with congestion received
    ECE_flag = flags >> 6 & 0x1
    #indicates that the Urgent pointer field is significant
    URG_flag = flags >> 5 & 0x1
    #acknowledgement field is significant
    ACK_flag = flags >> 4 & 0x1
    #push function, asks to push the buffered data to the received
    PSH_flag = flags >> 3 & 0x1
    #reset the connection
    RST_flag = flags >> 2 & 0x1
    #synchronize sequence numbers
    SYN_flag = flags >> 1 & 0x1
    #no more data coming
    FIN_flag = flags & 0x1
    
    print "NS: {}\nCWR: {}\nECE: {}\nURG: {}\nACK: {}".format(NS_flag, CWR_flag, ECE_flag, URG_flag, ACK_flag)
    print "\nPSH: {}\nRST: {}\nSYN: {}\nFIN: {}\n".format(PSH_flag, RST_flag, SYN_flag, FIN_flag)
    
if __name__ == '__main__':
    main()

