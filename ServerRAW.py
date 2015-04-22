# -*- coding: utf-8 -*-
"""
Created on Tue Apr 21 19:25:22 2015

@author: Daniel Aguilera
NetID: 1000659280
Class: CSE5344
Assignment: Lab 3

This is the code provided by the assigment. It is the server code that will be
run to wait for a packet from the client and simulate a 30% loss rate. The code
was unedited and is shown as provided by the lab instructions
"""

# We will need the following module to generate randomized lost packets
import random
import socket
import sys
import re
from struct import *


def main():
	rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
	
	print "Ready to serve!"
	count = 0
	while(count<=20):
		print "Connected!"		
		packet = rawSocket.recvfrom(65565)
		#print packet[0]
		eth_length, eth_protocol = print_Etho(packet[0])
		IP_length, protocol = print_IP_Linux(packet[0], eth_length)
		print_TCP(packet[0], eth_length+IP_length)
		count += 1
		print "Message Reply Sent"+str(count)
	rawSocket.close()
	
def print_Etho(packet):
	eth_length = 14
	eth_header = packet[:eth_length]
	eth = unpack('!6s6sH', eth_header)
	#eth_protocol = socket.ntohs(eth[2])
	eth_protocol = eth[2]
	print '\n\nDestination MAC: ' + eth_addr(packet[:6]) + ' Source MAC: ' + eth_addr(packet[6:12]) + ' Protocol: ' + hex(eth_protocol)

	return eth_length, hex(eth_protocol)

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
	return b

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
    #print "Type of Service: \t" + TypeOfService(TOS)
    print "Length:\t\t\t" + str(totalLength)
    #print "ID:\t\t\t" + str(hex(ID)) + '(' +str(ID) + ')'
    print "Flags:\t\t\t" + getFlags(flags)
    #print "Fragment Offset:\t" + str(fragments)
    print "TTL:\t\t\t" + str(ttl)
    print "Protocol:\t\t" + getProtocol(protocol)
    #print "Checksum:\t\t" + str(checksum)
    print "SourceIP:\t\t" + sourceIP
    print "DestinationIP:\t\t" + destinationIP
    
    #will be used to find where the Transport information begins in methods calling print_IP()
    return iphl, protocol

"""
This function prints the TCP data, it unpacks and deciphers the header data
"""
def print_TCP(packet, iphl):
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
    getTCPFlags(tcph[4], tcph[5])     
    #the congestion window
    conge_win = tcph[6]
    
    print 'Source Port {}, Destination Port {}, sequence {}'.format(source_port, destination_port, sequence)
    print 'Acknowledgement {}, TCP Length {}, Congestion Window: {}'.format(acknowledgment, tcph_length*4, conge_win)
    
    header_size = iphl + tcph_length * 4
    data_size = len(packet) - header_size
    data = packet[header_size:]  



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
