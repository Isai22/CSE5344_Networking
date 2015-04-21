# -*- coding: utf-8 -*-
"""
Created on Sun Feb 22 22:17:22 2015

@author: Daniel Aguilera
NetID: 1000659280
Class: CSE5344
Assignment: Lab 2

This is the code provided by the assigment. It is the server code that will be
run to wait for a packet from the client and simulate a 30% loss rate. The code
was unedited and is shown as provided by the lab instructions
"""

# We will need the following module to generate randomized lost packets
import random
from socket import *


def main():
    # Create a UDP socket
    # Notice the use of SOCK_DGRAM for UDP packets
    serverSocket = socket(AF_INET, SOCK_DGRAM)
    # Assign IP address and port number to socket
    serverSocket.bind(('', 12000))
    while True:
        print "Ready to serve..."
        # Generate random number in the range of 0 to 10
        rand = random.randint(0, 10)
        # Receive the client packet along with the address it is coming from
        message, address = serverSocket.recvfrom(1024)
        print message
        # Capitalize the message from the client
        message = message.upper() # If rand is less is than 4, we consider the packet lost and do not respond
        if rand < 4:
            continue
        # Otherwise, the server responds
        serverSocket.sendto(message, address)


if __name__ == '__main__': 
    main()