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


"""
import the needed classes and libraries needed
"""
import socket
from datetime import *

def main() :

	#create the port number 12000 and the serverName set to 'localhost'
	serverPort = 12000
	serverName = 'localhost'

	clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	clientSocket.connect((serverName, serverPort))
	i = 0
	message = 'Ping from me'
	while(i<10):
		clientSocket.send(message)
		response = clientSocket.recv(65565)
		print response
		i += 1
	clientSocket.close()
	
	




if __name__ == '__main__': 
    main()
