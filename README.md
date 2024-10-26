# COMMUNICATION PROTOCOLS - ASSIGNMENT 4 - HTTP WEB CLIENT. COMMUNICATION USING REST API.

**STUDENT** - Gavrilă Paul-Alexandru

The assignment contains the implementation of a HTTP web client that communicates with a server (in this case, an online book library), using the C programming language and the REST API for accessing and modifying data
using HTTP requests.


The program reads commands from console that are sent to the server as HTTP requests, which can be categorized into 3 types:
- *POST REQUEST* - adding/sending data to the server
- *GET REQUEST* - asking to receive data from the server
- *DELETE REQUEST* - removing data from the server

The functions that are used for constructing the requests can be found in the requests.c file. A request header will contain its type identifier, the IP address of the server, the URL of the access route, the type of content of the message (only for POST requests), but also the Session Cookie and the Access Token when these are necessary for the execution of the command. The Session Cookie proves to the server that the user is logged into its account, while the Access Token grants the user permission to access the library.


