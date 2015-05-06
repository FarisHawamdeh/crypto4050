***Changed from a fork***


To compile:

Simply run 'make' in the command line.


To Run:

  Follow in order:
    1. ./secureserver 8081
    2. ./ssl-server 8080 localhost 8081
    3. ./ssl-client localhost 8080
    
    ***The port numbers can be different... Just be sure that it is a different port number between the ssl-server and secureserver***
