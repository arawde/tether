// Standard libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// System libraries & networking
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <regex.h>
//#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
//#include <sys/wait.h>

#include "dir.h"
#include "usage.h"

#define BACKLOG 4

struct sockaddr server_ip;

// Get socket address, IPv4/6
void *get_address(struct sockaddr *sa){
  if(sa->sa_family == AF_INET){
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Build a regex, use it, and destroy it
int regexecutioner(char* string, char* regex, int flags){
  int r;
  regex_t expression;

  regcomp(&expression, regex, flags);
  r = regexec(&expression, string, 0, NULL, 0);
  if(r != 0 && r != REG_NOMATCH){
    regerror(r, &expression, string, sizeof(string));
    fprintf(stderr, "Regex failed: %s\n", string);
    exit(1);
  }
  regfree(&expression);
  return r;
}

char* handle_login(char* user){
  char* response;
  if(regexecutioner(user, "\\s*cs317\\s+$", REG_EXTENDED) == 0){
    return response = "230 Login successful\r\n";
  } else {
    return response = "530 Login failed\r\n";
  }
}

char* handle_type(char* type){
  char* response;
  if(regexecutioner(type, "(^\\s*i\\s+|image\\s+)", REG_EXTENDED | REG_ICASE) == 0){
    return response = "200 Switching to Binary mode\r\n";
  }
  if(regexecutioner(type, "(^\\s*a|ascii\\s+)", REG_EXTENDED | REG_ICASE) == 0){
    return response = "200 Switching to ASCII mode\r\n";
  }
  else {
    return response = "504 Given mode not supported\r\n";
  }
}

char* handle_mode(char *mode){
  char* response;
  if(regexecutioner(mode, ".*", REG_EXTENDED|REG_ICASE) == 0){
    return response = "We only handle stream mode\r\n";
  }
  else {
    return response = "504 Command not implemented for that parameter\r\n";
  }
}

char* handle_nlst(char* null){
  return "";
}

// Open a connection for passive data transfer
char* handle_pasv(char* args){
  char *response = malloc(64 * sizeof(char));
  char ip[INET_ADDRSTRLEN];
  int port;

  static int data_socket_fd;
  // Create our data structure for making a socket...
  static struct sockaddr_in data_transfer;
  struct addrinfo server_hints, *server_info;
  socklen_t data_transfer_size;

  if((data_socket_fd = socket(PF_INET, SOCK_STREAM, 0)) == -1){
    return response = "425 Cannot open data connection\r\n";
  }

  memset(&server_hints, 0, sizeof server_hints);
  server_hints.ai_family = AF_UNSPEC;
  server_hints.ai_socktype = SOCK_STREAM;
  server_hints.ai_flags = AI_PASSIVE;
  int rv;
  if((rv = getaddrinfo(NULL, 0, &server_hints, &server_info)) != 0){
    fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(rv));
  }

  for(server_info = &server_hints; server_info != NULL; server_info ->ai_next){
    // lol ipv4 only
    if(server_info->ai_family == AF_INET){
      data_transfer = *(struct sockaddr_in*) server_info->ai_addr;
      strcpy(inet_ntoa(data_transfer.sin_addr), ip);
    }
  }

  printf("IP is... %s\n", ip);

  data_transfer_size = sizeof server_hints;

  if(bind(data_socket_fd, (struct sockaddr*) &data_transfer, sizeof(data_transfer))
      == -1){
    return response = "425 Cannot open data connection\r\n";
  }

  if(listen(data_socket_fd, BACKLOG) == -1){
    return response = "425 Cannot listen on created socket\r\n";
  }


  getsockname(data_socket_fd, (struct sockaddr*) &data_transfer, &data_transfer_size);
  port = ntohs(data_transfer.sin_port);

  //hostip = gethostbyname("localhost");



  printf("Constructing response...\n");

  sprintf(response, "227 Entering Passive Mode (%s)\r\n", ip);

  printf("%s",response);
  return response;
}

char* handle_retr(char* null){
  return "stub";
}

char* handle_stru(char* null){
  return "We only handle file structure\r\n";
}


int parse_request(char* request){
  int flags = REG_EXTENDED | REG_ICASE;
  static char* available_commands[] = {
    "\\s*USER\\s+",
    "\\s*MODE\\s+\\w+\\s*$",
    "\\s*NLST\\s+",
    "\\s*PASV\\s*",
    "\\s*RETR\\s+",
    "\\s*STRU\\s+\\w+\\s*",
    "\\s*TYPE\\s+",
    "\\s*QUIT\\s*"
  };
  int code = 0;
  for(code; code < 8; code++){
    if(regexecutioner(request, available_commands[code], flags) == 0){
      return code;
    } else {
      continue;
    }
  }
  return -1;

}


// Pause the program for terminated child program signals
/*void sigchild_handler(int s){
  int saved_error = errno;

  while(waitpid(-1, NULL, WNOHANG) > 0);

  errno = saved_error;
}*/


int main(int argc, char **argv) {
  //// This is the main program for the thread version of nc (what is nc)

  // file descriptors for our sockets
  int host_socket_fd, client_socket_fd;

  // hints for socket type, server info, and something else (what is p)
  struct addrinfo hints, *server_info, *p;

  // we need to hold data for incoming client connections
  struct sockaddr_storage client_addresses;
  socklen_t client_address_size;

  // struct sigaction signals; // We need to hold signals sent to server process
  char ip[INET6_ADDRSTRLEN]; // We'll need a string for IPs
  int rv; // Return value holder for various calls
  int yes = 1; // Sometimes we'll need to refer to an address of this for opts

  // Check the command line arguments
  if (argc != 2) {
    usage(argv[0]);
    return -1;
  }

  // Fill out hints
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // Accept both IPv4/6
  hints.ai_socktype = SOCK_STREAM; // There's a TCP handshake its all v formal
  hints.ai_flags = AI_PASSIVE; // Bind socket to _all_ local interfaces

  // Attempt to get address info for our server info
  if((rv = getaddrinfo(NULL, argv[1], &hints, &server_info)) != 0){
    fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(rv));
    return 1;
  }

  // Loop through the available interfaces and bind the first that works
  for(p = server_info; p != NULL; p->ai_next){
    // If socket() errors...
    if((host_socket_fd = socket(p->ai_family, p->ai_socktype,
            p->ai_protocol)) == -1){
      perror("Error creating host socket descriptor");
      continue; // Back to top of loop
    }

    // Try to set socket options for reusing local address
    if(setsockopt(host_socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int))
        == -1){
      perror("Error w/ setsockopt");
      exit(1); // Why exit here? Because our socket was good up to here?
    }

    // Try to bind our socket
    if(bind(host_socket_fd, p->ai_addr, p->ai_addrlen) == -1){
      close(host_socket_fd); // Close our socket since bind failed
      perror("Error binding host socket");
      continue;
    }

    break; // We got through everything okay, let's move on
  }

  freeaddrinfo(server_info); // We don't need our available interfaces anymore

  // If we didn't actually get anything from our loop...
  if(p == NULL){
    fprintf(stderr, "Server: failed to bind socket\n");
    exit(1);
  }

  // Listen for connections w/ queue size BACKLOG
  if(listen(host_socket_fd, BACKLOG) == -1){
    perror("Could not listen on socket");
    exit(1);
  }

  /*
  signals.sa_handler = sigchild_handler; // Set our signal handler (reap processes?)
  sigemptyset(&signals.sa_mask); // Create an empty set for signals
  signals.sa_flags = SA_RESTART; // We want to restart pending calls

  // Has our child errored? Check with the handler
  if(sigaction(SIGCHLD, &signals, NULL) == -1){
    perror("Signal received from child");
    exit(1);
  }
  */

  printf("Waiting for connections to socket...\n");
  // What is our IP?
  //server_ip =


  // This is how to call the function in dir.c to get a listing of a directory.
  // It requires a file descriptor, so in your code you would pass in the file descriptor

  /*
   printf("Printed %d directory entries\n", listFiles(1, "."));
   return 0;
  */


  // Sometimes I sit and wait for connections, sometimes I just wait
  while(1){
    client_address_size = sizeof client_addresses;
    client_socket_fd = accept(host_socket_fd, (struct sockaddr *) &client_addresses,
        &client_address_size);

    // Something went wrong accepting the client...
    if(client_socket_fd == -1){
      perror("Error accepting a client connection");
      continue; // Back to start, we probably have other clients
    }

    // Convert connecting client IP into a format we can read...
    inet_ntop(client_addresses.ss_family,
        get_address((struct sockaddr*)&client_addresses), ip, sizeof ip);

    printf("Client connected from %s\n", ip);

    // Client connected, are we ready?
    char* response = "220 CSftp Server ready\r\n";
    if(send(client_socket_fd, response, strlen(response), 0) == -1){
      perror("Failed to indicate server ready");
    }

    // Things are good, let's start accepting commands
    char buffer[512];
    memset(&buffer, 0, 512);
    int code = 0;
    char* args;
    while(code != 7){ // 7 = QUIT code from parse_request
      recv(client_socket_fd, buffer, sizeof buffer, 0);
      printf("Client said: %s\n", buffer);
      code = parse_request(buffer);
      printf("Request said: %d\n", code);
      switch (code){
        case 0: // USER
          args = buffer + 5;
          response = handle_login(args);
          send(client_socket_fd, response, strlen(response), 0);
          break;
        case 1: // MODE
          args = buffer + 5;
          response = handle_mode(args);
          send(client_socket_fd, response, strlen(response), 0);
          break;
        case 2:
          args = buffer + 5;
          response = handle_nlst(args);
          send(client_socket_fd, response, strlen(response), 0);
          break;
        case 3: // PASV
          args = buffer + 5;
          response = handle_pasv(args);
          //send(client_socket_fd, response, strlen(response), 0);
          break;
        case 4:
          args = buffer + 5;
          response = handle_retr(args);
          send(client_socket_fd, response, strlen(response), 0);
          break;
        case 5:
          args = buffer + 5;
          response = handle_stru(args);
          send(client_socket_fd, response, strlen(response), 0);
          break;
        case 6:
          args = buffer + 5;
          response = handle_type(args);
          send(client_socket_fd, response, strlen(response), 0);
          break;
        case 7: // QUIT
          response = "221 Goodbye\r\n";
          send(client_socket_fd, response, strlen(response), 0);
          close(client_socket_fd); // SHUT IT DOWN
          break;
        default:
          response = "502 Command not implemented\r\n";
          send(client_socket_fd, response, strlen(response), 0);
          break;
      }
      memset(&buffer, 0, 512); // Reset the buffer before we loop around
    }

    /*int match = regexecutioner(buffer, "\\s*USER\\s+cs317\\s*",
        REG_ICASE | REG_EXTENDED);
    if(match == 0){
      response = "230 Login successful\r\n";
      send(client_socket_fd, response, strlen(response), 0);

      memset(&buffer, 0, 512);
      recv(client_socket_fd, buffer, sizeof buffer, 0);

      //handle_commend(buffer) // Returns code for command
      int code;
      if(regexecutioner(buffer, "\\s*QUIT\\s*", REG_ICASE | REG_EXTENDED) == 0){
        code = 221;
      }
      switch(code){
        case 221:
          response = "221 Goodbye\r\n";
          send(client_socket_fd, response, strlen(response), 0);
          close(client_socket_fd);
          break;
      }

    }
    if(match == REG_NOMATCH) {
      response = "530 Login failed\r\n";
      send(client_socket_fd, response, strlen(response), 0);
    }*/
  }
}
