// Standard libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// System libraries & networking
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>

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

// Parse requests from the client and return corresponding codes
int parse_request(char* request){
  int flags = REG_EXTENDED | REG_ICASE;
  static char* available_commands[] = {
    "\\s*USER\\s+",
    "\\s*MODE\\s+\\w+\\s*$",
    "\\s*NLST\\s*",
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

/*
 * A large block of functions for handling different client commands
 *
 */

// Handle user login
char* handle_login(char* user){
  char* response;
  if(regexecutioner(user, "\\s*cs317\\s+$", REG_EXTENDED) == 0){
    return response = "230 Login successful\r\n";
  } else {
    return response = "530 Login failed\r\n";
  }
}

// Handle available types
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

// Handle mode; only `stream` allowed
char* handle_mode(char *mode){
  char* response;
  if(regexecutioner(mode, ".*", REG_EXTENDED|REG_ICASE) == 0){
    return response = "We only handle stream mode\r\n";
  }
  else {
    return response = "504 Command not implemented for that parameter\r\n";
  }
}

// Create a socket for passive data transfer
// A lot of this code is re-used from the initial socket setup copied form Beej
// inside of main. I wanted to refactor it, but.. you know how that ends up
int handle_pasv(int client_socket){
  char* response;
  char ip[INET6_ADDRSTRLEN];
  int port;

  // Structures for finding our IP...
  struct ifaddrs *interface_list, *interface;
  static struct sockaddr_in *host;
  socklen_t host_size;
  static int passive_fd;

  // Get available interfaces
  getifaddrs(&interface_list);
  for(interface = interface_list; interface; interface = interface->ifa_next){
    if(interface->ifa_addr->sa_family == AF_INET){ // IPv4 only
      host = (struct sockaddr_in *) interface ->ifa_addr;
      strcpy(ip, inet_ntoa(host->sin_addr)); // We got an IP!
    }
  }

  // The client needs commas!
  int i; // xd
  for(i = 0; i < INET6_ADDRSTRLEN; i++){
    if(ip[i] == '.'){
      ip[i] = ',';
    }
  }

  // Create our data structure for making a socket...
  static struct sockaddr_in data_transfer;
  struct addrinfo server_hints, *server_info, *p;

  memset(&server_hints, 0, sizeof server_hints);
  server_hints.ai_family = AF_UNSPEC;
  server_hints.ai_socktype = SOCK_STREAM;
  server_hints.ai_flags = AI_PASSIVE;

  int err; if((err = getaddrinfo(NULL, "0", &server_hints, &server_info)) != 0){
    fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(err));
    return -1;
  }

  // Lets get a socket! (This is familiar)
  for(p = server_info; p != NULL; p->ai_next){
    // Set up our socket (hopefully)
    if((passive_fd = socket(p->ai_family, p->ai_socktype,
            p->ai_protocol)) == -1){
      response = "425 Cannot open data connection\r\n";
      send(client_socket, response, strlen(response), 0);
      continue;
    }
    // Bind our socket
    if(bind(passive_fd, (struct sockaddr*) &data_transfer, sizeof data_transfer)
        == -1){
      response = "425 Cannot bind data transfer socket\r\n";
      send(client_socket, response, strlen(response), 0);
      continue;
    }
    break; // mission accomplished
  }

  freeaddrinfo(server_info);

  host_size = sizeof host;
  if(getsockname(passive_fd, (struct sockaddr*) host, &host_size) != 0){
    fprintf(stderr, "getsockname(): %s\n", gai_strerror(err));
  }
  port = ntohs(host->sin_port);

  // Chop our port into bytes
  char harbor[16];
  sprintf(harbor, "%d,%d", port / 256, port % 256);
  char final_response[64];

  // Switzerland mode
  sprintf(final_response, "227 Entering Passive Mode (%s,%s)\r\n", ip, harbor);
  send(client_socket, final_response, strlen(final_response), 0);

  if(listen(passive_fd, 1) == -1){
    // We only want one user of this transfer socket
    perror("Could not listen on socket");
    return -1;
  }

  return passive_fd;
}

// Send a list of directory entries to the client
char* handle_nlst(int client_socket, int data_socket){
  int pasv_socket = accept(data_socket, NULL, 0);
  char* message = "150 Here comes the directory listing\r\n";
  send(client_socket, message, strlen(message), 0);
  int list_len = listFiles(pasv_socket, ".");
  if(list_len < 0){
    return "550 File not available\r\n";
  }

  close(pasv_socket);
  return "226 Directory send OK\r\n";
}

// Send a file to the client
char* handle_retr(char* args, int client_socket, int data_socket){
  char filename[strlen(args)];
  int i;
  for(i = 0; i < strlen(args); i++){
    if(args[i] == '\r' || args[i] == '\n'){
      filename[i] = '\0';
      break;
    }
    filename[i] = args[i];
  }

  FILE* file = fopen(filename, "r");
  if(file == NULL){
    return "550 File not found\r\n";
  }

  // We need file size!
  struct stat file_stats;
  stat(filename, &file_stats);

  char* message = "150 Opening BINARY mode data connection\r\n";
  send(client_socket, message, strlen(message), 0);

  int pasv_socket = accept(data_socket, NULL, 0);
  int success = sendfile(pasv_socket, fileno(file), NULL, file_stats.st_size);

  close(pasv_socket);
  if(success > 0){
    return "226 Transfer complete\r\n";
  } else {
    perror("Problem sending file...");
    return "450 Failed to transfer file\r\n";
  }
}

// Handle STRU (structure)
char* handle_stru(char* null){
  return "We only handle file structure\r\n";
}


// Where the magic happens, if you're Voldemort
int main(int argc, char **argv) {
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

  printf("Waiting for connections to socket...\n");

  // Sometimes I sit and wait for connections, sometimes I just sit and wait
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
    int data_socket = -1;
    char* args;

    while(code != 7){ // 7 = QUIT code from parse_request
      recv(client_socket_fd, buffer, sizeof buffer, 0);
      code = parse_request(buffer);
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
        case 2: // NLST
          args = buffer + 5; // This should be empty
          // Lets check
          if(regexecutioner(args, "\\S+", REG_EXTENDED) == 0){
            response = "501 No parameters allowed for this version of NLST\r\n";
            send(client_socket_fd, response, strlen(response), 0);
            break;
          }
          // We need a passive data transfer socket if one hasn't been created
          // previously
          if(data_socket < 1){
            data_socket = handle_pasv(client_socket_fd);
            break;
          }
          response = handle_nlst(client_socket_fd, data_socket);
          send(client_socket_fd, response, strlen(response), 0);
          break;
        case 3: // PASV
          data_socket = handle_pasv(client_socket_fd);
          break;
        case 4: // RETR
          if(data_socket < 1){
            data_socket = handle_pasv(client_socket_fd);
          }
          args = buffer + 5;
          response = handle_retr(args, client_socket_fd, data_socket);
          send(client_socket_fd, response, strlen(response), 0);
          break;
        case 5: // STRU
          args = buffer + 5;
          response = handle_stru(args);
          send(client_socket_fd, response, strlen(response), 0);
          break;
        case 6: // TYPE
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
  }
}
