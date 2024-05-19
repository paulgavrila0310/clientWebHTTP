#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include "parson.h"

// server address, port and socket
char serv_addr[] = "34.246.184.49";
int port = 8080;
int sockfd;
// message and response buffers
char* message;
char* response;
// session cookie and jwt token
char* session_cookie;
char* jwt_token;

// register a new user into the system
int register_user() {
    char *username = NULL, *password = NULL;
    size_t username_size = 0, password_size = 0;

    // username
    printf("username=");
    getline(&username, &username_size, stdin);
    if (strchr(username, ' ')) {
        printf("\nERROR - Invalid username!");
        return -1;
    }

    // password
    printf("\npassword=");
    getline(&password, &password_size, stdin);
    if (strchr(password, ' ')) {
        printf("\nERROR - Invalid password!");
        return -1;
    }

    // successful register
    printf("\nSUCCESS - New user registered.");

    // constructing the JSON packet
    JSON_Value* root_value = json_value_init_object();
    JSON_Object* root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);
    char* json = json_serialize_to_string_pretty(root_value);

    // connecting to server
    sockfd = open_connection(serv_addr, port, AF_INET, SOCK_STREAM, 0);

    // POST request data
    char url[] = "/api/v1/tema/auth/register";
    char content_type[] = "application/json";

    // creating message
    message = compute_post_request(serv_addr, url, content_type, &json, 2, NULL, 0);

    // sending message to server and receiving response
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // closing connection
    close_connection(sockfd);
    json_free_serialized_string(json);
    json_value_free(root_value);
    return 0;
}

// log in to an existing account
int login_user() {
    char *username = NULL, *password = NULL;
    size_t username_size = 0, password_size = 0;

    // username
    printf("username=");
    getline(&username, &username_size, stdin);
    if (strchr(username, ' ')) {
        printf("\nERROR - Invalid username!");
        return -1;
    }

    // password
    printf("\npassword=");
    getline(&password, &password_size, stdin);
    if (strchr(password, ' ')) {
        printf("\nERROR - Invalid password!");
        return -1;
    }

    // successful register
    printf("\nSUCCESS - User logged in.");

    // constructing the JSON packet
    JSON_Value* root_value = json_value_init_object();
    JSON_Object* root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);
    char* json = json_serialize_to_string_pretty(root_value);

    // connecting to server
    sockfd = open_connection(serv_addr, port, AF_INET, SOCK_STREAM, 0);

    // POST request data
    char url[] = "/api/v1/tema/auth/login";
    char content_type[] = "application/json";

    // creating message
    message = compute_post_request(serv_addr, url, content_type, &json, 2, NULL, 0);

    // sending message to server and receiving response
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // setting session cookie
    session_cookie = get_cookie(response);

    // closing connection
    close_connection(sockfd);
    json_free_serialized_string(json);
    json_value_free(root_value);
    return 0;
}

int enter_library() {
    // opening connection
    sockfd = open_connection(serv_addr, port, AF_INET, SOCK_STREAM, 0);

    // GET request data
    char url[] = "/api/v1/tema/library/access";

    // creating message
    message = compute_get_request(serv_addr, url, NULL, &session_cookie, 1, NULL);

    // sending message to server and receiving response
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // printing response
    if (session_cookie == NULL) {
        printf("ERROR - User not logged in!\n");
        return -1;
    } else {
        printf("SUCCESS - Access granted!");
    }

    // setting jwt token
    jwt_token = get_jwt_token(response);

    // closing connection
    close_connection(sockfd);
    return 0;
}

int get_books() {
    // checking if user has access to library
    if (jwt_token == NULL) {
        printf("ERROR - User does not have access to library!\n");
        return -1;
    }

    // opening connection
    sockfd = open_connection(serv_addr, port, AF_INET, SOCK_STREAM, 0);

    // GET request data
    char url[] = "/api/v1/tema/library/books";

    // creating message
    char** cookies = &session_cookie;
    message = compute_get_request(serv_addr, url, NULL, cookies, 1, jwt_token);

    // sending message to server and receiving response
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);
    
    // printing the list of JSON packets
    JSON_Value *root_value = json_parse_string(response);
    JSON_Object *root_object = json_value_get_object(root_value);
    JSON_Array *books_array = json_object_get_array(root_object, "books");
    char *serialized_string = json_serialize_to_string_pretty(json_array_get_wrapping_value(books_array));
    printf("%s\n", serialized_string);

    // closing connection
    close_connection(sockfd);
    return 0;
}

int get_book() {
    // checking if user has access to library
    if (jwt_token == NULL) {
        printf("ERROR - User does not have access to library!\n");
        return -1;
    }

    char* book_id = NULL;
    int id_size = 0;

    // asking for book id
    printf("id=");
    getline(&book_id, &id_size, stdin);
    if (!is_number(book_id)) {
        printf("\nERROR - Invalid book ID! (has to be number)");
        return -1;
    }

    // opening connection
    sockfd = open_connection(serv_addr, port, AF_INET, SOCK_STREAM, 0);

    // GET request data
    char base_url[] = "/api/v1/tema/library/books/:";
    int url_len = strlen(base_url) + strlen(book_id) + 1;
    char url[url_len];
    memset(url, 0, url_len);
    sprintf(url, "%s%s", base_url, book_id);

    // creating message
    char** cookies = NULL;
    message = compute_get_request(serv_addr, url, NULL, cookies, 0, jwt_token);

    // sending message to server and receiving response
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // closing connection
    close_connection(sockfd);
    return 0;
}

int add_book() {
    // checking if user has access to library
    if (jwt_token == NULL) {
        printf("ERROR - User does not have access to library!\n");
        return -1;
    }

    char *title = NULL, *author = NULL, *genre = NULL, *page_count = NULL, *publisher = NULL;
    int title_size = 0, author_size = 0, genre_size = 0;
    int page_count_size = 0, publisher_size = 0;

    // gathering data about the new book
    printf("title=");
    getline(&title, &title_size, stdin);
    printf("\nauthor=");
    getline(&author, &author_size, stdin);
    printf("\ngenre=");
    getline(&genre, &genre_size, stdin);
    printf("\npublisher=");
    getline(&publisher, &publisher_size, stdin);
    printf("\npage_count=");
    getline(&page_count, &page_count_size, stdin);
    if (!is_number(page_count)) {
        printf("\nERROR - Page count must be a number!");
        return -1;
    }
    printf("\nSUCCESS - Book added into database!\n");

    // constructing the JSON packet
    JSON_Value* root_value = json_value_init_object();
    JSON_Object* root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "title", title);
    json_object_set_string(root_object, "author", author);
    json_object_set_string(root_object, "genre", genre);
    json_object_set_string(root_object, "page_count", page_count);
    json_object_set_string(root_object, "publisher", publisher);
    char* json = json_serialize_to_string_pretty(root_value);

    // connecting to server
    sockfd = open_connection(serv_addr, port, AF_INET, SOCK_STREAM, 0);

    // POST request data
    char url[] = "/api/v1/tema/library/books";
    char content_type[] = "application/json";

    // creating message
    message = compute_post_request(serv_addr, url, content_type, &json, 5, &session_cookie, 1);

    // sending message to server and receiving response
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // closing connection
    close_connection(sockfd);
    json_free_serialized_string(json);
    json_value_free(root_value);
    return 0;
}

int delete_book() {
    char* book_id = NULL;
    int id_size = 0;

    // asking for book id
    printf("id=");
    getline(&book_id, &id_size, stdin);
    if (!is_number(book_id)) {
        printf("\nERROR - Invalid book ID! (has to be number)");
        return -1;
    }

    // opening connection
    sockfd = open_connection(serv_addr, port, AF_INET, SOCK_STREAM, 0);

    // DELETE request data
    char base_url[] = "/api/v1/tema/library/books/:";
    int url_len = strlen(base_url) + strlen(book_id);
    char url[url_len];
    memset(url, 0, url_len);
    sprintf(url, "%s%s", base_url, book_id);

    // creating message
    message = compute_delete_request(serv_addr, url, jwt_token);

    // sending message to server and receiving response
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // closing connection
    close_connection(sockfd);
    return 0;
}

int logout() {
    // opening connection
    sockfd = open_connection(serv_addr, port, AF_INET, SOCK_STREAM, 0);

    // GET request data
    char url[] = "/api/v1/tema/auth/logout";

    // creating message
    char** cookies = NULL;
    message = compute_get_request(serv_addr, url, NULL, cookies, 0, jwt_token);

    // sending message to server and receiving response
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // closing connection
    close_connection(sockfd);

    // setting session cookie and jwt token to null
    session_cookie = NULL;
    jwt_token = NULL;
    return 0;
}

int main() {
    
    session_cookie = NULL;
    jwt_token = NULL;

    while (1) {
        // reading command from console
        char command[20];
        memset(command, 0, 20);
        fgets(command, sizeof(command), stdin);
        int ret;

        // executing command
        if (strcmp(command, "register\n") == 0) {
            ret = register_user();
            if (ret == -1)
                continue;
        }

        if (strcmp(command, "login\n") == 0) {
            ret = login_user();
            if (ret == -1)
                continue;
        }

        if (strcmp(command, "enter_library\n") == 0) {
            ret = enter_library();
            if (ret == -1)
                continue;
        }

        if (strcmp(command, "get_books\n") == 0) {
            ret = get_books();
            if (ret == -1)
                continue;
        }

        if (strcmp(command, "get_book\n") == 0) {
            ret = get_book();
            if (ret == -1)
                continue;
        }

        if (strcmp(command, "add_book\n") == 0) {
            ret = add_book();
            if (ret == -1)
                continue;
        }

        if (strcmp(command, "delete_book\n") == 0) {
            ret = delete_book();
            if (ret == -1)
                continue;
        }

        if (strcmp(command, "logout\n") == 0) {
            ret = logout();
            if (ret == -1)
                continue;
        }

        if (strcmp(command, "exit\n") == 0) {
            break;
        }
    }

    return 0;
}