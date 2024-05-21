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
// session cookie and jwt token
char* session_cookie;
char* jwt_token;

// register a new user into the system
int register_user() {
    char *message, *response;
    char *username = NULL, *password = NULL;
    size_t username_size = 0, password_size = 0;

    // username
    printf("username=");
    getline(&username, &username_size, stdin);
    if (strchr(username, ' ')) {
        printf("ERROR - Invalid username!\n");
        return -1;
    }
    username[strlen(username) - 1] = '\0';

    // password
    printf("password=");
    getline(&password, &password_size, stdin);
    if (strchr(password, ' ')) {
        printf("ERROR - Invalid password!\n");
        return -1;
    }
    password[strlen(password) - 1] = '\0';

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

    if (strstr(response, "OK")) {
        printf("SUCCESS - New user registered!\n");
    } else {
        printf("ERROR - User already has an account!\n");
    }

    // closing connection
    close_connection(sockfd);
    json_free_serialized_string(json);
    json_value_free(root_value);
    return 0;
}

// log in to an existing account
int login_user() {
    char *message, *response;
    char *username = NULL, *password = NULL;
    size_t username_size = 0, password_size = 0;

    // username
    printf("username=");
    getline(&username, &username_size, stdin);
    if (strchr(username, ' ')) {
        printf("\nERROR - Invalid username!");
        return -1;
    }
    username[strlen(username) - 1] = '\0';

    // password
    printf("password=");
    getline(&password, &password_size, stdin);
    if (strchr(password, ' ')) {
        printf("\nERROR - Invalid password!");
        return -1;
    }
    password[strlen(password) - 1] = '\0';

    // constructing the JSON packet
    JSON_Value* root_value = json_value_init_object();
    JSON_Object* root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);
    char* json = json_serialize_to_string_pretty(root_value);
    //printf("%s\n", json);

    // connecting to server
    sockfd = open_connection(serv_addr, port, AF_INET, SOCK_STREAM, 0);

    // POST request data
    char url[] = "/api/v1/tema/auth/login";
    char content_type[] = "application/json";

    // creating message
    char** cookies = (char**)malloc(sizeof(char*));
    cookies[0] = session_cookie;
    message = compute_post_request(serv_addr, url, content_type, &json, 2, cookies, 1);

    // sending message to server and receiving response
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);
    //printf("Message from server: %s\n", response);

    // printing response
    if (strstr(response, "400 Bad Request")) {
        printf("ERROR - Wrong username or password!\n");
    }

    if (strstr(response, "200 OK")) {
        printf("SUCCESS - User logged in!");
    }

    // setting session cookie
    session_cookie = get_cookie(response);
    //printf("Cookie-ul este: %s\n", session_cookie);

    // closing connection
    close_connection(sockfd);
    json_free_serialized_string(json);
    json_value_free(root_value);
    free(cookies);
    return 0;
}

int enter_library() {
    if (session_cookie == NULL) {
        printf("ERROR - User not logged in!\n");
        return -1;
    }

    char *message, *response;

    // opening connection
    sockfd = open_connection(serv_addr, port, AF_INET, SOCK_STREAM, 0);

    // GET request data
    char url[] = "/api/v1/tema/library/access";

    // creating message
    char** cookies = (char**)malloc(sizeof(char*));
    cookies[0] = session_cookie;
    message = compute_get_request(serv_addr, url, NULL, cookies, 1, jwt_token);

    // sending message to server and receiving response
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // printing response
    printf("Message from server: %s\n", response);
    if (strstr(response, "401 Unauthorized")) {
        printf("ERROR - User is not logged in!\n");
    } else {
        printf("SUCCESS - Library access granted!\n");
    }

    // setting jwt token
    jwt_token = get_jwt_token(response);

    // closing connection
    close_connection(sockfd);
    free(cookies);
    return 0;
}

int get_books() {
    // checking if user is logged in
    if (session_cookie == NULL) {
            printf("ERROR - User not logged in!\n");
            return -1;
        }

    // checking if user has access to library
    if (jwt_token == NULL) {
        printf("ERROR - User does not have access to library!\n");
        return -1;
    }

    char *message, *response;

    // opening connection
    sockfd = open_connection(serv_addr, port, AF_INET, SOCK_STREAM, 0);

    // GET request data
    char url[] = "/api/v1/tema/library/books";

    // creating message
    char** cookies = (char**)malloc(sizeof(char*));
    cookies[0] = session_cookie;
    message = compute_get_request(serv_addr, url, NULL, cookies, 1, jwt_token);

    // sending message to server and receiving response
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);
    
    if (strstr(response, "OK")) {
        // printing the list of JSON packets
        JSON_Value *root_value = json_parse_string(response);
        JSON_Object *root_object = json_value_get_object(root_value);
        JSON_Array *books_array = json_object_get_array(root_object, "books");
        char *serialized_string = json_serialize_to_string_pretty(json_array_get_wrapping_value(books_array));
        //printf("%s\n", serialized_string);
        json_free_serialized_string(serialized_string);
        json_value_free(root_value);
       // printf("%s\n", response);
    } else {
        printf("ERROR - Could not print information about books!\n");
        //printf("%s\n", response);
    }

    // closing connection
    close_connection(sockfd);
    free(cookies);
    return 0;
}

int get_book() {
    // checking if user is logged in
    if (session_cookie == NULL) {
            printf("ERROR - User not logged in!\n");
            return -1;
        }

    // checking if user has access to library
    if (jwt_token == NULL) {
        printf("ERROR - User does not have access to library!\n");
        return -1;
    }

    char *message, *response;
    char* book_id = NULL;
    size_t id_size = 0;

    // asking for book id
    printf("id=");
    getline(&book_id, &id_size, stdin);
    book_id[strlen(book_id) - 1] = '\0';
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
    url[url_len - 1] = '\0';

    // creating message
    char** cookies = (char**)malloc(sizeof(char*));
    cookies[0] = session_cookie;
    message = compute_get_request(serv_addr, url, NULL, cookies, 1, jwt_token);

    // sending message to server and receiving response
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // printing response
    if (strstr(response, "OK")) {
        printf("SUCCESS - Displayed information about book with ID %s\n", book_id);
    }  else {
        printf("ERROR - Book ID does not exist!\n");
    }

    // closing connection
    close_connection(sockfd);
    free(cookies);
    return 0;
}

int add_book() {
    // checking if user is logged in
    if (session_cookie == NULL) {
            printf("ERROR - User not logged in!\n");
            return -1;
        }

    // checking if user has access to library
    if (jwt_token == NULL) {
        printf("ERROR - User does not have access to library!\n");
        return -1;
    }

    char *message, *response;
    char *title = NULL, *author = NULL, *genre = NULL, *page_count = NULL, *publisher = NULL;
    size_t title_size = 0, author_size = 0, genre_size = 0;
    size_t page_count_size = 0, publisher_size = 0;

    // gathering data about the new book
    printf("title=");
    getline(&title, &title_size, stdin);
    title[strlen(title) - 1] = '\0';
    printf("\nauthor=");
    getline(&author, &author_size, stdin);
    author[strlen(author) - 1] = '\0';
    printf("\ngenre=");
    getline(&genre, &genre_size, stdin);
    genre[strlen(genre) - 1] = '\0';
    printf("\npublisher=");
    getline(&publisher, &publisher_size, stdin);
    publisher[strlen(publisher) - 1] = '\0';
    printf("\npage_count=");
    getline(&page_count, &page_count_size, stdin);
    page_count[strlen(page_count) - 1] = '\0';
    if (!is_number(page_count)) {
        printf("\nERROR - Page count must be a number!");
        return -1;
    }
    //printf("\nSUCCESS - Book added into database!\n");
    //fflush(stdin);

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
    char** cookies = (char**)malloc(sizeof(char*));
    cookies[0] = session_cookie;
    message = compute_post_request(serv_addr, url, content_type, &json, 5, &session_cookie, 1);

    // sending message to server and receiving response
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);
    printf("Response from Server: %s\n", response);

    // printing response
    if (strstr(response, "OK")) {
        printf("SUCCESS - New book added into database!\n");
    } else {
        printf("ERROR - Could not add book to database!\n");
    }

    // closing connection
    close_connection(sockfd);
    json_free_serialized_string(json);
    json_value_free(root_value);
    free(cookies);
    // free(title);
    // free(author);
    // free(genre);
    // free(publisher);
    // free(page_count);
    // free(message);
    // free(response);
    return 0;
}

int delete_book() {
    // checking if user is logged in
    if (session_cookie == NULL) {
            printf("ERROR - User not logged in!\n");
            return -1;
        }

    // checking if user has access to library
    if (jwt_token == NULL) {
        printf("ERROR - User does not have access to library!\n");
        return -1;
    }

    char *message, *response;
    char* book_id = NULL;
    size_t id_size = 0;

    // asking for book id
    printf("id=");
    getline(&book_id, &id_size, stdin);
    book_id[strlen(book_id) - 1] = '\0';
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

    // printing response
    if (strstr(response, "OK")) {
        printf("SUCCESS - Book with ID %s deleted from database!\n", book_id);
    } else {
        printf("ERROR - Could not remove book from database!\n");
    }

    // closing connection
    close_connection(sockfd);
    return 0;
}

int logout() {
    // checking if user is logged in
    if (session_cookie == NULL) {
            printf("ERROR - User not logged in!\n");
            return -1;
        }

    char *message, *response;

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

    // printing response
    if (strstr(response, "OK")) {
        printf("SUCCESS - Logged out.\n");
    } else {
        printf("ERROR - Could not log out of account!\n");
    }

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
        char* command = NULL;
        size_t command_len = 0;
        getline(&command, &command_len, stdin);
        command[strlen(command) - 1] = '\0';
        int ret;

        // executing command
        if (strcmp(command, "register") == 0) {
            ret = register_user();
            if (ret == -1)
                continue;
        }

        if (strcmp(command, "login") == 0) {
            ret = login_user();
            if (ret == -1)
                continue;
        }

        if (strcmp(command, "enter_library") == 0) {
            ret = enter_library();
            if (ret == -1)
                continue;
        }

        if (strcmp(command, "get_books") == 0) {
            ret = get_books();
            if (ret == -1)
                continue;
        }

        if (strcmp(command, "get_book") == 0) {
            ret = get_book();
            if (ret == -1)
                continue;
        }

        if (strcmp(command, "add_book") == 0) {
            ret = add_book();
            if (ret == -1)
                continue;
        }

        if (strcmp(command, "delete_book") == 0) {
            ret = delete_book();
            if (ret == -1)
                continue;
        }

        if (strcmp(command, "logout") == 0) {
            ret = logout();
            if (ret == -1)
                continue;
        }

        if (strcmp(command, "exit") == 0) {
            break;
        }

        //free(command);
    }

    return 0;
}