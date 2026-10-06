#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;

static void stop_service(int signal_number) {
    (void)signal_number;
    stopping = 1;
}

static int inherited_listener(void) {
    const char *descriptor = getenv("ORKA_LISTEN_FD");
    if (descriptor == NULL || strcmp(descriptor, "3") != 0) {
        return -1;
    }
    int listener = 3;
    struct sockaddr_in6 address = {0};
    socklen_t address_size = sizeof(address);
    int accepting = 0, v6only = 1;
    socklen_t option_size = sizeof(accepting);
    struct timeval timeout = {.tv_sec = 1};
    if (getsockname(listener, (struct sockaddr *)&address, &address_size) != 0 ||
        address.sin6_family != AF_INET6 || ntohs(address.sin6_port) != 18080 ||
        getsockopt(listener, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &option_size) != 0 || accepting != 1 ||
        getsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, &option_size) != 0 || v6only != 0 ||
        fcntl(listener, F_SETFD, FD_CLOEXEC) != 0 ||
        setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        unsetenv("ORKA_LISTEN_FD") != 0) {
        return -1;
    }
    return listener;
}

static ssize_t read_request(int connection, char *request, size_t capacity) {
    struct timespec started;
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
        return -1;
    }
    size_t used = 0;
    while (!stopping && used < capacity - 1) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            return -1;
        }
        long elapsed = (now.tv_sec - started.tv_sec) * 1000 +
                       (now.tv_nsec - started.tv_nsec) / 1000000;
        if (elapsed >= 1000) {
            return -1;
        }
        struct pollfd descriptor = {.fd = connection, .events = POLLIN};
        int ready = poll(&descriptor, 1, (int)(1000 - elapsed));
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready <= 0) {
            return -1;
        }
        ssize_t received = read(connection, request + used, capacity - 1 - used);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return -1;
        }
        used += (size_t)received;
        request[used] = '\0';
        if (strstr(request, "\r\n\r\n") != NULL) {
            return (ssize_t)used;
        }
    }
    return -1;
}

int main(void) {
    struct sigaction action = {0};
    action.sa_handler = stop_service;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) != 0 || signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        return 125;
    }
    int listener = inherited_listener();
    if (listener < 0) {
        return 125;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("ready");
    while (!stopping) {
        int connection = accept(listener, NULL, NULL);
        if (connection < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            close(listener);
            return 125;
        }
        char request[2048] = {0};
        ssize_t length = read_request(connection, request, sizeof(request));
        if (length < 0 && stopping) {
            close(connection);
            break;
        }
        if (length <= 0 || strncmp(request, "GET /reserve HTTP/1.1\r\n", sizeof("GET /reserve HTTP/1.1\r\n") - 1) != 0) {
            close(connection);
            close(listener);
            return 125;
        }
        puts("reserve");
        const char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nreserved\n";
        size_t sent = 0;
        while (sent < sizeof(response) - 1) {
            ssize_t length_sent = write(connection, response + sent, sizeof(response) - 1 - sent);
            if (length_sent <= 0) {
                close(connection);
                close(listener);
                return stopping ? 0 : 125;
            }
            sent += (size_t)length_sent;
        }
        close(connection);
    }
    close(listener);
    return 0;
}
