#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <botan/auto_rng.h>
#include <botan/tls_client.h>
#include <botan/tls_session_manager_memory.h>

#include "newserver_tls.h"

static std::string base64_encode(const std::string &in) {
    static const char kEnc[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0;
    int valb = -6;
    for (std::string::size_type i = 0; i < in.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(in[i]);
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(kEnc[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        out.push_back(kEnc[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (out.size() % 4) {
        out.push_back('=');
    }
    return out;
}

static bool parse_http_response(const std::string &resp, int &status_out, std::string &body_out) {
    status_out = 0;
    body_out.clear();
    size_t line_end = resp.find("\r\n");
    if (line_end == std::string::npos) {
        return false;
    }
    std::string status_line = resp.substr(0, line_end);
    size_t sp = status_line.find(' ');
    if (sp == std::string::npos) {
        return false;
    }
    size_t sp2 = status_line.find(' ', sp + 1);
    std::string code_str = (sp2 == std::string::npos)
                               ? status_line.substr(sp + 1)
                               : status_line.substr(sp + 1, sp2 - sp - 1);
    status_out = std::atoi(code_str.c_str());
    size_t header_end = resp.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        return false;
    }
    body_out = resp.substr(header_end + 4);
    return true;
}

static bool connect_tcp(const std::string &host, int port, int &sock_out) {
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port);
    struct addrinfo *res = nullptr;
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) {
        return false;
    }

    int sock = -1;
    for (struct addrinfo *ai = res; ai != nullptr; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) {
            continue;
        }
        if (connect(sock, ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen)) == 0) {
            sock_out = sock;
            freeaddrinfo(res);
            return true;
        }
        close(sock);
        sock = -1;
    }

    freeaddrinfo(res);
    return false;
}

int main(int argc, char **argv) {
    if (argc < 8) {
        std::fprintf(stderr,
                     "Usage: %s <host> <port> <ca_cert> <client_cert> <client_key> <user> <pass> [path] [method] [body]\n",
                     argv[0]);
        return 1;
    }
    std::string host = argv[1];
    int port = std::atoi(argv[2]);
    std::string ca_cert = argv[3];
    std::string client_cert = argv[4];
    std::string client_key = argv[5];
    std::string user = argv[6];
    std::string pass = argv[7];
    std::string path = (argc > 8) ? argv[8] : "/";
    std::string method = (argc > 9) ? argv[9] : "GET";
    std::string body = (argc > 10) ? argv[10] : "";

    int sock = -1;
    if (!connect_tcp(host, port, sock)) {
        std::perror("connect");
        return 1;
    }

    try {
        std::shared_ptr<Botan::AutoSeeded_RNG> rng(new Botan::AutoSeeded_RNG());
        std::shared_ptr<Botan::TLS::Session_Manager_In_Memory> session_mgr(
            new Botan::TLS::Session_Manager_In_Memory(rng));
        std::shared_ptr<StrictPolicy> policy(new StrictPolicy());
        std::vector<std::string> cas;
        cas.push_back(ca_cert);
        std::shared_ptr<SimpleCredentials> creds(new SimpleCredentials("", "", cas, client_cert, client_key));
        std::shared_ptr<SocketCallbacks> cb(new SocketCallbacks(sock));

        Botan::TLS::Client client(cb,
                                  session_mgr,
                                  creds,
                                  policy,
                                  rng,
                                  Botan::TLS::Server_Information(host, port),
                                  Botan::TLS::Protocol_Version::TLS_V12);

        std::string auth = user + ":" + pass;
        std::string auth_b64 = base64_encode(auth);
        std::string req = method + " " + path + " HTTP/1.1\r\n";
        req += "Host: " + host + "\r\n";
        req += "Authorization: Basic " + auth_b64 + "\r\n";
        if (!body.empty()) {
            char len_buf[32];
            std::snprintf(len_buf, sizeof(len_buf), "%lu", (unsigned long)body.size());
            req += "Content-Type: application/json\r\n";
            req += "Content-Length: ";
            req += len_buf;
            req += "\r\n";
        }
        req += "Connection: close\r\n\r\n";
        req += body;

        char buf[2048];
        while (!client.is_active()) {
            ssize_t n = ::recv(sock, buf, sizeof(buf), 0);
            if (n <= 0) {
                close(sock);
                return 1;
            }
            client.from_peer(std::span<const uint8_t>(reinterpret_cast<uint8_t *>(buf),
                                                      static_cast<size_t>(n)));
        }

        client.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(req.data()), req.size()));

        std::string resp;
        while (true) {
            ssize_t n = ::recv(sock, buf, sizeof(buf), 0);
            if (n <= 0) {
                break;
            }
            client.from_peer(std::span<const uint8_t>(reinterpret_cast<uint8_t *>(buf),
                                                      static_cast<size_t>(n)));
            resp = cb->app_data();
        }

        client.close();
        close(sock);

        int status = 0;
        std::string body;
        if (!parse_http_response(resp, status, body)) {
            std::fprintf(stderr, "Failed to parse response\n");
            return 1;
        }
        std::printf("%s", body.c_str());
        return (status >= 200 && status < 300) ? 0 : 2;
    } catch (std::exception &e) {
        std::fprintf(stderr, "Error: %s\n", e.what());
        close(sock);
        return 1;
    } catch (...) {
        close(sock);
        return 1;
    }
}
