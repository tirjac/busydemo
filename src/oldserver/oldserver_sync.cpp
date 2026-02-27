#include "oldserver_sync.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>

#include <openssl/err.h>
#include <openssl/ssl.h>

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
    status_out = ::atoi(code_str.c_str());
    size_t header_end = resp.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        return false;
    }
    body_out = resp.substr(header_end + 4);
    return true;
}

bool https_request_remote_openssl(const char *host,
                               int port,
                               const char *ca_path,
                               const char *client_cert,
                               const char *client_key,
                               const std::string &method,
                               const std::string &path,
                               const std::string &body,
                               const std::string &user,
                               const std::string &pass,
                               int &status_out,
                               std::string &body_out) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return false;
    }

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(sock);
        return false;
    }

    if (connect(sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        close(sock);
        return false;
    }
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        close(sock);
        return false;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_load_verify_locations(ctx, ca_path, NULL) != 1) {
        SSL_CTX_free(ctx);
        close(sock);
        return false;
    }
    if (SSL_CTX_use_certificate_file(ctx, client_cert, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        close(sock);
        return false;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        close(sock);
        return false;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        close(sock);
        return false;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        close(sock);
        return false;
    }
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        return false;
    }
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        return false;
    }

    std::string auth = user + ":" + pass;
    std::string auth_b64 = base64_encode(auth);
    std::string req = method + " " + path + " HTTP/1.1\r\n";
    req += "Host: ";
    req += host;
    req += "\r\n";
    req += "Authorization: Basic " + auth_b64 + "\r\n";
    req += "X-Internal-Forward: 1\r\n";
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

    SSL_write(ssl, req.c_str(), static_cast<int>(req.size()));

    std::string resp;
    char buf[2048];
    int n = 0;
    while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) {
        resp.append(buf, static_cast<size_t>(n));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);

    return parse_http_response(resp, status_out, body_out);
}
