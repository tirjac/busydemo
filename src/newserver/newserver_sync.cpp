#include "newserver_sync.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <memory>
#include <span>
#include <string>

#include <botan/auto_rng.h>
#include <botan/tls_client.h>
#include <botan/tls_session_manager_memory.h>
#include <botan/tls_signature_scheme.h>

#include "newserver_tls.h"

namespace {
class SyncClientPolicy : public StrictPolicy {
public:
    bool allow_tls12() const override {
        return true;
    }
    bool allow_tls13() const override {
        return false;
    }
    std::vector<std::string> allowed_signature_methods() const override {
        std::vector<std::string> methods;
        methods.push_back("RSA");
        methods.push_back("ECDSA");
        return methods;
    }
    std::vector<Botan::TLS::Signature_Scheme> allowed_signature_schemes() const override {
        std::vector<Botan::TLS::Signature_Scheme> schemes;
        schemes.push_back(Botan::TLS::Signature_Scheme::RSA_PKCS1_SHA256);
        schemes.push_back(Botan::TLS::Signature_Scheme::RSA_PKCS1_SHA384);
        schemes.push_back(Botan::TLS::Signature_Scheme::RSA_PKCS1_SHA512);
        schemes.push_back(Botan::TLS::Signature_Scheme::RSA_PKCS1_SHA1);
        schemes.push_back(Botan::TLS::Signature_Scheme::ECDSA_SHA256);
        schemes.push_back(Botan::TLS::Signature_Scheme::ECDSA_SHA384);
        schemes.push_back(Botan::TLS::Signature_Scheme::ECDSA_SHA512);
        return schemes;
    }
};
}  // namespace

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

bool https_request_remote_botan(const char *host,
                                int port,
                                const char *remote_ca_path,
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

    try {
        std::shared_ptr<Botan::AutoSeeded_RNG> rng(new Botan::AutoSeeded_RNG());
        std::shared_ptr<Botan::TLS::Session_Manager_In_Memory> session_mgr(
            new Botan::TLS::Session_Manager_In_Memory(rng));
        std::shared_ptr<StrictPolicy> policy(new SyncClientPolicy());
        std::vector<std::string> cas;
        cas.push_back(remote_ca_path);
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

        char buf[2048];
        while (!client.is_active()) {
            ssize_t n = ::recv(sock, buf, sizeof(buf), 0);
            if (n <= 0) {
                close(sock);
                return false;
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

        return parse_http_response(resp, status_out, body_out);
    } catch (...) {
        close(sock);
        return false;
    }
}
