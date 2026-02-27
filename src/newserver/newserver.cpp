#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <span>
#include <string>
#include <sys/stat.h>
#include <vector>

#include "newserver_db.h"
#include "newserver_sync.h"
#include "newserver_tls.h"

#include <nlohmann/json.hpp>

#include <botan/auto_rng.h>
#include <botan/tls_server.h>
#include <botan/tls_session_manager_memory.h>

namespace {
int create_listen_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    int enable = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
        perror("setsockopt(SO_REUSEADDR)");
        close(fd);
        return -1;
    }

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, 16) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

std::string to_lower(std::string s) {
    for (char &c : s) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return s;
}

bool extract_header(const std::string &headers, const std::string &name, std::string &value_out) {
    std::string needle = to_lower(name);
    size_t pos = 0;
    while (pos < headers.size()) {
        size_t line_end = headers.find("\r\n", pos);
        if (line_end == std::string::npos) {
            break;
        }
        std::string line = headers.substr(pos, line_end - pos);
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = to_lower(line.substr(0, colon));
            if (key == needle) {
                size_t start = colon + 1;
                while (start < line.size() && (line[start] == ' ' || line[start] == '\t')) {
                    start++;
                }
                value_out = line.substr(start);
                return true;
            }
        }
        pos = line_end + 2;
    }
    return false;
}

int parse_content_length(const std::string &headers) {
    std::string value;
    if (!extract_header(headers, "Content-Length", value)) {
        return 0;
    }
    return std::atoi(value.c_str());
}

bool read_http_body(Botan::TLS::Channel &channel, SocketCallbacks &cb, int fd, int content_length, std::string &body) {
    while (static_cast<int>(body.size()) < content_length) {
        char buf[2048];
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            return false;
        }
        channel.received_data(reinterpret_cast<uint8_t *>(buf), static_cast<size_t>(n));
        body = cb.app_data();
    }
    if (static_cast<int>(body.size()) > content_length) {
        body.resize(static_cast<size_t>(content_length));
    }
    return true;
}

bool parse_request_line(const std::string &headers, std::string &method_out, std::string &path_out) {
    size_t line_end = headers.find("\r\n");
    if (line_end == std::string::npos) {
        return false;
    }
    std::string line = headers.substr(0, line_end);
    size_t first_sp = line.find(' ');
    if (first_sp == std::string::npos) {
        return false;
    }
    size_t second_sp = line.find(' ', first_sp + 1);
    if (second_sp == std::string::npos) {
        return false;
    }
    method_out = line.substr(0, first_sp);
    path_out = line.substr(first_sp + 1, second_sp - first_sp - 1);
    return true;
}

bool starts_with(const std::string &s, const char *prefix) {
    size_t n = std::strlen(prefix);
    return s.size() >= n && s.compare(0, n, prefix) == 0;
}

std::string sync_comment(const char *local_field, const char *remote_field, bool request_ok, int status_code) {
    std::string comment = local_field;
    comment += " ";
    if (request_ok && status_code == 200) {
        comment += "synced with ";
        comment += remote_field;
        return comment;
    }
    comment += "could not be synced with ";
    comment += remote_field;
    comment += ", reason: ";
    if (!request_ok) {
        comment += "remote server not running";
    } else {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "remote status %d", status_code);
        comment += buf;
    }
    return comment;
}

std::string extract_request_path(const std::string &headers) {
    size_t line_end = headers.find("\r\n");
    if (line_end == std::string::npos) {
        return "/";
    }
    std::string line = headers.substr(0, line_end);
    size_t first_sp = line.find(' ');
    if (first_sp == std::string::npos) {
        return "/";
    }
    size_t second_sp = line.find(' ', first_sp + 1);
    if (second_sp == std::string::npos) {
        return "/";
    }
    return line.substr(first_sp + 1, second_sp - first_sp - 1);
}

bool base64_decode(const std::string &in, std::string &out) {
    static const int8_t kDec[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };

    out.clear();
    int val = 0;
    int valb = -8;
    for (unsigned char c : in) {
        if (c == '=') {
            break;
        }
        int8_t d = kDec[c];
        if (d < 0) {
            return false;
        }
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return true;
}

bool json_parse_object(const std::string &body, nlohmann::json &out) {
    out = nlohmann::json::parse(body, nullptr, false);
    return out.is_object();
}

bool json_get_string(const nlohmann::json &obj, const char *key, std::string &out) {
    if (!obj.contains(key) || !obj[key].is_string()) {
        return false;
    }
    out = obj[key].get<std::string>();
    return true;
}

bool json_get_int(const nlohmann::json &obj, const char *key, int &out) {
    if (!obj.contains(key) || !obj[key].is_number_integer()) {
        return false;
    }
    out = obj[key].get<int>();
    return true;
}

bool extract_basic_credentials(const std::string &auth_header, std::string &user_out, std::string &pass_out) {
    const std::string prefix = "Basic ";
    if (auth_header.size() <= prefix.size() || auth_header.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    std::string decoded;
    if (!base64_decode(auth_header.substr(prefix.size()), decoded)) {
        return false;
    }
    size_t colon = decoded.find(':');
    if (colon == std::string::npos) {
        return false;
    }
    user_out = decoded.substr(0, colon);
    pass_out = decoded.substr(colon + 1);
    return true;
}

struct UserEntry {
    std::string user;
    std::string pass;
};

std::string trim(const std::string &s) {
    std::string::size_type start = 0;
    while (start < s.size() && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n')) {
        ++start;
    }
    std::string::size_type end = s.size();
    while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t' || s[end - 1] == '\r' || s[end - 1] == '\n')) {
        --end;
    }
    return s.substr(start, end - start);
}

bool load_users(const char *path, std::vector<UserEntry> &users) {
    users.clear();
    std::ifstream in(path);
    if (!in) {
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') {
            continue;
        }
        std::string::size_type colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        UserEntry e;
        e.user = trim(line.substr(0, colon));
        e.pass = trim(line.substr(colon + 1));
        if (!e.user.empty()) {
            users.push_back(e);
        }
    }
    return true;
}

struct UserCache {
    std::vector<UserEntry> users;
    time_t mtime;
    off_t size;
    bool loaded;
    UserCache() : mtime(0), size(0), loaded(false) {}
};

bool load_users_cached(const char *path, std::vector<UserEntry> &users_out) {
    static UserCache cache;
    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    }

    if (!cache.loaded || cache.mtime != st.st_mtime || cache.size != st.st_size) {
        std::vector<UserEntry> fresh;
        if (!load_users(path, fresh)) {
            return false;
        }
        cache.users = fresh;
        cache.mtime = st.st_mtime;
        cache.size = st.st_size;
        cache.loaded = true;
    }

    users_out = cache.users;
    return true;
}

bool check_user_pass(const std::vector<UserEntry> &users,
                     const std::string &user,
                     const std::string &pass) {
    for (std::vector<UserEntry>::size_type i = 0; i < users.size(); ++i) {
        if (users[i].user == user && users[i].pass == pass) {
            return true;
        }
    }
    return false;
}

bool check_user_exists(const std::vector<UserEntry> &users,
                       const std::string &user) {
    for (std::vector<UserEntry>::size_type i = 0; i < users.size(); ++i) {
        if (users[i].user == user) {
            return true;
        }
    }
    return false;
}

bool extract_and_check_auth(const std::string &headers,
                            const std::vector<UserEntry> &users,
                            std::string &user_out,
                            std::string &pass_out) {
    std::string auth;
    if (extract_header(headers, "Authorization", auth)) {
        if (extract_basic_credentials(auth, user_out, pass_out)) {
            return check_user_pass(users, user_out, pass_out);
        }
    }

    std::string user_hdr;
    std::string pass_hdr;
    if (extract_header(headers, "X-Auth-User", user_hdr) &&
        extract_header(headers, "X-Auth-Pass", pass_hdr)) {
        user_out = user_hdr;
        pass_out = pass_hdr;
        return check_user_pass(users, user_out, pass_out);
    }
    return false;
}

std::string build_http_response(int code, const char *status, const char *body) {
    char response[512];
    int body_len = static_cast<int>(std::strlen(body));
    int resp_len = std::snprintf(
        response,
        sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        code,
        status,
        body_len,
        body);
    if (resp_len <= 0) {
        return std::string();
    }
    return std::string(response, static_cast<size_t>(resp_len));
}

bool read_until_headers(Botan::TLS::Channel &channel,
                        SocketCallbacks &cb,
                        int fd,
                        std::string &headers_out,
                        std::string &body_out) {
    headers_out.clear();
    body_out.clear();
    char buf[2048];
    std::string data;
    while (data.find("\r\n\r\n") == std::string::npos) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            return false;
        }
        channel.received_data(reinterpret_cast<uint8_t *>(buf), static_cast<size_t>(n));
        data = cb.app_data();
        if (data.size() > 16384) {
            return false;
        }
    }
    size_t header_end = data.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        return false;
    }
    headers_out = data.substr(0, header_end + 4);
    body_out = data.substr(header_end + 4);
    return true;
}

}

int main(int argc, char **argv) {
    const int port = (argc > 1) ? std::atoi(argv[1]) : 8443;
    const char *cert_path = (argc > 2) ? argv[2] : "example/certs/server2/server.crt";
    const char *key_path = (argc > 3) ? argv[3] : "example/certs/server2/server.key";
    const char *local_ca_path = (argc > 4) ? argv[4] : "example/certs/server2/ca.crt";
    const char *user_file = (argc > 5) ? argv[5] : "example/newserver.users";
    const char *db_path = (argc > 6) ? argv[6] : "example/newserver.db";
    const char *remote_host = (argc > 7) ? argv[7] : "127.0.0.1";
    const int remote_port = (argc > 8) ? std::atoi(argv[8]) : 8444;
    const char *internal_ca_path = (argc > 9) ? argv[9] : "example/certs/internal/ca.crt";
    const char *client_cert = (argc > 10) ? argv[10] : "example/certs/internal/client.crt";
    const char *client_key = (argc > 11) ? argv[11] : "example/certs/internal/client.key";
    const char *remote_server_ca_path =
        (argc > 12) ? argv[12] : "example/certs/server1/ca.crt";

    signal(SIGPIPE, SIG_IGN);

    int server_fd = create_listen_socket(port);
    if (server_fd < 0) {
        return 1;
    }

    std::printf("Botan server listening on port %d\n", port);

    while (true) {
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, reinterpret_cast<sockaddr *>(&client_addr), &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        try {
            auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
            auto session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
            auto policy = std::make_shared<StrictPolicy>();
            std::vector<std::string> cas;
            cas.push_back(local_ca_path);
            if (std::strcmp(internal_ca_path, local_ca_path) != 0) {
                cas.push_back(internal_ca_path);
            }
            auto creds = std::make_shared<SimpleCredentials>(cert_path, key_path, cas);
            auto cb = std::make_shared<SocketCallbacks>(client_fd);

            Botan::TLS::Server server(cb, session_mgr, creds, policy, rng, false);

            std::string headers;
            std::string body;
            if (!read_until_headers(server, *cb, client_fd, headers, body)) {
                close(client_fd);
                continue;
            }

            int content_length = parse_content_length(headers);
            if (content_length > 0 && static_cast<int>(body.size()) < content_length) {
                if (!read_http_body(server, *cb, client_fd, content_length, body)) {
                    server.close();
                    close(client_fd);
                    continue;
                }
            }

            std::vector<UserEntry> users;
            if (!load_users_cached(user_file, users)) {
                std::string resp = build_http_response(503, "Service Unavailable", "users file not available\n");
                server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                server.close();
                close(client_fd);
                continue;
            }

            std::string internal_hdr;
            bool internal_forward = extract_header(headers, "X-Internal-Forward", internal_hdr);

            std::string req_user;
            std::string req_pass;
            if (!extract_and_check_auth(headers, users, req_user, req_pass)) {
                if (internal_forward) {
                    std::string auth;
                    if (extract_header(headers, "Authorization", auth) &&
                        extract_basic_credentials(auth, req_user, req_pass) &&
                        check_user_exists(users, req_user)) {
                        // accept internal forward if user exists on remote
                    } else {
                        std::string user_hdr;
                        std::string pass_hdr;
                        if (extract_header(headers, "X-Auth-User", user_hdr) &&
                            extract_header(headers, "X-Auth-Pass", pass_hdr) &&
                            check_user_exists(users, user_hdr)) {
                            req_user = user_hdr;
                            req_pass = pass_hdr;
                        } else {
                            std::string resp = build_http_response(401, "Unauthorized", "Invalid username/password\n");
                            server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                            server.close();
                            close(client_fd);
                            continue;
                        }
                    }
                } else {
                    std::string resp = build_http_response(401, "Unauthorized", "Invalid username/password\n");
                    server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                    server.close();
                    close(client_fd);
                    continue;
                }
            }

            std::string method;
            std::string path;
            if (!parse_request_line(headers, method, path)) {
                std::string resp = build_http_response(400, "Bad Request", "Invalid request line\n");
                server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                server.close();
                close(client_fd);
                continue;
            }

            if (path == "/") {
                std::string nickname;
                int age = 0;
                bool age_set = false;
                std::string name_out = req_user;
                sqlite3 *db = nullptr;
                if (db_open(db_path, &db)) {
                    if (db_get_user(db, req_user, nickname, age, age_set) && !nickname.empty()) {
                        name_out = nickname;
                    }
                    db_close(db);
                }
                std::string body = "Hello " + name_out + "\n";
                std::string resp = build_http_response(200, "OK", body.c_str());
                server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
            } else if (starts_with(path, "/oldapi/")) {
                int remote_status = 0;
                std::string remote_body;
                if (https_request_remote_botan(remote_host,
                                               remote_port,
                                               remote_server_ca_path,
                                               client_cert,
                                               client_key,
                                               method,
                                               path,
                                               body,
                                               req_user,
                                               req_pass,
                                               remote_status,
                                               remote_body) &&
                    remote_status == 200) {
                    std::string resp = build_http_response(200, "OK", remote_body.c_str());
                    server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                } else {
                    std::string resp = build_http_response(503, "Service Unavailable", "remote server not running\n");
                    server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                }
            } else if (starts_with(path, "/internal/")) {
                if (!internal_forward) {
                    std::string resp = build_http_response(403, "Forbidden", "internal only\n");
                    server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                } else if (path == "/internal/setuser") {
                    if (method != "POST") {
                        std::string resp = build_http_response(405, "Method Not Allowed", "Use POST\n");
                        server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                    } else {
                        sqlite3 *db = NULL;
                        if (!db_open(db_path, &db) || !db_init_new(db)) {
                            db_close(db);
                            std::string resp = build_http_response(503, "Service Unavailable", "db unavailable\n");
                            server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                            server.close();
                            close(client_fd);
                            continue;
                        }
                        db_ensure_row(db, req_user);
                        nlohmann::json request;
                        if (!json_parse_object(body, request)) {
                            std::string resp = build_http_response(400, "Bad Request", "Invalid JSON\n");
                            server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                        } else {
                            int age = 0;
                            bool has_age = json_get_int(request, "age", age);
                            if (!has_age) {
                                std::string resp = build_http_response(400, "Bad Request", "No fields provided\n");
                                server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                            } else if (db_update_int(db, "age", age, req_user)) {
                                nlohmann::json resp_obj;
                                resp_obj["ok"] = true;
                                resp_obj["comment"] = "success";
                                std::string resp = build_http_response(200, "OK", resp_obj.dump().c_str());
                                server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                            } else {
                                std::string resp = build_http_response(503, "Service Unavailable", "db unavailable\n");
                                server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                            }
                        }
                        db_close(db);
                    }
                } else if (path == "/internal/setdata") {
                    if (method != "POST") {
                        std::string resp = build_http_response(405, "Method Not Allowed", "Use POST\n");
                        server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                    } else {
                        sqlite3 *db = NULL;
                        if (!db_open(db_path, &db) || !db_init_new(db)) {
                            db_close(db);
                            std::string resp = build_http_response(503, "Service Unavailable", "db unavailable\n");
                            server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                            server.close();
                            close(client_fd);
                            continue;
                        }
                        db_ensure_row(db, req_user);
                        nlohmann::json request;
                        if (!json_parse_object(body, request)) {
                            std::string resp = build_http_response(400, "Bad Request", "Invalid JSON\n");
                            server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                        } else {
                            std::string portfolio;
                            bool has_portfolio = json_get_string(request, "portfolio", portfolio);
                            if (!has_portfolio) {
                                std::string resp = build_http_response(400, "Bad Request", "No fields provided\n");
                                server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                            } else if (db_update_text(db, "portfolio", portfolio, req_user)) {
                                nlohmann::json resp_obj;
                                resp_obj["ok"] = true;
                                resp_obj["comment"] = "success";
                                std::string resp = build_http_response(200, "OK", resp_obj.dump().c_str());
                                server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                            } else {
                                std::string resp = build_http_response(503, "Service Unavailable", "db unavailable\n");
                                server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                            }
                        }
                        db_close(db);
                    }
                } else {
                    std::string resp = build_http_response(404, "Not Found", "Not Found\n");
                    server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                }
            } else if (starts_with(path, "/newapi/")) {
                sqlite3 *db = NULL;
                if (!db_open(db_path, &db) || !db_init_new(db)) {
                    db_close(db);
                    std::string resp = build_http_response(503, "Service Unavailable", "db unavailable\n");
                    server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                    server.close();
                    close(client_fd);
                    continue;
                }

                db_ensure_row(db, req_user);

                if (path == "/newapi/setuser") {
                    if (method != "POST") {
                        std::string resp = build_http_response(405, "Method Not Allowed", "Use POST\n");
                        server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                    } else {
                        nlohmann::json request;
                        if (!json_parse_object(body, request)) {
                            std::string resp = build_http_response(400, "Bad Request", "Invalid JSON\n");
                            server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                            db_close(db);
                            server.close();
                            close(client_fd);
                            continue;
                        }
                        std::string nickname;
                        int age = 0;
                        bool has_name = json_get_string(request, "nickname", nickname);
                        bool has_age = json_get_int(request, "age", age);
                        if (!has_name && !has_age) {
                            std::string resp = build_http_response(400, "Bad Request", "No fields provided\n");
                            server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                        } else {
                            bool ok = true;
                            if (has_name) ok = ok && db_update_text(db, "nickname", nickname, req_user);
                            if (has_age) ok = ok && db_update_int(db, "age", age, req_user);
                            if (ok && has_age && !internal_forward) {
                                nlohmann::json remote_req;
                                remote_req["age"] = age;
                                std::string remote_body_str = remote_req.dump();
                                int remote_status = 0;
                                std::string remote_body;
                                bool req_ok = https_request_remote_botan(remote_host,
                                                                         remote_port,
                                                                         remote_server_ca_path,
                                                                         client_cert,
                                                                         client_key,
                                                                         "POST",
                                                                         "/internal/setuser",
                                                                         remote_body_str,
                                                                         req_user,
                                                                         req_pass,
                                                                         remote_status,
                                                                         remote_body);
                                if (!(req_ok && remote_status == 200)) {
                                    ok = false;
                                }
                                std::string comment = sync_comment("age", "oldserver:age", req_ok, remote_status);
                                nlohmann::json resp_obj;
                                resp_obj["ok"] = ok;
                                resp_obj["comment"] = comment;
                                std::string body_resp = resp_obj.dump();
                                if (ok) {
                                    std::string resp = build_http_response(200, "OK", body_resp.c_str());
                                    server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                                } else {
                                    std::string resp = build_http_response(503, "Service Unavailable", body_resp.c_str());
                                    server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                                }
                                db_close(db);
                                server.close();
                                close(client_fd);
                                continue;
                            }
                            if (ok) {
                                nlohmann::json resp_obj;
                                resp_obj["ok"] = true;
                                if (has_age && internal_forward) {
                                    resp_obj["comment"] = "success";
                                }
                                std::string resp = build_http_response(200, "OK", resp_obj.dump().c_str());
                                server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                            } else {
                                std::string resp = build_http_response(503, "Service Unavailable", "remote server not running\n");
                                server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                            }
                        }
                    }
                } else if (path == "/newapi/setdata") {
                    if (method != "POST") {
                        std::string resp = build_http_response(405, "Method Not Allowed", "Use POST\n");
                        server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                    } else {
                        nlohmann::json request;
                        if (!json_parse_object(body, request)) {
                            std::string resp = build_http_response(400, "Bad Request", "Invalid JSON\n");
                            server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                            db_close(db);
                            server.close();
                            close(client_fd);
                            continue;
                        }
                        std::string portfolio;
                        std::string flavour;
                        bool has_portfolio = json_get_string(request, "portfolio", portfolio);
                        bool has_flavour = json_get_string(request, "flavour", flavour);
                        if (!has_portfolio && !has_flavour) {
                            std::string resp = build_http_response(400, "Bad Request", "No fields provided\n");
                            server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                        } else {
                            bool ok = true;
                            if (has_portfolio) ok = ok && db_update_text(db, "portfolio", portfolio, req_user);
                            if (has_flavour) ok = ok && db_update_text(db, "flavour", flavour, req_user);
                            if (ok && has_portfolio && !internal_forward) {
                                nlohmann::json remote_req;
                                remote_req["assets"] = portfolio;
                                std::string body_remote = remote_req.dump();
                                int remote_status = 0;
                                std::string remote_body;
                                bool req_ok = https_request_remote_botan(remote_host,
                                                                         remote_port,
                                                                         remote_server_ca_path,
                                                                         client_cert,
                                                                         client_key,
                                                                         "POST",
                                                                         "/internal/setdata",
                                                                         body_remote,
                                                                         req_user,
                                                                         req_pass,
                                                                         remote_status,
                                                                         remote_body);
                                if (!(req_ok && remote_status == 200)) {
                                    ok = false;
                                }
                                std::string comment = sync_comment("portfolio", "oldserver:assets", req_ok, remote_status);
                                nlohmann::json resp_obj;
                                resp_obj["ok"] = ok;
                                resp_obj["comment"] = comment;
                                std::string body_resp = resp_obj.dump();
                                if (ok) {
                                    std::string resp = build_http_response(200, "OK", body_resp.c_str());
                                    server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                                } else {
                                    std::string resp = build_http_response(503, "Service Unavailable", body_resp.c_str());
                                    server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                                }
                                db_close(db);
                                server.close();
                                close(client_fd);
                                continue;
                            }
                            if (ok) {
                                nlohmann::json resp_obj;
                                resp_obj["ok"] = true;
                                if (has_portfolio && internal_forward) {
                                    resp_obj["comment"] = "success";
                                }
                                std::string resp = build_http_response(200, "OK", resp_obj.dump().c_str());
                                server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                            } else {
                                std::string resp = build_http_response(503, "Service Unavailable", "remote server not running\n");
                                server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                            }
                        }
                    }
                } else if (path == "/newapi/getuser") {
                    if (method != "GET") {
                        std::string resp = build_http_response(405, "Method Not Allowed", "Use GET\n");
                        server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                    } else {
                        std::string nickname;
                        int age = 0;
                        bool age_set = false;
                        if (!db_get_user(db, req_user, nickname, age, age_set)) {
                            std::string resp = build_http_response(404, "Not Found", "Not Found\n");
                            server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                        } else {
                            nlohmann::json resp_obj;
                            resp_obj["nickname"] = nickname;
                            if (age_set) {
                                resp_obj["age"] = age;
                            } else {
                                resp_obj["age"] = nullptr;
                            }
                            std::string resp = build_http_response(200, "OK", resp_obj.dump().c_str());
                            server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                        }
                    }
                } else if (path == "/newapi/getportfolio") {
                    if (method != "GET") {
                        std::string resp = build_http_response(405, "Method Not Allowed", "Use GET\n");
                        server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                    } else {
                        std::string val;
                        if (!db_get_field(db, req_user, "portfolio", val)) {
                            std::string resp = build_http_response(404, "Not Found", "Not Found\n");
                            server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                        } else {
                            nlohmann::json resp_obj;
                            resp_obj["portfolio"] = val;
                            std::string resp = build_http_response(200, "OK", resp_obj.dump().c_str());
                            server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                        }
                    }
                } else if (path == "/newapi/getflavour") {
                    if (method != "GET") {
                        std::string resp = build_http_response(405, "Method Not Allowed", "Use GET\n");
                        server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                    } else {
                        std::string val;
                        if (!db_get_field(db, req_user, "flavour", val)) {
                            std::string resp = build_http_response(404, "Not Found", "Not Found\n");
                            server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                        } else {
                            nlohmann::json resp_obj;
                            resp_obj["flavour"] = val;
                            std::string resp = build_http_response(200, "OK", resp_obj.dump().c_str());
                            server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                        }
                    }
                } else {
                    std::string resp = build_http_response(404, "Not Found", "Not Found\n");
                    server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
                }

                db_close(db);
            } else {
                std::string resp = build_http_response(404, "Not Found", "Not Found\n");
                server.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(resp.data()), resp.size()));
            }

            server.close();
            close(client_fd);
        } catch (const std::exception &e) {
            std::fprintf(stderr, "Newserver exception: %s\n", e.what());
            close(client_fd);
        } catch (...) {
            std::fprintf(stderr, "Newserver exception: unknown\n");
            close(client_fd);
        }
    }

    close(server_fd);
    return 0;
}
