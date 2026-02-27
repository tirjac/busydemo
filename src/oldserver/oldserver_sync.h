#ifndef OLDSERVER_SYNC_H
#define OLDSERVER_SYNC_H

#include <string>

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
                               std::string &body_out);

#endif
