#include "newserver_tls.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <botan/asn1_obj.h>
#include <botan/data_src.h>
#include <botan/tls_exceptn.h>
#include <botan/x509path.h>

bool StrictPolicy::require_client_certificate_authentication() const {
    return true;
}

bool StrictPolicy::require_cert_revocation_info() const {
    return false;
}

std::vector<std::string> StrictPolicy::allowed_signature_hashes() const {
    std::vector<std::string> hashes;
    hashes.push_back("SHA-256");
    hashes.push_back("SHA-384");
    hashes.push_back("SHA-512");
    hashes.push_back("SHA-1");
    return hashes;
}

std::vector<std::string> StrictPolicy::allowed_signature_methods() const {
    std::vector<std::string> methods;
    methods.push_back("RSA");
    methods.push_back("ECDSA");
    return methods;
}

std::vector<Botan::TLS::Signature_Scheme> StrictPolicy::allowed_signature_schemes() const {
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

size_t StrictPolicy::minimum_signature_strength() const {
    return 80;
}
SimpleCredentials::SimpleCredentials(const std::string &server_cert_path,
                                     const std::string &server_key_path,
                                     const std::vector<std::string> &trusted_ca_paths,
                                     const std::string &client_cert_path,
                                     const std::string &client_key_path)
    : has_server_cert_(!server_cert_path.empty()),
      has_client_cert_(!client_cert_path.empty()) {
    if (has_server_cert_) {
        server_cert_ = Botan::X509_Certificate(server_cert_path);
        Botan::DataSource_Stream server_key_src(server_key_path);
        server_key_ = Botan::PKCS8::load_key(server_key_src);
    }
    if (has_client_cert_) {
        client_cert_ = Botan::X509_Certificate(client_cert_path);
        Botan::DataSource_Stream client_key_src(client_key_path);
        client_key_ = Botan::PKCS8::load_key(client_key_src);
    }
    for (std::vector<std::string>::size_type i = 0; i < trusted_ca_paths.size(); ++i) {
        store_.add_certificate(Botan::X509_Certificate(trusted_ca_paths[i]));
    }
}

std::vector<Botan::Certificate_Store *> SimpleCredentials::trusted_certificate_authorities(
    const std::string &,
    const std::string &) {
    std::vector<Botan::Certificate_Store *> stores;
    stores.push_back(&store_);
    return stores;
}

std::vector<Botan::X509_Certificate> SimpleCredentials::cert_chain(
    const std::vector<std::string> &,
    const std::vector<Botan::AlgorithmIdentifier> &,
    const std::string &type,
    const std::string &) {
    if (type == "tls-server") {
        return has_server_cert_ ? std::vector<Botan::X509_Certificate>(1, server_cert_)
                                : std::vector<Botan::X509_Certificate>();
    }
    if (type == "tls-client" && has_client_cert_) {
        return std::vector<Botan::X509_Certificate>(1, client_cert_);
    }
    return std::vector<Botan::X509_Certificate>();
}

std::shared_ptr<Botan::Private_Key> SimpleCredentials::private_key_for(
    const Botan::X509_Certificate &cert,
    const std::string &,
    const std::string &) {
    if (has_server_cert_ && cert == server_cert_) {
        return server_key_;
    }
    if (has_client_cert_ && cert == client_cert_) {
        return client_key_;
    }
    return std::shared_ptr<Botan::Private_Key>();
}

SocketCallbacks::SocketCallbacks(int fd) : fd_(fd), closed_(false) {}

void SocketCallbacks::tls_emit_data(std::span<const uint8_t> data) {
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = ::send(fd_, data.data() + sent, data.size() - sent, 0);
        if (n <= 0) {
            break;
        }
        sent += static_cast<size_t>(n);
    }
}

void SocketCallbacks::tls_record_received(uint64_t, std::span<const uint8_t> data) {
    app_data_.append(reinterpret_cast<const char *>(data.data()), data.size());
}

void SocketCallbacks::tls_alert(Botan::TLS::Alert alert) {
    // std::fprintf(stderr, "Botan TLS alert: %s (%d)%s\n",
    //              alert.type_string().c_str(), alert.type(),
    //              alert.is_fatal() ? " [fatal]" : "");
    if (alert.is_fatal()) {
        closed_ = true;
    }
}

void SocketCallbacks::tls_session_established(const Botan::TLS::Session_Summary &) {
}

void SocketCallbacks::tls_verify_cert_chain(
    const std::vector<Botan::X509_Certificate> &cert_chain,
    const std::vector<std::optional<Botan::OCSP::Response>> &ocsp_responses,
    const std::vector<Botan::Certificate_Store *> &trusted_roots,
    Botan::Usage_Type usage,
    std::string_view hostname,
    const Botan::TLS::Policy &policy) {
    if (cert_chain.empty()) {
        throw Botan::Invalid_Argument("Certificate chain was empty");
    }

    Botan::Path_Validation_Restrictions restrictions(policy.require_cert_revocation_info(),
                                                     policy.minimum_signature_strength());

    std::string_view hostname_to_check = hostname;
    if (usage == Botan::Usage_Type::TLS_CLIENT_AUTH) {
        hostname_to_check = std::string_view();
    }

    if (!hostname.empty()) {
        // std::fprintf(stderr, "Botan TLS verify: usage=%s hostname='%.*s'\n",
        //              usage == Botan::Usage_Type::TLS_CLIENT_AUTH ? "client" : "server",
        //              static_cast<int>(hostname.size()), hostname.data());
    } else {
        // std::fprintf(stderr, "Botan TLS verify: usage=%s hostname=<empty>\n",
        //              usage == Botan::Usage_Type::TLS_CLIENT_AUTH ? "client" : "server");
    }

    Botan::Path_Validation_Result result = Botan::x509_path_validate(
        cert_chain,
        restrictions,
        trusted_roots,
        hostname_to_check,
        usage,
        tls_current_timestamp(),
        tls_verify_cert_chain_ocsp_timeout(),
        ocsp_responses);

    if (!result.successful_validation()) {
        throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::BadCertificate,
                                        "Certificate validation failure: " + result.result_string());
    }
}

const std::string &SocketCallbacks::app_data() const {
    return app_data_;
}

void SocketCallbacks::clear_app_data() {
    app_data_.clear();
}

bool SocketCallbacks::closed() const {
    return closed_;
}
