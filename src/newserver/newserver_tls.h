/**
 * @project
 * @file src/newserver/newserver_tls.h
 * @author  S Roychowdhury < shreos at tirja dot com >
 * @version 1.0.0
 *
 * @section LICENSE
 *
 * Copyright (c) 2026 Shreos Roychowdhury
 * Copyright (c) 2026 Tirja Consulting LLP
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * @section DESCRIPTION
 *
 *  newserver_tls.h :
 *
 */
// newserver_tls.h: Botan TLS helpers (credentials, policy, and socket callbacks).
#ifndef NEWSERVER_TLS_H
#define NEWSERVER_TLS_H

#include <memory>
#include <string>
#include <vector>

#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <botan/credentials_manager.h>
#include <botan/pkcs8.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_policy.h>
#include <botan/x509cert.h>

class StrictPolicy : public Botan::TLS::Policy {
public:
	bool require_client_certificate_authentication() const override;
	bool require_cert_revocation_info() const override;
	std::vector<std::string> allowed_signature_hashes() const override;
	std::vector<std::string> allowed_signature_methods() const override;
	std::vector<Botan::TLS::Signature_Scheme> allowed_signature_schemes() const override;
	size_t minimum_signature_strength() const override;
};

class SimpleCredentials final : public Botan::Credentials_Manager {
public:
	SimpleCredentials(const std::string &server_cert_path,
	                  const std::string &server_key_path,
	                  const std::vector<std::string> &trusted_ca_paths,
	                  const std::string &client_cert_path = std::string(),
	                  const std::string &client_key_path = std::string());

	std::vector<Botan::Certificate_Store *> trusted_certificate_authorities(
	    const std::string &,
	    const std::string &) override;

	std::vector<Botan::X509_Certificate> cert_chain(
	    const std::vector<std::string> &,
	    const std::vector<Botan::AlgorithmIdentifier> &,
	    const std::string &type,
	    const std::string &) override;

	std::shared_ptr<Botan::Private_Key> private_key_for(
	    const Botan::X509_Certificate &cert,
	    const std::string &,
	    const std::string &) override;

private:
	Botan::AutoSeeded_RNG rng_;
	Botan::Certificate_Store_In_Memory store_;
	Botan::X509_Certificate server_cert_;
	std::shared_ptr<Botan::Private_Key> server_key_;
	Botan::X509_Certificate client_cert_;
	std::shared_ptr<Botan::Private_Key> client_key_;
	bool has_server_cert_;
	bool has_client_cert_;
};

class SocketCallbacks : public Botan::TLS::Callbacks {
public:
	explicit SocketCallbacks(int fd);

	void tls_emit_data(std::span<const uint8_t> data) override;
	void tls_record_received(uint64_t, std::span<const uint8_t> data) override;
	void tls_alert(Botan::TLS::Alert alert) override;
	void tls_session_established(const Botan::TLS::Session_Summary &) override;
	void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate> &cert_chain,
	                           const std::vector<std::optional<Botan::OCSP::Response>> &ocsp_responses,
	                           const std::vector<Botan::Certificate_Store *> &trusted_roots,
	                           Botan::Usage_Type usage,
	                           std::string_view hostname,
	                           const Botan::TLS::Policy &policy) override;

	const std::string &app_data() const;
	void clear_app_data();
	bool closed() const;

private:
	int fd_;
	std::string app_data_;
	bool closed_;
};

#endif
