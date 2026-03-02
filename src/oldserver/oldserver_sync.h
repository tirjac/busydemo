/**
 * @project
 * @file src/oldserver/oldserver_sync.h
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
 *  oldserver_sync.h :
 *
 */
// oldserver_sync.h: HTTPS sync client interface for oldserver.
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
