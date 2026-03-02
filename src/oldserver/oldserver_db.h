/**
 * @project
 * @file src/oldserver/oldserver_db.h
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
 *  oldserver_db.h :
 *
 */
// oldserver_db.h: DB interface for oldserver (SQLite).
#ifndef OLDSERVER_DB_H
#define OLDSERVER_DB_H

#include <string>

struct sqlite3;

bool db_open(const char *path, sqlite3 **db_out);
void db_close(sqlite3 *db);
bool db_init_old(sqlite3 *db);
bool db_ensure_row(sqlite3 *db, const std::string &id);
bool db_update_text(sqlite3 *db, const char *field, const std::string &val, const std::string &id);
bool db_update_int(sqlite3 *db, const char *field, int val, const std::string &id);
bool db_get_user(sqlite3 *db, const std::string &id, std::string &name_out, int &age_out, bool &age_set);
bool db_get_field(sqlite3 *db, const std::string &id, const char *field, std::string &value_out);

#endif
