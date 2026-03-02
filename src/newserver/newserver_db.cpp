/**
 * @project
 * @file src/newserver/newserver_db.cpp
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
 *  newserver_db.cpp :
 *
 */
// newserver_db.cpp: SQLite-backed persistence for newserver user and data records.
#include "newserver_db.h"

#include <sqlite3.h>

bool db_open(const char *path, sqlite3 **db_out)
{
	*db_out = NULL;
	if (sqlite3_open(path, db_out) != SQLITE_OK) {
		if (*db_out) {
			sqlite3_close(*db_out);
		}
		*db_out = NULL;
		return false;
	}
	sqlite3_busy_timeout(*db_out, 2000);
	return true;
}

void db_close(sqlite3 *db)
{
	if (db) {
		sqlite3_close(db);
	}
}

bool db_init_new(sqlite3 *db)
{
	const char *sql =
	    "CREATE TABLE IF NOT EXISTS newdata ("
	    "id TEXT PRIMARY KEY,"
	    "nickname TEXT,"
	    "age INTEGER,"
	    "portfolio TEXT,"
	    "flavour TEXT"
	    ");";
	return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

bool db_ensure_row(sqlite3 *db, const std::string &id)
{
	const char *sql = "INSERT OR IGNORE INTO newdata (id) VALUES (?);";
	sqlite3_stmt *stmt = NULL;
	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		return false;
	}
	sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
	bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
	sqlite3_finalize(stmt);
	return ok;
}

bool db_update_text(sqlite3 *db, const char *field, const std::string &val, const std::string &id)
{
	std::string sql = "UPDATE newdata SET ";
	sql += field;
	sql += " = ? WHERE id = ?;";
	sqlite3_stmt *stmt = NULL;
	if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK) {
		return false;
	}
	sqlite3_bind_text(stmt, 1, val.c_str(), -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 2, id.c_str(), -1, SQLITE_TRANSIENT);
	bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
	sqlite3_finalize(stmt);
	return ok;
}

bool db_update_int(sqlite3 *db, const char *field, int val, const std::string &id)
{
	std::string sql = "UPDATE newdata SET ";
	sql += field;
	sql += " = ? WHERE id = ?;";
	sqlite3_stmt *stmt = NULL;
	if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK) {
		return false;
	}
	sqlite3_bind_int(stmt, 1, val);
	sqlite3_bind_text(stmt, 2, id.c_str(), -1, SQLITE_TRANSIENT);
	bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
	sqlite3_finalize(stmt);
	return ok;
}

bool db_get_user(sqlite3 *db, const std::string &id, std::string &name_out, int &age_out, bool &age_set)
{
	const char *sql = "SELECT nickname, age FROM newdata WHERE id = ?;";
	sqlite3_stmt *stmt = NULL;
	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		return false;
	}
	sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
	int rc = sqlite3_step(stmt);
	if (rc != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return false;
	}
	const unsigned char *name = sqlite3_column_text(stmt, 0);
	name_out = name ? reinterpret_cast<const char *>(name) : "";
	if (sqlite3_column_type(stmt, 1) == SQLITE_NULL) {
		age_set = false;
		age_out = 0;
	}
	else {
		age_set = true;
		age_out = sqlite3_column_int(stmt, 1);
	}
	sqlite3_finalize(stmt);
	return true;
}

bool db_get_field(sqlite3 *db, const std::string &id, const char *field, std::string &value_out)
{
	std::string sql = "SELECT ";
	sql += field;
	sql += " FROM newdata WHERE id = ?;";
	sqlite3_stmt *stmt = NULL;
	if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK) {
		return false;
	}
	sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
	int rc = sqlite3_step(stmt);
	if (rc != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return false;
	}
	const unsigned char *val = sqlite3_column_text(stmt, 0);
	value_out = val ? reinterpret_cast<const char *>(val) : "";
	sqlite3_finalize(stmt);
	return true;
}
