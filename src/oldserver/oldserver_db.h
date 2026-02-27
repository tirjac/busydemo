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
