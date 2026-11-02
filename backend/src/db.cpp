#include "db.hpp"

#include <sys/stat.h>

namespace scamshield {

Db::Db(const std::string& path) {
    int rc = sqlite3_open(path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::string msg = db_ ? sqlite3_errmsg(db_) : "cannot open database";
        sqlite3_close(db_);
        db_ = nullptr;
        throw DbError(msg, rc);
    }
    if (path != ":memory:") ::chmod(path.c_str(), 0600);  // owner-only
    sqlite3_busy_timeout(db_, 3000);
}

Db::~Db() {
    if (db_) sqlite3_close(db_);
}

void Db::exec(const char* sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::string msg = err ? err : "sql error";
        sqlite3_free(err);
        throw DbError(msg, rc);
    }
}

Stmt::Stmt(Db& db, const char* sql) : db_(db.raw()) {
    int rc = sqlite3_prepare_v2(db_, sql, -1, &st_, nullptr);
    if (rc != SQLITE_OK) throw DbError(sqlite3_errmsg(db_), rc);
}

Stmt::~Stmt() {
    if (st_) sqlite3_finalize(st_);
}

Stmt& Stmt::text(int idx, const std::string& v) {
    sqlite3_bind_text(st_, idx, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
    return *this;
}

Stmt& Stmt::integer(int idx, long long v) {
    sqlite3_bind_int64(st_, idx, v);
    return *this;
}

bool Stmt::step() {
    int rc = sqlite3_step(st_);
    if (rc == SQLITE_ROW) return true;
    if (rc == SQLITE_DONE) return false;
    throw DbError(sqlite3_errmsg(db_), sqlite3_extended_errcode(db_));
}

std::string Stmt::colText(int idx) const {
    const unsigned char* t = sqlite3_column_text(st_, idx);
    return t ? std::string(reinterpret_cast<const char*>(t), static_cast<std::size_t>(sqlite3_column_bytes(st_, idx)))
             : std::string();
}

long long Stmt::colInt(int idx) const { return sqlite3_column_int64(st_, idx); }

bool Stmt::colIsNull(int idx) const { return sqlite3_column_type(st_, idx) == SQLITE_NULL; }

}  // namespace scamshield
