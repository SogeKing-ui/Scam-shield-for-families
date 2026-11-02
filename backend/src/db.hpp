// Small RAII wrapper around SQLite. All queries use bound parameters (no string building),
// which prevents SQL injection.
#pragma once

#include <sqlite3.h>

#include <stdexcept>
#include <string>

namespace scamshield {

struct DbError : std::runtime_error {
    int code;
    DbError(const std::string& msg, int c) : std::runtime_error(msg), code(c) {}
    bool isConstraint() const { return (code & 0xFF) == SQLITE_CONSTRAINT; }
};

class Db {
public:
    explicit Db(const std::string& path);
    ~Db();
    Db(const Db&) = delete;
    Db& operator=(const Db&) = delete;
    sqlite3* raw() const { return db_; }
    void exec(const char* sql);

private:
    sqlite3* db_ = nullptr;
};

class Stmt {
public:
    Stmt(Db& db, const char* sql);
    ~Stmt();
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    Stmt& text(int idx, const std::string& v);
    Stmt& integer(int idx, long long v);
    bool step();  // true when a row is ready, false when finished
    void run() { step(); }
    std::string colText(int idx) const;
    long long colInt(int idx) const;
    bool colIsNull(int idx) const;
    int changes() const { return sqlite3_changes(db_); }

private:
    sqlite3* db_;
    sqlite3_stmt* st_ = nullptr;
};

}  // namespace scamshield
