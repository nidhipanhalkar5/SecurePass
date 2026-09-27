#include "crow.h"
#include <sqlite3.h>
#include <string>
#include <fstream>
#include <cstdlib>
#include <sodium.h>

void add_cors(crow::response& res) {
    res.set_header("Access-Control-Allow-Origin", "http://127.0.0.1:5500");
    res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type");
    res.set_header("Access-Control-Max-Age", "86400");
}

std::string json_escape(const char* text) {
    if (!text) return "";

    std::string result;

    for (const char* p = text; *p; ++p) {
        switch (*p) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += *p;
        }
    }

    return result;
}

int main() {
    crow::SimpleApp app;

    const char* db_file = "securepass.db";


    CROW_ROUTE(app, "/api/login")
    .methods(crow::HTTPMethod::POST)
    ([db_file](const crow::request& req, crow::response& res) {

        auto body = crow::json::load(req.body);

        if (!body || !body.has("password")) {
            res.code = 400;
            res.write("{\"error\":\"Password is required\"}");
            res.end();
            return;
        }

        std::string password = std::string(body["password"].s());

        sqlite3* db = nullptr;

        if (sqlite3_open(db_file, &db) != SQLITE_OK) {
            res.code = 500;
            res.write("{\"error\":\"Could not open database\"}");
            res.end();
            return;
        }

        const char* sql =
            "SELECT password_hash FROM auth WHERE id = 1;";

        sqlite3_stmt* stmt = nullptr;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            sqlite3_close(db);
            res.code = 500;
            res.write("{\"error\":\"Database query failed\"}");
            res.end();
            return;
        }

        std::string stored_hash;

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* hash =
                reinterpret_cast<const char*>(
                    sqlite3_column_text(stmt, 0)
                );

            if (hash) {
                stored_hash = hash;
            }
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);

        if (stored_hash.empty()) {
            res.code = 500;
            res.write("{\"error\":\"Master password is not configured\"}");
            res.end();
            return;
        }

        if (crypto_pwhash_str_verify(
                stored_hash.c_str(),
                password.c_str(),
                password.size()) != 0) {

            res.code = 401;
            res.write("{\"error\":\"Invalid master password\"}");
            res.end();
            return;
        }

        res.code = 200;
        res.set_header("Content-Type", "application/json");
        res.write("{\"success\":true,\"message\":\"Login successful\"}");
        res.end();
    });

    CROW_ROUTE(app, "/api/passwords")
    .methods(crow::HTTPMethod::OPTIONS)
    ([](const crow::request&, crow::response& res) {
        add_cors(res);
        res.code = 204;
        res.end();
    });

    CROW_ROUTE(app, "/api/passwords")
    .methods(crow::HTTPMethod::GET)
    ([db_file](const crow::request&, crow::response& res) {
        add_cors(res);

        sqlite3* db = nullptr;

        if (sqlite3_open(db_file, &db) != SQLITE_OK) {
            res.code = 500;
            res.write("{\"error\":\"Could not open database\"}");
            res.end();
            return;
        }

        const char* sql =
            "SELECT id, website, url, username, password, notes "
            "FROM passwords ORDER BY id;";

        sqlite3_stmt* stmt = nullptr;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            sqlite3_close(db);
            res.code = 500;
            res.write("{\"error\":\"Database query failed\"}");
            res.end();
            return;
        }

        std::string json = "[";
        bool first = true;

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) json += ",";
            first = false;

            int id = sqlite3_column_int(stmt, 0);

            const char* website =
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));

            const char* url =
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));

            const char* username =
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));

            const char* password =
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));

            const char* notes =
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));

            json += "{";
            json += "\"id\":" + std::to_string(id) + ",";
            json += "\"website\":\"" + json_escape(website) + "\",";
            json += "\"url\":\"" + json_escape(url) + "\",";
            json += "\"username\":\"" + json_escape(username) + "\",";
            json += "\"password\":\"" + json_escape(password) + "\",";
            json += "\"notes\":\"" + json_escape(notes) + "\"";
            json += "}";
        }

        json += "]";

        sqlite3_finalize(stmt);
        sqlite3_close(db);

        res.set_header("Content-Type", "application/json");
        res.write(json);
        res.end();
    });

    CROW_ROUTE(app, "/api/passwords")
    .methods(crow::HTTPMethod::POST)
    ([db_file](const crow::request& req, crow::response& res) {
        add_cors(res);

        auto body = crow::json::load(req.body);

        if (!body) {
            res.code = 400;
            res.write("{\"error\":\"Invalid JSON\"}");
            res.end();
            return;
        }

        if (!body.has("website") ||
            !body.has("username") ||
            !body.has("password")) {

            res.code = 400;
            res.write("{\"error\":\"website, username and password are required\"}");
            res.end();
            return;
        }

        std::string website = std::string(body["website"].s());
        std::string username = std::string(body["username"].s());
        std::string password = std::string(body["password"].s());

        std::string url = body.has("url")
            ? std::string(body["url"].s())
            : "";

        std::string notes = body.has("notes")
            ? std::string(body["notes"].s())
            : "";

        sqlite3* db = nullptr;

        if (sqlite3_open(db_file, &db) != SQLITE_OK) {
            res.code = 500;
            res.write("{\"error\":\"Could not open database\"}");
            res.end();
            return;
        }

        const char* sql =
            "INSERT INTO passwords "
            "(website, url, username, password, notes) "
            "VALUES (?, ?, ?, ?, ?);";

        sqlite3_stmt* stmt = nullptr;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            sqlite3_close(db);
            res.code = 500;
            res.write("{\"error\":\"Could not prepare database query\"}");
            res.end();
            return;
        }

        sqlite3_bind_text(stmt, 1, website.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, url.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, username.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, password.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, notes.c_str(), -1, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);

            res.code = 500;
            res.write("{\"error\":\"Could not save password\"}");
            res.end();
            return;
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);

        res.code = 201;
        res.set_header("Content-Type", "application/json");
        res.write("{\"message\":\"Password saved successfully\"}");
        res.end();
    });


    CROW_ROUTE(app, "/")
    ([] {
        std::ifstream file("../frontend/index.html");
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        crow::response res(content);
        res.set_header("Content-Type", "text/html");
        return res;
    });

    CROW_ROUTE(app, "/index.html")
    ([] {
        std::ifstream file("../frontend/index.html");
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        crow::response res(content);
        res.set_header("Content-Type", "text/html");
        return res;
    });

    CROW_ROUTE(app, "/dashboard.html")
    ([] {
        std::ifstream file("../frontend/dashboard.html");
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        crow::response res(content);
        res.set_header("Content-Type", "text/html");
        return res;
    });

    CROW_ROUTE(app, "/add-password.html")
    ([] {
        std::ifstream file("../frontend/add-password.html");
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        crow::response res(content);
        res.set_header("Content-Type", "text/html");
        return res;
    });

    CROW_ROUTE(app, "/edit-password.html")
    ([] {
        std::ifstream file("../frontend/edit-password.html");
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        crow::response res(content);
        res.set_header("Content-Type", "text/html");
        return res;
    });

    CROW_ROUTE(app, "/style.css")
    ([] {
        std::ifstream file("../frontend/style.css");
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        crow::response res(content);
        res.set_header("Content-Type", "text/css");
        return res;
    });

    CROW_ROUTE(app, "/script.js")
    ([] {
        std::ifstream file("../frontend/script.js");
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        crow::response res(content);
        res.set_header("Content-Type", "application/javascript");
        return res;
    });

    const char* port_env = std::getenv("PORT");
    int port = port_env ? std::stoi(port_env) : 18080;
    app.bindaddr("0.0.0.0").port(port).multithreaded().run();

    return 0;
}
