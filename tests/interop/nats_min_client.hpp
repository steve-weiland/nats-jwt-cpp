#pragma once
// A MINIMAL NATS client for the e2e gate only (test code, not the library):
// enough of the protocol to authenticate with a .creds file, subscribe to
// $SYS.REQ.USER.AUTH, receive MSG/HMSG (headers carry Nats-Server-Xkey on
// sealed callout requests — binary bodies the `nats reply --command` relay
// could not carry) and publish a reply. A production daemon should use
// nats.c; this exists so the gate needs no extra dependency.
#include <jwt/jwt.hpp>
#include <nkeys/nkeys.hpp>
#include <nlohmann/json.hpp>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <fstream>
#include <functional>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

class MinNatsClient {
public:
    struct Msg {
        std::string subject, reply;
        std::map<std::string, std::string> headers;
        std::vector<std::uint8_t> payload;
    };

    // url: nats://host:port ; creds: a .creds file (JWT + user seed)
    void connect(const std::string& url, const std::string& credsFile) {
        auto hp = url.substr(url.find("://") + 3);
        auto colon = hp.rfind(':');
        const std::string host = hp.substr(0, colon), port = hp.substr(colon + 1);
        addrinfo hints{}, *res = nullptr;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) throw std::runtime_error("resolve " + host);
        for (auto* a = res; a; a = a->ai_next) {
            fd_ = ::socket(a->ai_family, a->ai_socktype, a->ai_protocol);
            if (fd_ >= 0 && ::connect(fd_, a->ai_addr, a->ai_addrlen) == 0) break;
            if (fd_ >= 0) ::close(fd_);
            fd_ = -1;
        }
        freeaddrinfo(res);
        if (fd_ < 0) throw std::runtime_error("connect " + url);

        const std::string info = readLine();  // INFO {...}
        if (info.rfind("INFO ", 0) != 0) throw std::runtime_error("expected INFO, got: " + info);
        auto j = nlohmann::json::parse(info.substr(5));
        const std::string nonce = j.value("nonce", "");

        const std::string contents = slurp(credsFile);
        const std::string userJwt = jwt::parseDecoratedJWT(contents);
        auto kp = jwt::parseDecoratedUserNKey(contents);
        std::string sig;
        if (!nonce.empty()) {
            auto raw = kp->sign(std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(nonce.data()), nonce.size()));
            sig = b64url(raw);
        }
        nlohmann::json c = {{"verbose", false}, {"pedantic", false}, {"tls_required", false},
                            {"name", "cpp_driver-callout"}, {"lang", "cpp"}, {"version", "0"},
                            {"protocol", 1}, {"headers", true}, {"jwt", userJwt}, {"sig", sig}};
        send("CONNECT " + c.dump() + "\r\nPING\r\n");
        // the server answers PONG (or -ERR on auth failure)
        for (;;) {
            const std::string line = readLine();
            if (line == "PONG") break;
            if (line.rfind("-ERR", 0) == 0) throw std::runtime_error("server: " + line);
        }
    }

    void subscribe(const std::string& subject, int sid) {
        send("SUB " + subject + " " + std::to_string(sid) + "\r\n");
    }

    void publish(const std::string& subject, std::span<const std::uint8_t> payload) {
        std::string frame = "PUB " + subject + " " + std::to_string(payload.size()) + "\r\n";
        frame.append(reinterpret_cast<const char*>(payload.data()), payload.size());
        frame += "\r\n";
        send(frame);
    }

    // Serve forever: PING→PONG, MSG/HMSG → handler.
    void run(const std::function<void(const Msg&)>& handler) {
        for (;;) {
            const std::string line = readLine();
            if (line == "PING") { send("PONG\r\n"); continue; }
            if (line.rfind("-ERR", 0) == 0) throw std::runtime_error("server: " + line);
            if (line.rfind("MSG ", 0) == 0 || line.rfind("HMSG ", 0) == 0) {
                const bool hmsg = line[0] == 'H';
                auto toks = split(line, ' ');
                // MSG subj sid [reply] len | HMSG subj sid [reply] hdrlen totlen
                Msg m;
                m.subject = toks.at(1);
                std::size_t hdrLen = 0, total = 0;
                if (hmsg) {
                    if (toks.size() == 6) { m.reply = toks[3]; hdrLen = std::stoul(toks[4]); total = std::stoul(toks[5]); }
                    else { hdrLen = std::stoul(toks.at(3)); total = std::stoul(toks.at(4)); }
                } else {
                    if (toks.size() == 5) { m.reply = toks[3]; total = std::stoul(toks[4]); }
                    else total = std::stoul(toks.at(3));
                }
                std::vector<std::uint8_t> body = readBytes(total);
                (void)readLine();  // trailing CRLF
                if (hmsg) {
                    // "NATS/1.0\r\nName: value\r\n\r\n"
                    const std::string hdr(body.begin(), body.begin() + static_cast<std::ptrdiff_t>(hdrLen));
                    for (const auto& h : split(hdr, '\n')) {
                        auto colon = h.find(':');
                        if (colon == std::string::npos) continue;
                        std::string k = h.substr(0, colon), v = h.substr(colon + 1);
                        while (!v.empty() && (v.front() == ' ')) v.erase(0, 1);
                        while (!v.empty() && (v.back() == '\r' || v.back() == ' ')) v.pop_back();
                        m.headers[k] = v;
                    }
                    m.payload.assign(body.begin() + static_cast<std::ptrdiff_t>(hdrLen), body.end());
                } else {
                    m.payload = std::move(body);
                }
                handler(m);
            }
            // +OK / INFO / anything else: ignore
        }
    }

    ~MinNatsClient() { if (fd_ >= 0) ::close(fd_); }

private:
    int fd_ = -1;
    std::string buf_;

    static std::string slurp(const std::string& p) {
        std::ifstream f(p);
        return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    }
    static std::string b64url(std::span<const std::uint8_t> d) {
        static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string out;
        std::size_t i = 0;
        for (; i + 2 < d.size(); i += 3) {
            const std::uint32_t v = (d[i] << 16) | (d[i + 1] << 8) | d[i + 2];
            out += tbl[(v >> 18) & 63]; out += tbl[(v >> 12) & 63]; out += tbl[(v >> 6) & 63]; out += tbl[v & 63];
        }
        if (i + 1 == d.size()) { const std::uint32_t v = d[i] << 16; out += tbl[(v >> 18) & 63]; out += tbl[(v >> 12) & 63]; }
        else if (i + 2 == d.size()) { const std::uint32_t v = (d[i] << 16) | (d[i + 1] << 8); out += tbl[(v >> 18) & 63]; out += tbl[(v >> 12) & 63]; out += tbl[(v >> 6) & 63]; }
        return out;
    }
    static std::vector<std::string> split(const std::string& s, char sep) {
        std::vector<std::string> out; std::size_t pos = 0;
        for (;;) { auto n = s.find(sep, pos); if (n == std::string::npos) { out.push_back(s.substr(pos)); break; } out.push_back(s.substr(pos, n - pos)); pos = n + 1; }
        return out;
    }
    void send(const std::string& s) {
        std::size_t off = 0;
        while (off < s.size()) {
            auto n = ::send(fd_, s.data() + off, s.size() - off, 0);
            if (n <= 0) throw std::runtime_error("send failed");
            off += static_cast<std::size_t>(n);
        }
    }
    void fill() {
        char tmp[65536];
        auto n = ::recv(fd_, tmp, sizeof tmp, 0);
        if (n <= 0) throw std::runtime_error("connection closed");
        buf_.append(tmp, static_cast<std::size_t>(n));
    }
    std::string readLine() {
        for (;;) {
            auto e = buf_.find("\r\n");
            if (e != std::string::npos) { std::string line = buf_.substr(0, e); buf_.erase(0, e + 2); return line; }
            fill();
        }
    }
    std::vector<std::uint8_t> readBytes(std::size_t n) {
        while (buf_.size() < n) fill();
        std::vector<std::uint8_t> out(buf_.begin(), buf_.begin() + static_cast<std::ptrdiff_t>(n));
        buf_.erase(0, n);
        return out;
    }
};
