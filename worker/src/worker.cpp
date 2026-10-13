#include <saga/worker.hpp>
#include "internal.hpp"

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <chrono>
#include <cstdio>
#include <limits>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

namespace saga {
namespace {
using detail::Json;
constexpr std::size_t max_response = 4 * 1024 * 1024;

std::string required_string(const Json& value, const char* key) {
    const auto& field = value.at(key);
    if (!field.is_string() || field.get_ref<const std::string&>().empty())
        throw std::runtime_error(std::string("nonempty string required: ") + key);
    const auto result = field.get<std::string>();
    if (result.find('\0') != std::string::npos)
        throw std::runtime_error(std::string("NUL in field: ") + key);
    return result;
}

std::int64_t nonnegative_integer(const Json& value) {
    if (!value.is_number_integer() ||
        (value.is_number_unsigned() && value.get<std::uint64_t>() > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())))
        throw std::runtime_error("integer claim outside supported range");
    const auto result = value.get<std::int64_t>();
    if (result < 0) throw std::runtime_error("negative generation or timestamp");
    return result;
}

std::vector<unsigned char> decode_base64url(const std::string& text) {
    if (text.empty() || text.size() % 4 == 1)
        throw std::runtime_error("invalid token encoding");
    std::string encoded = text;
    for (char& character : encoded) {
        if (character == '-') character = '+';
        else if (character == '_') character = '/';
        else if (!((character >= 'A' && character <= 'Z') ||
                   (character >= 'a' && character <= 'z') ||
                   (character >= '0' && character <= '9')))
            throw std::runtime_error("invalid token alphabet");
    }
    const auto padding = (4 - encoded.size() % 4) % 4;
    encoded.append(padding, '=');
    std::vector<unsigned char> decoded(encoded.size() / 4 * 3);
    const int length = EVP_DecodeBlock(decoded.data(),
        reinterpret_cast<const unsigned char*>(encoded.data()), static_cast<int>(encoded.size()));
    if (length < 0) throw std::runtime_error("invalid token encoding");
    decoded.resize(static_cast<std::size_t>(length) - padding);
    std::string canonical((decoded.size() + 2) / 3 * 4, '\0');
    EVP_EncodeBlock(reinterpret_cast<unsigned char*>(canonical.data()), decoded.data(),
                    static_cast<int>(decoded.size()));
    while (!canonical.empty() && canonical.back() == '=') canonical.pop_back();
    for (char& character : canonical) {
        if (character == '+') character = '-';
        if (character == '/') character = '_';
    }
    if (canonical != text) throw std::runtime_error("noncanonical token encoding");
    return decoded;
}

struct Transfer {
    std::string data;
    bool too_large = false;
};

std::size_t receive(char* bytes, std::size_t size, std::size_t count, void* opaque) {
    auto& transfer = *static_cast<Transfer*>(opaque);
    const auto length = size * count;
    if (length > max_response - transfer.data.size()) {
        transfer.too_large = true;
        return 0;
    }
    transfer.data.append(bytes, length);
    return length;
}
}

WorkerConfig WorkerConfig::from_json(const std::string& document) {
    const auto value = Json::parse(document);
    if (!value.is_object()) throw std::runtime_error("worker config must be an object");
    WorkerConfig config;
    config.provider_url = required_string(value, "provider_url");
    config.ca_certificate = required_string(value, "ca_certificate");
    config.client_certificate = required_string(value, "client_certificate");
    config.client_key = required_string(value, "client_key");
    config.provider_public_key = required_string(value, "provider_public_key");
    config.agent_id = required_string(value, "agent_id");
    return config;
}

struct Worker::Impl {
    WorkerConfig config;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> public_key{nullptr, EVP_PKEY_free};

    explicit Impl(WorkerConfig input) : config(std::move(input)) {
        if (landlock_abi() < 9) throw std::runtime_error("Landlock ABI >= 9 is required; execution refused");
        if (config.provider_url.rfind("https://", 0) != 0 ||
            config.provider_url.find_first_of("?#@", 8) != std::string::npos)
            throw std::runtime_error("provider_url must be a plain HTTPS origin");
        while (config.provider_url.back() == '/') config.provider_url.pop_back();
        if (config.provider_url.find('/', 8) != std::string::npos)
            throw std::runtime_error("provider_url must not contain a path");
        // Repeating curl_global_init without global cleanup is intentional: a
        // library instance must not tear down libcurl owned by its embedding app.
        if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
            throw std::runtime_error("libcurl initialization failed");
        const auto close_file = [](FILE* file) { std::fclose(file); };
        const std::unique_ptr<FILE, decltype(close_file)> stream(
            std::fopen(config.provider_public_key.c_str(), "r"), close_file);
        if (!stream) throw std::runtime_error("cannot read pinned Provider public key");
        public_key.reset(PEM_read_PUBKEY(stream.get(), nullptr, nullptr, nullptr));
        if (!public_key || EVP_PKEY_base_id(public_key.get()) != EVP_PKEY_ED25519)
            throw std::runtime_error("Provider public key must be Ed25519");
    }

    Json request(const char* method, const std::string& path, const Json& payload = nullptr) {
        const std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> connection(curl_easy_init(), curl_easy_cleanup);
        if (!connection) throw std::runtime_error("cannot initialize Provider connection");
        const auto url = config.provider_url + path;
        const std::string body = payload.is_null() ? "" : payload.dump();
        Transfer transfer;
        char error[CURL_ERROR_SIZE] = {};
        curl_easy_setopt(connection.get(), CURLOPT_URL, url.c_str());
        curl_easy_setopt(connection.get(), CURLOPT_PROXY, "");
        curl_easy_setopt(connection.get(), CURLOPT_PROTOCOLS_STR, "https");
        curl_easy_setopt(connection.get(), CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(connection.get(), CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(connection.get(), CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(connection.get(), CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
        curl_easy_setopt(connection.get(), CURLOPT_CAINFO, config.ca_certificate.c_str());
        curl_easy_setopt(connection.get(), CURLOPT_SSLCERT, config.client_certificate.c_str());
        curl_easy_setopt(connection.get(), CURLOPT_SSLKEY, config.client_key.c_str());
        curl_easy_setopt(connection.get(), CURLOPT_CONNECTTIMEOUT, 5L);
        curl_easy_setopt(connection.get(), CURLOPT_TIMEOUT, 15L);
        curl_easy_setopt(connection.get(), CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(connection.get(), CURLOPT_WRITEFUNCTION, receive);
        curl_easy_setopt(connection.get(), CURLOPT_WRITEDATA, &transfer);
        curl_easy_setopt(connection.get(), CURLOPT_ERRORBUFFER, error);
        curl_easy_setopt(connection.get(), CURLOPT_CUSTOMREQUEST, method);
        std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers(
            curl_slist_append(nullptr, "Content-Type: application/json"), curl_slist_free_all);
        curl_easy_setopt(connection.get(), CURLOPT_HTTPHEADER, headers.get());
        if (!payload.is_null()) {
            curl_easy_setopt(connection.get(), CURLOPT_POSTFIELDS, body.data());
            curl_easy_setopt(connection.get(), CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
        }
        const auto status = curl_easy_perform(connection.get());
        if (status != CURLE_OK)
            throw std::runtime_error(transfer.too_large ? "Provider response too large" :
                std::string("Provider transport failed: ") + (error[0] ? error : curl_easy_strerror(status)));
        long http_status = 0;
        curl_easy_getinfo(connection.get(), CURLINFO_RESPONSE_CODE, &http_status);
        Json reply;
        try { reply = Json::parse(transfer.data); }
        catch (...) { throw std::runtime_error("Provider returned invalid JSON"); }
        if (http_status < 200 || http_status >= 300)
            throw std::runtime_error("Provider HTTP " + std::to_string(http_status) + ": " + reply.dump());
        if (!reply.is_object()) throw std::runtime_error("Provider response must be an object");
        return reply;
    }

    Json verify(const std::string& token, const std::string& task, std::int64_t epoch) {
        if (token.size() > 1500000) throw std::runtime_error("token too large");
        const auto delimiter = token.find('.');
        if (delimiter == std::string::npos || token.find('.', delimiter + 1) != std::string::npos)
            throw std::runtime_error("invalid signed token");
        const auto payload = decode_base64url(token.substr(0, delimiter));
        const auto signature = decode_base64url(token.substr(delimiter + 1));
        if (signature.size() != 64) throw std::runtime_error("invalid Ed25519 signature size");
        const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!context || EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, public_key.get()) != 1 ||
            EVP_DigestVerify(context.get(), signature.data(), signature.size(), payload.data(), payload.size()) != 1)
            throw std::runtime_error("Provider token signature rejected");
        const auto claims = Json::parse(payload.begin(), payload.end());
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (!claims.is_object() || claims.at("v") != 1 ||
            required_string(claims, "iss") != "saga-cap/provider" ||
            required_string(claims, "aud") != "saga-cap/worker" ||
            required_string(claims, "sub") != config.agent_id ||
            required_string(claims, "task_id") != task ||
            nonnegative_integer(claims.at("epoch")) != epoch ||
            nonnegative_integer(claims.at("iat")) > now + 2 ||
            nonnegative_integer(claims.at("iat")) >= nonnegative_integer(claims.at("exp")) ||
            nonnegative_integer(claims.at("exp")) <= now || !claims.at("capability").is_object())
            throw std::runtime_error("Provider token claims rejected");
        required_string(claims, "jti");
        return claims.at("capability");
    }
};

Worker::Worker(WorkerConfig config) : impl_(std::make_unique<Impl>(std::move(config))) {}
Worker::~Worker() = default;
Worker::Worker(Worker&&) noexcept = default;
Worker& Worker::operator=(Worker&&) noexcept = default;

std::string Worker::perform(const std::string& call_record) {
    std::string execution_id;
    bool executor_started = false;
    Json result;
    try {
        if (call_record.size() > 2 * 1024 * 1024) throw std::runtime_error("call record too large");
        const auto record = Json::parse(call_record);
        const auto task = required_string(record, "task_id");
        const auto format = required_string(record, "format");
        const auto state = impl_->request("GET", "/v1/state");
        if (required_string(state, "agent_id") != impl_->config.agent_id)
            throw std::runtime_error("Provider state identity rejected");
        const auto previous_epoch = nonnegative_integer(state.at("epoch"));
        if (previous_epoch == std::numeric_limits<std::int64_t>::max())
            throw std::runtime_error("Provider generation exhausted");
        const auto grant = impl_->request("POST", "/v1/rotate", {
            {"task_id", task}, {"expected_epoch", state.at("epoch")},
            {"format", format}, {"call", record.at("call")}});
        if (required_string(grant, "agent_id") != impl_->config.agent_id ||
            nonnegative_integer(grant.at("epoch")) != previous_epoch + 1)
            throw std::runtime_error("Provider grant generation rejected");
        const auto token = required_string(grant, "token");
        const auto capability = impl_->verify(token, task, grant.at("epoch").get<std::int64_t>());
        const auto admission = impl_->request("POST", "/v1/admit", {{"token", token}});
        execution_id = required_string(admission, "execution_id");
        if (admission.at("capability") != capability)
            throw std::runtime_error("admission capability differs from signed capability");
        result = detail::execute_child(capability, executor_started);
        result["epoch"] = grant.at("epoch");
        result["task_id"] = task;
    } catch (const std::exception& error) {
        result = {{"ok", false}, {"error", error.what()}};
    }
    if (!execution_id.empty()) {
        try {
            impl_->request("POST", "/v1/finish", {
                {"execution_id", execution_id},
                {"outcome", result.value("ok", false) ? "succeeded" : "failed"}});
        } catch (const std::exception& error) {
            // Effects may already exist. Preserve that fact for the caller and
            // leave the durable gate closed until explicit operational repair.
            result["execution_ok"] = result.value("ok", false);
            result["ok"] = false;
            result["finish_error"] = error.what();
            result["execution_id"] = execution_id;
        }
    }
    result["executor_started"] = executor_started;
    return result.dump();
}

std::string sandbox_probe(const std::string& specification) {
    return detail::probe_child(detail::Json::parse(specification)).dump();
}
} // namespace saga
