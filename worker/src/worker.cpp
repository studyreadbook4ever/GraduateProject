#include <saga/worker.hpp>
#include "internal.hpp"

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <chrono>
#include <cstdio>
#include <limits>
#include <memory>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace saga {
namespace {
using detail::Json;
constexpr std::size_t max_response = 5 * 1024 * 1024;

void validate_text(const std::string& value) {
    if (value.empty() || value.find('\0') != std::string::npos)
        throw std::runtime_error("nonempty UTF-8 text without NUL required");
    (void)Json(value).dump(); // Also validates UTF-8 for directly constructed configs.
}

std::string required_string(const Json& value, const char* key) {
    const auto& field = value.at(key);
    if (!field.is_string() || field.get_ref<const std::string&>().empty())
        throw std::runtime_error(std::string("nonempty string required: ") + key);
    const auto result = field.get<std::string>();
    validate_text(result);
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
    std::string request_id;
    bool too_large = false;
};

bool identifier(const std::string& value, std::size_t length) {
    return value.size() == length && value.find_first_not_of("0123456789abcdef") == std::string::npos;
}

void validate_operation_id(const std::string& value) {
    if (value.empty() || value.size() > 128 ||
        std::string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").find(value.front()) == std::string::npos ||
        value.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-") != std::string::npos)
        throw std::runtime_error("invalid operation identity");
}

std::string new_call_id() {
    unsigned char bytes[16];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) throw std::runtime_error("cannot create call identity");
    constexpr char alphabet[] = "0123456789abcdef";
    std::string output;
    for (const auto byte : bytes) {
        output += alphabet[byte >> 4];
        output += alphabet[byte & 15];
    }
    return output;
}

struct RequestError : std::runtime_error {
    std::string code;
    long status;
    bool transport;
    std::string request_id;
    RequestError(std::string reason, long http_status = 0, bool transport_failure = false,
                 std::string correlation = {})
        : std::runtime_error("Provider request failed"), code(std::move(reason)),
          status(http_status), transport(transport_failure), request_id(std::move(correlation)) {}
};

std::size_t receive_header(char* bytes, std::size_t size, std::size_t count, void* opaque) {
    auto& transfer = *static_cast<Transfer*>(opaque);
    const auto length = size * count;
    std::string header(bytes, length);
    constexpr char prefix[] = "x-saga-request-id:";
    std::string name = header.substr(0, sizeof(prefix) - 1);
    for (auto& character : name)
        if (character >= 'A' && character <= 'Z') character += 'a' - 'A';
    if (name == prefix) {
        const auto start = header.find_first_not_of(" \t", sizeof(prefix) - 1);
        if (start != std::string::npos) {
            const auto end = header.find_first_of(" \t\r\n", start);
            const auto value = header.substr(start, end - start);
            if (identifier(value, 32)) transfer.request_id = value;
        }
    }
    return length;
}

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
        for (const auto* value : {&config.provider_url, &config.ca_certificate,
             &config.client_certificate, &config.client_key, &config.provider_public_key, &config.agent_id})
            validate_text(*value);
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

    Json request(const char* method, const std::string& path, const Json& payload = nullptr,
                 const std::string& call_id = {}) {
        const std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> connection(curl_easy_init(), curl_easy_cleanup);
        if (!connection) throw std::runtime_error("cannot initialize Provider connection");
        const auto url = config.provider_url + path;
        const std::string body = payload.is_null() ? "" : payload.dump();
        Transfer transfer;
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
        curl_easy_setopt(connection.get(), CURLOPT_HEADERFUNCTION, receive_header);
        curl_easy_setopt(connection.get(), CURLOPT_HEADERDATA, &transfer);
        curl_easy_setopt(connection.get(), CURLOPT_CUSTOMREQUEST, method);
        std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers(
            curl_slist_append(nullptr, "Content-Type: application/json"), curl_slist_free_all);
        if (!call_id.empty()) {
            const auto correlation = "X-Saga-Call-ID: " + call_id;
            auto* appended = curl_slist_append(headers.get(), correlation.c_str());
            if (!appended) throw std::runtime_error("cannot initialize Provider headers");
            headers.release();
            headers.reset(appended);
        }
        curl_easy_setopt(connection.get(), CURLOPT_HTTPHEADER, headers.get());
        if (!payload.is_null()) {
            curl_easy_setopt(connection.get(), CURLOPT_POSTFIELDS, body.data());
            curl_easy_setopt(connection.get(), CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
        }
        const auto status = curl_easy_perform(connection.get());
        if (status != CURLE_OK)
            throw RequestError(transfer.too_large ? "provider_response_too_large" : "provider_transport",
                               0, !transfer.too_large, transfer.request_id);
        long http_status = 0;
        curl_easy_getinfo(connection.get(), CURLINFO_RESPONSE_CODE, &http_status);
        Json reply;
        try { reply = Json::parse(transfer.data); }
        catch (...) { throw RequestError("invalid_provider_response", http_status, false, transfer.request_id); }
        if (http_status < 200 || http_status >= 300) {
            std::string code = "provider_rejected";
            if (reply.is_object() && reply.contains("error") && reply["error"].is_object() &&
                reply["error"].contains("code") && reply["error"]["code"].is_string()) {
                const auto candidate = reply["error"]["code"].get<std::string>();
                if (!candidate.empty() && candidate.size() <= 64 &&
                    candidate.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_") == std::string::npos)
                    code = candidate;
            }
            throw RequestError(code, http_status, false, transfer.request_id);
        }
        if (!reply.is_object()) throw RequestError("invalid_provider_response", http_status, false, transfer.request_id);
        return reply;
    }

    Json observe(const std::string& call_id) {
        for (unsigned int attempt = 0; ; ++attempt) {
            try { return request("GET", "/v1/state", nullptr, call_id); }
            catch (const RequestError& error) {
                if (!error.transport || attempt == 2) throw;
                std::this_thread::sleep_for(std::chrono::milliseconds(25 * (attempt + 1)));
            }
        }
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
    std::string call_id;
    std::string operation_id;
    std::string phase = "parse";
    bool executor_started = false;
    bool admission_uncertain = false;
    bool grant_observed = false;
    Json result;
    try {
        call_id = new_call_id();
        if (call_record.size() > 2 * 1024 * 1024) throw std::runtime_error("call record too large");
        const auto record = Json::parse(call_record);
        if (!record.is_object() || (record.size() != 3 && record.size() != 4) || !record.contains("call") ||
            (record.size() == 4 && !record.contains("operation_id")))
            throw std::runtime_error("call record fields do not match schema");
        operation_id = record.contains("operation_id") ? required_string(record, "operation_id") : new_call_id();
        validate_operation_id(operation_id);
        const auto task = required_string(record, "task_id");
        const auto format = required_string(record, "format");
        Json grant;
        std::int64_t previous_epoch = 0;
        for (unsigned int attempt = 0; ; ++attempt) {
            phase = "state";
            const auto state = impl_->observe(call_id);
            if (required_string(state, "agent_id") != impl_->config.agent_id)
                throw std::runtime_error("Provider state identity rejected");
            previous_epoch = nonnegative_integer(state.at("epoch"));
            if (previous_epoch == std::numeric_limits<std::int64_t>::max())
                throw std::runtime_error("Provider generation exhausted");
            phase = "rotate";
            try {
                grant = impl_->request("POST", "/v1/rotate", {
                    {"task_id", task}, {"expected_epoch", previous_epoch},
                    {"format", format}, {"call", record.at("call")}, {"operation_id", operation_id}}, call_id);
                grant_observed = true;
                break;
            } catch (const RequestError& error) {
                // A definite rejected CAS has no effects. An ambiguous POST
                // response is never replayed, even if no child has started.
                if (error.status != 409 || error.code != "epoch_conflict" || attempt == 2) throw;
                std::this_thread::sleep_for(std::chrono::milliseconds(25 * (attempt + 1)));
            }
        }
        phase = "verify";
        if (required_string(grant, "operation_id") != operation_id ||
            required_string(grant, "task_id") != task || required_string(grant, "agent_id") != impl_->config.agent_id)
            throw std::runtime_error("Provider operation binding rejected");
        const auto operation_state = required_string(grant, "status");
        if (operation_state != "ready") {
            if (operation_state != "running" && operation_state != "succeeded" && operation_state != "failed" &&
                operation_state != "revoked" && operation_state != "expired")
                throw std::runtime_error("Provider operation state rejected");
            Json cached;
            if ((operation_state == "succeeded" || operation_state == "failed") &&
                grant.contains("receipt") && grant.at("receipt").is_object()) {
                cached = grant.at("receipt");
                if (!cached.contains("ok") || !cached.at("ok").is_boolean() ||
                    cached.at("ok").get<bool>() != (operation_state == "succeeded") ||
                    required_string(cached, "operation_id") != operation_id ||
                    cached.at("execution_id") != grant.at("execution_id"))
                    throw std::runtime_error("Provider cached receipt rejected");
                cached["original_call_id"] = cached.value("call_id", std::string{});
                cached["original_executor_started"] = cached.value("executor_started", false);
                cached["cached"] = true;
            } else {
                const auto code = operation_state == "running" ? "operation_in_progress" :
                    operation_state == "revoked" ? "operation_revoked" :
                    operation_state == "expired" ? "operation_expired" : "operation_result_unavailable";
                cached = {{"ok", false}, {"error", "Operation state requires reconciliation"}, {"error_code", code}};
                if (grant.contains("execution_id") && grant.at("execution_id").is_string())
                    cached["execution_id"] = grant.at("execution_id");
            }
            cached["call_id"] = call_id;
            cached["operation_id"] = operation_id;
            cached["operation_status"] = operation_state;
            cached["task_id"] = task;
            cached["epoch"] = grant.at("epoch");
            cached["phase"] = "reconcile";
            cached["replayed"] = true;
            cached["executor_started"] = false;
            cached["admission_uncertain"] = operation_state == "running";
            cached["completion_recorded"] = operation_state == "succeeded" || operation_state == "failed";
            cached["retry_safe"] = false;
            return cached.dump();
        }
        if (required_string(grant, "agent_id") != impl_->config.agent_id ||
            (!grant.value("replay", false) && nonnegative_integer(grant.at("epoch")) != previous_epoch + 1))
            throw std::runtime_error("Provider grant generation rejected");
        const auto token = required_string(grant, "token");
        const auto capability = impl_->verify(token, task, grant.at("epoch").get<std::int64_t>());
        phase = "admit";
        admission_uncertain = true;
        const auto admission = impl_->request("POST", "/v1/admit", {{"token", token}}, call_id);
        execution_id = required_string(admission, "execution_id");
        if (!identifier(execution_id, 48)) throw std::runtime_error("invalid execution identity");
        admission_uncertain = false;
        if (admission.at("capability") != capability)
            throw std::runtime_error("admission capability differs from signed capability");
        phase = "execute";
        result = detail::execute_child(capability, executor_started);
        if (!result.is_object() || !result.contains("ok") || !result.at("ok").is_boolean())
            throw std::runtime_error("invalid executor receipt");
        if (!result.at("ok").get<bool>() && !result.contains("error_code"))
            result["error_code"] = "execution_failed";
        result["epoch"] = grant.at("epoch");
        result["task_id"] = task;
    } catch (const RequestError& error) {
        if (phase == "admit" && error.status >= 400 && error.status < 500)
            admission_uncertain = false;
        result = {{"ok", false}, {"error", "Provider request failed"},
                  {"error_code", error.code}, {"http_status", error.status}};
        if (!error.request_id.empty()) result["request_id"] = error.request_id;
        if (phase == "rotate" && (error.status == 0 || error.status >= 500))
            result["provider_state_uncertain"] = true;
        if (error.code == "operation_conflict" || error.code == "execution_busy")
            result["operation_state_uncertain"] = true;
    } catch (const std::exception&) {
        const auto code = phase == "parse" ? "invalid_call" : phase == "verify" ? "invalid_capability" :
                          phase == "execute" ? "worker_failed" : "invalid_provider_response";
        result = {{"ok", false}, {"error", "Worker could not complete the call"}, {"error_code", code}};
    }
    if (result.contains("phase")) result["executor_phase"] = result.at("phase");
    result["phase"] = phase;
    result["call_id"] = call_id;
    if (!operation_id.empty()) result["operation_id"] = operation_id;
    result["admission_uncertain"] = admission_uncertain;
    result["completion_recorded"] = false;
    result["executor_started"] = executor_started;
    result["retry_safe"] = !grant_observed && !executor_started && !admission_uncertain && execution_id.empty() &&
                           !result.value("provider_state_uncertain", false) && !result.value("operation_state_uncertain", false);
    if (!execution_id.empty()) {
        result["execution_id"] = execution_id;
        const bool execution_ok = result.value("ok", false);
        Json completion = {{"execution_id", execution_id}, {"outcome", execution_ok ? "succeeded" : "failed"}};
        if (!execution_ok) {
            const auto code = result.value("error_code", std::string("execution_failed"));
            completion["failure_code"] = !executor_started ? "worker_failed" :
                code == "sandbox_setup_failed" ? "sandbox_setup_failed" :
                code == "executor_timeout" ? "worker_timeout" :
                code == "executor_protocol_failed" ? "invalid_worker_output" : "execution_failed";
        }
        // The receipt becomes authoritative in the same transaction that ends
        // the admission. A lost acknowledgement can then be reconciled by ID.
        auto receipt = result;
        receipt["completion_recorded"] = true;
        completion["receipt"] = std::move(receipt);
        try {
            for (unsigned int attempt = 0; ; ++attempt) {
                try {
                    const auto finished = impl_->request("POST", "/v1/finish", completion, call_id);
                    if (required_string(finished, "execution_id") != execution_id ||
                        finished.at("outcome") != completion.at("outcome") || finished.at("finished") != true)
                        throw std::runtime_error("invalid completion response");
                    break;
                } catch (const RequestError& error) {
                    if (!error.transport || attempt == 2) throw;
                    std::this_thread::sleep_for(std::chrono::milliseconds(25 * (attempt + 1)));
                }
            }
            result["completion_recorded"] = true;
        } catch (const std::exception&) {
            // Effects may already exist. Preserve that fact for the caller and
            // leave the durable gate closed until explicit operational repair.
            result["execution_ok"] = execution_ok;
            result["ok"] = false;
            result["finish_error"] = "Completion acknowledgement unavailable";
            result["error"] = "Execution completed but completion acknowledgement is uncertain";
            result["error_code"] = "completion_uncertain";
            result["phase"] = "finish";
        }
    }
    return result.dump();
}

std::string Worker::operation_status(const std::string& operation_id) {
    std::string call_id;
    Json result;
    try {
        validate_operation_id(operation_id);
        call_id = new_call_id();
        result = impl_->request("POST", "/v1/operation", {{"operation_id", operation_id}}, call_id);
        if (required_string(result, "operation_id") != operation_id ||
            required_string(result, "agent_id") != impl_->config.agent_id)
            throw std::runtime_error("Provider operation binding rejected");
        result["ok"] = true;
    } catch (const RequestError& error) {
        result = {{"ok", false}, {"error", "Operation status unavailable"}, {"error_code", error.code},
                  {"http_status", error.status}};
    } catch (const std::exception&) {
        result = {{"ok", false}, {"error", "Operation status could not be read"},
                  {"error_code", "invalid_operation_status"}};
    }
    result["call_id"] = call_id;
    result["phase"] = "reconcile";
    result["executor_started"] = false;
    return result.dump();
}

std::string Worker::revoke() {
    std::string call_id;
    Json result;
    try {
        call_id = new_call_id();
        for (unsigned int attempt = 0; ; ++attempt) {
            const auto state = impl_->observe(call_id);
            if (required_string(state, "agent_id") != impl_->config.agent_id)
                throw std::runtime_error("Provider state identity rejected");
            const auto epoch = nonnegative_integer(state.at("epoch"));
            if (epoch == std::numeric_limits<std::int64_t>::max())
                throw std::runtime_error("Provider generation exhausted");
            try {
                result = impl_->request("POST", "/v1/revoke", {{"expected_epoch", epoch}}, call_id);
                if (required_string(result, "agent_id") != impl_->config.agent_id ||
                    nonnegative_integer(result.at("epoch")) != epoch + 1 || result.at("revoked") != true)
                    throw std::runtime_error("Provider revocation response rejected");
                result["ok"] = true;
                break;
            } catch (const RequestError& error) {
                if (error.status != 409 || error.code != "epoch_conflict" || attempt == 2) throw;
            }
        }
    } catch (const RequestError& error) {
        result = {{"ok", false}, {"error", "Provider revocation request failed"},
                  {"error_code", error.code}, {"http_status", error.status},
                  {"provider_state_uncertain", error.status == 0 || error.status >= 500}};
        if (!error.request_id.empty()) result["request_id"] = error.request_id;
    } catch (const std::exception&) {
        result = {{"ok", false}, {"error", "Provider revocation could not be confirmed"},
                  {"error_code", "invalid_provider_response"}, {"provider_state_uncertain", true}};
    }
    result["call_id"] = call_id;
    result["phase"] = "revoke";
    result["executor_started"] = false;
    return result.dump();
}

std::string sandbox_probe(const std::string& specification) {
    return detail::probe_child(detail::Json::parse(specification)).dump();
}
} // namespace saga
