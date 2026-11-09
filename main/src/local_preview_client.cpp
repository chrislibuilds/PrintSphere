#include "printsphere/local_preview_client.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_tls.h"
#include "printsphere/bambu_status.hpp"

namespace printsphere {

namespace {

constexpr char kTag[] = "printsphere.localpreview";
constexpr uint16_t kFtpsPort = 990;
constexpr size_t kMaxCoverBytes = 256U * 1024U;
constexpr size_t kZipTailBytes = 8192;
constexpr size_t kLocalHeaderMargin = 1024;  // local-header extra field is not in the directory
constexpr int64_t kReplyTimeoutUs = 6000000;
constexpr int64_t kDataTimeoutUs = 15000000;
constexpr uint32_t kMaxAttemptsPerJob = 5;

uint16_t le16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint32_t le32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

bool is_tls_retry(ssize_t result) {
  return result == ESP_TLS_ERR_SSL_WANT_READ || result == ESP_TLS_ERR_SSL_WANT_WRITE;
}

// Minimal FTPS client: implicit TLS on the control channel, TLS on the data channel
// resuming the control channel's session (the printer rejects data connections that do
// not reuse it).
class FtpsSession {
 public:
  FtpsSession() = default;
  FtpsSession(const FtpsSession&) = delete;
  FtpsSession& operator=(const FtpsSession&) = delete;
  ~FtpsSession() { close(); }

  bool open(const std::string& host, const std::string& user, const std::string& pass) {
    host_ = host;
    ctl_ = esp_tls_init();
    if (ctl_ == nullptr) {
      return false;
    }
    esp_tls_cfg_t cfg = make_cfg(nullptr);
    if (esp_tls_conn_new_sync(host_.c_str(), static_cast<int>(host_.size()), kFtpsPort, &cfg,
                              ctl_) != 1) {
      ESP_LOGW(kTag, "FTPS control connect failed");
      return false;
    }
    session_ = esp_tls_get_client_session(ctl_);
    if (session_ == nullptr) {
      ESP_LOGW(kTag, "No TLS session available for data channel reuse");
      return false;
    }

    int code = 0;
    if (!read_reply(&code, kReplyTimeoutUs) || code != 220) {
      ESP_LOGW(kTag, "FTPS banner missing (code=%d)", code);
      return false;
    }
    if (!command("USER " + user, &code) || (code != 331 && code != 230)) {
      return false;
    }
    if (code == 331) {
      if (!command("PASS " + pass, &code) || code != 230) {
        ESP_LOGW(kTag, "FTPS login rejected (code=%d)", code);
        return false;
      }
    }
    return command("PBSZ 0", &code) && code == 200 && command("PROT P", &code) && code == 200 &&
           command("TYPE I", &code) && code == 200;
  }

  bool size_of(const std::string& path, size_t* size) {
    int code = 0;
    if (!command("SIZE " + path, &code) || code != 213) {
      return false;
    }
    const size_t value = static_cast<size_t>(std::strtoull(reply_text_.c_str() + 4, nullptr, 10));
    if (value == 0) {
      return false;
    }
    *size = value;
    return true;
  }

  // Reads up to `want` bytes of `path` starting at `offset`; stops early at end of file.
  bool read_range(const std::string& path, size_t offset, size_t want,
                  std::vector<uint8_t>* out) {
    out->clear();
    int code = 0;
    if (!command("PASV", &code) || code != 227) {
      return false;
    }
    int a, b, c, d, p1, p2;
    const char* paren = std::strchr(reply_text_.c_str(), '(');
    if (paren == nullptr ||
        std::sscanf(paren, "(%d,%d,%d,%d,%d,%d)", &a, &b, &c, &d, &p1, &p2) != 6) {
      return false;
    }
    const uint16_t data_port = static_cast<uint16_t>((p1 << 8) | p2);

    if (offset > 0) {
      if (!command("REST " + std::to_string(offset), &code) || code != 350) {
        return false;
      }
    }
    // RETR goes out before the data connection is opened: the server only accepts (and
    // starts the data-channel TLS handshake) once it is processing the transfer.
    if (!send_line("RETR " + path)) {
      return false;
    }

    esp_tls_t* data = esp_tls_init();
    if (data == nullptr) {
      return false;
    }
    esp_tls_cfg_t cfg = make_cfg(session_);
    if (esp_tls_conn_new_sync(host_.c_str(), static_cast<int>(host_.size()), data_port, &cfg,
                              data) != 1) {
      ESP_LOGW(kTag, "FTPS data connect failed");
      esp_tls_conn_destroy(data);
      return false;
    }

    bool ok = read_reply(&code, kReplyTimeoutUs) && (code == 150 || code == 125);
    if (ok) {
      out->reserve(std::min<size_t>(want, kMaxCoverBytes + kLocalHeaderMargin + 64));
      std::vector<uint8_t> chunk(2048);
      const int64_t deadline = esp_timer_get_time() + kDataTimeoutUs;
      while (out->size() < want && esp_timer_get_time() < deadline) {
        const ssize_t n = esp_tls_conn_read(data, chunk.data(), chunk.size());
        if (n > 0) {
          out->insert(out->end(), chunk.begin(), chunk.begin() + n);
        } else if (n == 0) {
          break;  // end of file
        } else if (!is_tls_retry(n)) {
          // Peer closing without close_notify at EOF is normal for some servers.
          break;
        }
      }
      if (out->size() > want) {
        out->resize(want);
      }
    }
    esp_tls_conn_destroy(data);

    // 226 after a full transfer, 426 after we stopped early. Either way the control
    // channel stays usable; if the reply never comes, discard the session.
    int final_code = 0;
    if (!read_reply(&final_code, kReplyTimeoutUs)) {
      broken_ = true;
    }
    return ok && !out->empty();
  }

  bool broken() const { return broken_; }

  void close() {
    if (ctl_ != nullptr) {
      esp_tls_conn_destroy(ctl_);
      ctl_ = nullptr;
    }
    if (session_ != nullptr) {
      esp_tls_free_client_session(session_);
      session_ = nullptr;
    }
  }

 private:
  esp_tls_cfg_t make_cfg(esp_tls_client_session_t* session) const {
    esp_tls_cfg_t cfg = {};
    cfg.timeout_ms = 7000;
    cfg.skip_common_name = true;
    cfg.addr_family = ESP_TLS_AF_INET;
    cfg.tls_version = ESP_TLS_VER_TLS_1_2;
    cfg.client_session = session;
#if CONFIG_MBEDTLS_DYNAMIC_BUFFER
    cfg.esp_tls_dyn_buf_strategy = ESP_TLS_DYN_BUF_RX_STATIC;
#endif
    return cfg;
  }

  bool send_line(const std::string& line) {
    const std::string wire = line + "\r\n";
    size_t sent = 0;
    const int64_t deadline = esp_timer_get_time() + kReplyTimeoutUs;
    while (sent < wire.size() && esp_timer_get_time() < deadline) {
      const ssize_t n = esp_tls_conn_write(ctl_, wire.data() + sent, wire.size() - sent);
      if (n > 0) {
        sent += static_cast<size_t>(n);
      } else if (!is_tls_retry(n)) {
        return false;
      }
    }
    return sent == wire.size();
  }

  bool command(const std::string& line, int* code) {
    return send_line(line) && read_reply(code, kReplyTimeoutUs);
  }

  // Reads one complete (possibly multi-line) reply; leaves its last line in reply_text_.
  bool read_reply(int* code, int64_t timeout_us) {
    const int64_t deadline = esp_timer_get_time() + timeout_us;
    while (true) {
      size_t start = 0;
      while (true) {
        const size_t eol = rx_.find("\r\n", start);
        if (eol == std::string::npos) {
          break;
        }
        const std::string line = rx_.substr(start, eol - start);
        start = eol + 2;
        if (line.size() >= 4 && std::isdigit(static_cast<unsigned char>(line[0])) &&
            line[3] == ' ') {
          *code = std::atoi(line.substr(0, 3).c_str());
          reply_text_ = line;
          rx_.erase(0, start);
          return true;
        }
      }
      rx_.erase(0, start);
      if (esp_timer_get_time() >= deadline) {
        return false;
      }
      char buffer[256];
      const ssize_t n = esp_tls_conn_read(ctl_, buffer, sizeof(buffer));
      if (n > 0) {
        rx_.append(buffer, static_cast<size_t>(n));
      } else if (n == 0 || !is_tls_retry(n)) {
        return false;
      }
    }
  }

  std::string host_;
  esp_tls_t* ctl_ = nullptr;
  esp_tls_client_session_t* session_ = nullptr;
  std::string rx_;
  std::string reply_text_;
  bool broken_ = false;
};

struct ZipEntry {
  uint16_t method = 0;
  uint32_t compressed_size = 0;
  uint32_t local_header_offset = 0;
  uint16_t name_len = 0;
};

// Finds `wanted` in the zip central directory. `tail` holds the file's last bytes
// starting at file offset `tail_base`.
bool find_zip_entry(FtpsSession& ftp, const std::string& path, size_t file_size,
                    const std::vector<uint8_t>& tail, size_t tail_base,
                    const std::string& wanted, ZipEntry* entry) {
  // End-of-central-directory record: PK\5\6, 22 bytes + comment.
  size_t eocd = std::string::npos;
  for (size_t i = tail.size() >= 22 ? tail.size() - 22 : 0; i + 4 <= tail.size(); --i) {
    if (le32(&tail[i]) == 0x06054b50U) {
      eocd = i;
      break;
    }
    if (i == 0) {
      break;
    }
  }
  if (eocd == std::string::npos || eocd + 22 > tail.size()) {
    ESP_LOGW(kTag, "Zip end record not found");
    return false;
  }
  const uint32_t cd_size = le32(&tail[eocd + 12]);
  const uint32_t cd_offset = le32(&tail[eocd + 16]);
  if (cd_size == 0xFFFFFFFFU || cd_offset == 0xFFFFFFFFU || cd_size > 256U * 1024U ||
      static_cast<size_t>(cd_offset) + cd_size > file_size) {
    ESP_LOGW(kTag, "Zip directory unsupported (zip64 or invalid)");
    return false;
  }

  std::vector<uint8_t> cd_fetched;
  const uint8_t* cd = nullptr;
  if (cd_offset >= tail_base) {
    cd = tail.data() + (cd_offset - tail_base);
  } else {
    if (!ftp.read_range(path, cd_offset, cd_size, &cd_fetched) || cd_fetched.size() < cd_size) {
      ESP_LOGW(kTag, "Zip directory read failed");
      return false;
    }
    cd = cd_fetched.data();
  }

  size_t pos = 0;
  while (pos + 46 <= cd_size && le32(cd + pos) == 0x02014b50U) {
    const uint16_t name_len = le16(cd + pos + 28);
    const uint16_t extra_len = le16(cd + pos + 30);
    const uint16_t comment_len = le16(cd + pos + 32);
    if (pos + 46 + name_len > cd_size) {
      break;
    }
    if (name_len == wanted.size() &&
        std::memcmp(cd + pos + 46, wanted.data(), name_len) == 0) {
      entry->method = le16(cd + pos + 10);
      entry->compressed_size = le32(cd + pos + 20);
      entry->local_header_offset = le32(cd + pos + 42);
      entry->name_len = name_len;
      return entry->compressed_size != 0xFFFFFFFFU && entry->local_header_offset != 0xFFFFFFFFU;
    }
    pos += 46U + name_len + extra_len + comment_len;
  }
  return false;
}

// "Name_plate_2" -> 2, anything else -> 1.
int plate_number_for(const std::string& job_name) {
  const size_t pos = job_name.rfind("_plate_");
  if (pos == std::string::npos) {
    return 1;
  }
  const int n = std::atoi(job_name.c_str() + pos + 7);
  return n > 0 && n < 100 ? n : 1;
}

}  // namespace

void LocalPreviewClient::configure(PrinterConnection connection) {
  if (connection.mqtt_username.empty()) {
    connection.mqtt_username = "bblp";
  }
  {
    std::lock_guard<std::mutex> lock(mutex_);
    connection_ = std::move(connection);
    snapshot_ = LocalPreviewSnapshot{};
  }
  reconfigure_requested_.store(true);
}

void LocalPreviewClient::request(const std::string& job_name) {
  bool changed = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (requested_job_ != job_name) {
      requested_job_ = job_name;
      changed = true;
    }
  }
  if (changed && task_handle_ != nullptr) {
    xTaskNotifyGive(task_handle_);
  }
}

LocalPreviewSnapshot LocalPreviewClient::snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return snapshot_;
}

esp_err_t LocalPreviewClient::start() {
  if (task_handle_ != nullptr) {
    return ESP_OK;
  }
  // Stack in PSRAM for the same reason as the camera task: internal RAM is too
  // fragmented by this point for a 12 KiB contiguous allocation.
  const BaseType_t result = xTaskCreateWithCaps(&LocalPreviewClient::task_entry, "local_preview",
                                                12288, this, 3, &task_handle_,
                                                MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  return result == pdPASS ? ESP_OK : ESP_FAIL;
}

void LocalPreviewClient::task_entry(void* context) {
  static_cast<LocalPreviewClient*>(context)->task_loop();
}

void LocalPreviewClient::task_loop() {
  std::string done_key;     // job whose cover is already cached
  std::string attempt_key;  // job the failure counter belongs to
  uint32_t failures = 0;
  int64_t next_try_us = 0;

  while (true) {
    ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(2000));

    if (reconfigure_requested_.exchange(false)) {
      done_key.clear();
      attempt_key.clear();
      failures = 0;
      next_try_us = 0;
    }

    PrinterConnection connection;
    std::string job_name;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      connection = connection_;
      job_name = requested_job_;
    }
    if (!connection.is_ready() || !network_ready_.load() || job_name.empty()) {
      continue;
    }

    const std::string key = bambu_job_match_key(job_name);
    if (key.empty() || key == done_key) {
      continue;
    }
    if (key != attempt_key) {
      attempt_key = key;
      failures = 0;
      next_try_us = 0;
    }
    if (failures >= kMaxAttemptsPerJob || esp_timer_get_time() < next_try_us) {
      continue;
    }

    std::shared_ptr<std::vector<uint8_t>> blob;
    if (fetch_cover(connection, job_name, &blob) && blob != nullptr) {
      {
        std::lock_guard<std::mutex> lock(mutex_);
        snapshot_.job_key = key;
        snapshot_.title = job_name;
        snapshot_.blob = std::move(blob);
      }
      done_key = key;
    } else {
      ++failures;
      next_try_us = esp_timer_get_time() + static_cast<int64_t>(failures) * 15000000LL;
      ESP_LOGW(kTag, "Local cover fetch failed for '%s' (attempt %u/%u)", job_name.c_str(),
               static_cast<unsigned>(failures), static_cast<unsigned>(kMaxAttemptsPerJob));
    }
  }
}

bool LocalPreviewClient::fetch_cover(const PrinterConnection& connection,
                                     const std::string& job_name,
                                     std::shared_ptr<std::vector<uint8_t>>* out_blob) {
  if (job_name.size() > 200 || job_name.find_first_of("\r\n") != std::string::npos) {
    return false;
  }

  FtpsSession ftp;
  if (!ftp.open(connection.host, connection.mqtt_username, connection.access_code)) {
    return false;
  }

  // Studio stores LAN-sent projects at the storage root; check the other known
  // locations as well.
  std::string path;
  size_t file_size = 0;
  for (const char* dir : {"/", "/cache/", "/model/"}) {
    for (const char* suffix : {".gcode.3mf", ".3mf"}) {
      const std::string candidate = std::string(dir) + job_name + suffix;
      if (ftp.size_of(candidate, &file_size)) {
        path = candidate;
        break;
      }
      if (ftp.broken()) {
        return false;
      }
    }
    if (!path.empty()) {
      break;
    }
  }
  if (path.empty()) {
    ESP_LOGW(kTag, "Project file for '%s' not found on printer", job_name.c_str());
    return false;
  }

  const size_t tail_len = std::min(file_size, kZipTailBytes);
  const size_t tail_base = file_size - tail_len;
  std::vector<uint8_t> tail;
  if (!ftp.read_range(path, tail_base, tail_len, &tail) || tail.size() < tail_len) {
    ESP_LOGW(kTag, "Zip tail read failed");
    return false;
  }

  ZipEntry entry;
  const int plate = plate_number_for(job_name);
  bool found = find_zip_entry(ftp, path, file_size, tail, tail_base,
                              "Metadata/plate_" + std::to_string(plate) + ".png", &entry);
  if (!found && plate != 1) {
    found = find_zip_entry(ftp, path, file_size, tail, tail_base, "Metadata/plate_1.png", &entry);
  }
  if (!found) {
    ESP_LOGW(kTag, "Cover entry not found in project file");
    return false;
  }
  if (entry.method != 0) {
    ESP_LOGW(kTag, "Cover is compressed (method %u); not supported", entry.method);
    return false;
  }
  if (entry.compressed_size == 0 || entry.compressed_size > kMaxCoverBytes) {
    ESP_LOGW(kTag, "Cover size %u out of range", static_cast<unsigned>(entry.compressed_size));
    return false;
  }

  const size_t want = std::min<size_t>(
      30U + entry.name_len + kLocalHeaderMargin + entry.compressed_size,
      file_size - entry.local_header_offset);
  std::vector<uint8_t> raw;
  if (!ftp.read_range(path, entry.local_header_offset, want, &raw) || raw.size() < 30 ||
      le32(raw.data()) != 0x04034b50U) {
    ESP_LOGW(kTag, "Cover local header read failed");
    return false;
  }
  const size_t data_start = 30U + le16(&raw[26]) + le16(&raw[28]);
  if (data_start + entry.compressed_size > raw.size()) {
    ESP_LOGW(kTag, "Cover data truncated");
    return false;
  }
  static const uint8_t kPngMagic[8] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
  if (std::memcmp(&raw[data_start], kPngMagic, sizeof(kPngMagic)) != 0) {
    ESP_LOGW(kTag, "Cover is not a PNG");
    return false;
  }

  *out_blob = std::make_shared<std::vector<uint8_t>>(raw.begin() + data_start,
                                                     raw.begin() + data_start +
                                                         entry.compressed_size);
  ESP_LOGI(kTag, "Local cover for '%s': %u bytes (plate %d)", job_name.c_str(),
           static_cast<unsigned>(entry.compressed_size), plate);
  return true;
}

}  // namespace printsphere
