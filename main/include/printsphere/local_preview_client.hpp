#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "printsphere/config_store.hpp"

namespace printsphere {

// Cover image of the job the printer is running, read straight from the printer.
// LAN-started prints have no Bambu Cloud task, so the cloud cannot provide their cover.
// The project file is fetched over the printer's FTPS server (implicit TLS, port 990,
// user "bblp" + access code); only the zip central directory and the one
// Metadata/plate_N.png entry are transferred (ranged reads), not the whole .3mf.
struct LocalPreviewSnapshot {
  std::string job_key;  // bambu_job_match_key() of the job the cover belongs to
  std::string title;    // job name as reported by the printer
  std::shared_ptr<std::vector<uint8_t>> blob;  // PNG bytes, null when none
};

class LocalPreviewClient {
 public:
  LocalPreviewClient() = default;

  void configure(PrinterConnection connection);
  void set_network_ready(bool ready) { network_ready_.store(ready); }
  // Job currently reported by the printer; empty when there is none. Cheap to call often.
  void request(const std::string& job_name);
  esp_err_t start();
  LocalPreviewSnapshot snapshot() const;

 private:
  static void task_entry(void* context);
  void task_loop();
  bool fetch_cover(const PrinterConnection& connection, const std::string& job_name,
                   std::shared_ptr<std::vector<uint8_t>>* out_blob);

  TaskHandle_t task_handle_ = nullptr;
  std::atomic<bool> network_ready_{false};
  std::atomic<bool> reconfigure_requested_{false};

  mutable std::mutex mutex_{};
  PrinterConnection connection_{};
  std::string requested_job_{};
  LocalPreviewSnapshot snapshot_{};
};

}  // namespace printsphere
