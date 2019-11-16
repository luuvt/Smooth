// Copyright 2019 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//         http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdint.h>
#include <string.h>
#include "esp_log.h"
#include "esp_event_base.h"
#include "esp_smartconfig.h"

static void handler_got_ssid_passwd(void *arg, esp_event_base_t base, int32_t event_id, void *data)
{
}

esp_err_t esp_smartconfig_start(const smartconfig_start_config_t *config)
{
    return ESP_OK;
}

esp_err_t esp_smartconfig_stop(void)
{
    return ESP_OK;
}