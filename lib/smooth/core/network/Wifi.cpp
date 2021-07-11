/*
Smooth - A C++ framework for embedded programming on top of Espressif's ESP-IDF
Copyright 2019 Per Malmberg (https://gitbub.com/PerMalmberg)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <cstring>
#include <sstream>
#include <iostream>
#include <chrono>
#include <thread>
#include "smooth/core/network/Wifi.h"
#include "smooth/core/network/NetworkStatus.h"
#include "smooth/core/ipc/Publisher.h"
#include "smooth/core/util/copy_min_to_buffer.h"
#include "smooth/core/logging/log.h"

#ifdef ESP_PLATFORM
#include "sdkconfig.h"
static_assert(CONFIG_ESP_SYSTEM_EVENT_TASK_STACK_SIZE >= 3072,
"Need enough stack to be able to log in the event loop callback.");
#endif

using namespace smooth::core::util;
using namespace smooth::core;

namespace smooth::core::network
{
    esp_netif_ip_info_t Wifi::ip_info;

    static void get_device_service_name(char *service_name, size_t max)
    {
        uint8_t eth_mac[6];
        const char *ssid_prefix = "SKYT_";
        // const char *ssid_prefix = "PROV_";
        esp_wifi_get_mac(WIFI_IF_STA, eth_mac);
        snprintf(service_name, max, "%s%02X%02X%02X",
                ssid_prefix, eth_mac[3], eth_mac[4], eth_mac[5]);
    }

    /* Handler for the optional provisioning endpoint registered by the application.
    * The data format can be chosen by applications. Here, we are using plain ascii text.
    * Applications can choose to use other formats like protobuf, JSON, XML, etc.
    */
    esp_err_t custom_prov_data_handler(uint32_t session_id, const uint8_t *inbuf, ssize_t inlen,
                                            uint8_t **outbuf, ssize_t *outlen, void *priv_data)
    {
        if (inbuf) {
            Log::info("Application", "Received data: ");
        }
        std::string response = "SUCCESS";
        *outbuf = reinterpret_cast<uint8_t*>(const_cast<char*>(response.c_str()));
        if (*outbuf == NULL) {
            Log::info("Application", "System out of memory");
            return ESP_ERR_NO_MEM;
        }
        *outlen = ssize_t(response.length() + 1); /* +1 for NULL terminating byte */

        return ESP_OK;
    }

    Wifi::Wifi()
    {
        esp_netif_init();

        esp_event_handler_instance_register(WIFI_PROV_EVENT,
                                           ESP_EVENT_ANY_ID,
                                           &Wifi::wifi_event_callback,
                                           this,
                                           &instance_wifi_event);

        esp_event_handler_instance_register(IP_EVENT,
                                           IP_EVENT_STA_GOT_IP,
                                           &Wifi::wifi_event_callback,
                                           this,
                                           &instance_ip_event);

        esp_event_handler_instance_register(WIFI_EVENT,
                                           ESP_EVENT_ANY_ID,
                                           &Wifi::wifi_event_callback,
                                           this,
                                           &instance_wifi_event);

        esp_event_handler_instance_register(SC_EVENT,
                                           ESP_EVENT_ANY_ID,
                                           &Wifi::wifi_event_callback,
                                           this,
                                           &instance_wifi_event);
    }

    Wifi::~Wifi()
    {
        esp_event_handler_instance_unregister(WIFI_PROV_EVENT, ESP_EVENT_ANY_ID, instance_wifi_event);
        esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_ip_event);
        esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_wifi_event);
        esp_event_handler_instance_unregister(SC_EVENT, ESP_EVENT_ANY_ID, instance_wifi_event);
        esp_wifi_disconnect();
        esp_wifi_stop();
        esp_wifi_deinit();
        esp_netif_deinit();
    }

    void Wifi::set_host_name(const std::string& name)
    {
        host_name = name;
    }

    void Wifi::set_ap_credentials(const std::string& wifi_ssid, const std::string& wifi_password)
    {
        this->ssid = wifi_ssid;
        this->password = wifi_password;
    }

    void Wifi::set_auto_connect(bool auto_connect)
    {
        auto_connect_to_ap = auto_connect;
    }

    void Wifi::connect_to_ap()
    {
        // Prepare to connect to the provided SSID and password
        wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
        esp_wifi_init(&init);
        esp_wifi_set_mode(WIFI_MODE_STA);

        wifi_config_t config;
        memset(&config, 0, sizeof(config));
        copy_min_to_buffer(ssid.begin(), ssid.length(), config.sta.ssid);
        copy_min_to_buffer(password.begin(), password.length(), config.sta.password);

        config.sta.bssid_set = false;

        // Store Wifi settings in flash - it is the applications responsibility to store settings.
        esp_wifi_set_storage(WIFI_STORAGE_RAM); // WIFI_STORAGE_RAM
        esp_wifi_set_config(WIFI_IF_STA, &config);

        close_if();
        interface = esp_netif_create_default_wifi_sta();

        connect();
    }

    void Wifi::connect() const
    {
#ifdef ESP_PLATFORM
        esp_wifi_start();
        esp_wifi_connect();
#else

        // Assume network is available when running under POSIX system.
        publish_status(true, true);
#endif
    }

    bool Wifi::is_connected_to_ap() const
    {
        return connected_to_ap;
    }

    void Wifi::wifi_event_callback(void* event_handler_arg,
                                   esp_event_base_t event_base,
                                   int32_t event_id,
                                   void* event_data)
    {
        // Note: be very careful with what you do in this method - it runs under the event task
        // (sys_evt) with a very small default stack.
        Wifi* wifi = reinterpret_cast<Wifi*>(event_handler_arg);
        // Log::info("event_base", " {}", event_base);
        // Log::info("event_id", " {}", event_id);
        if (event_base == WIFI_EVENT)
        {
            if (event_id == WIFI_EVENT_STA_START)
            {
                Log::info("event", "WIFI_EVENT_STA_START");
                if (!wifi->is_smartconfig && wifi->interface) {
                    esp_netif_set_hostname(wifi->interface, wifi->host_name.c_str());
                }
            }
            else if (event_id == WIFI_EVENT_STA_CONNECTED)
            {
                wifi->connected_to_ap = true;
            }
            else if (event_id == WIFI_EVENT_STA_DISCONNECTED)
            {
                wifi->ip_info.ip.addr = 0;
                wifi->ip_info.netmask = wifi->ip_info.ip;
                wifi->ip_info.gw = wifi->ip_info.ip;

                wifi->connected_to_ap = false;
                publish_status(wifi->connected_to_ap, true);

                if (wifi->auto_connect_to_ap)
                {
                    esp_wifi_stop();
                    wifi->connect();
                }
            }
            else if (event_id == WIFI_EVENT_AP_START)
            {
                wifi->ip_info.ip.addr = 0xC0A80401; // 192.168.4.1
                publish_status(true, true);
            }
            else if (event_id == WIFI_EVENT_AP_STOP)
            {
                wifi->ip_info.ip.addr = 0;
                wifi->ip_info.netmask = wifi->ip_info.ip;
                wifi->ip_info.gw = wifi->ip_info.ip;
                Log::info("SoftAP", "AP stopped");
                publish_status(false, true);
            }
            else if (event_id == WIFI_EVENT_AP_STACONNECTED)
            {
                auto data = reinterpret_cast<wifi_event_ap_staconnected_t*>(event_data);
                Log::info("SoftAP", "Station connected. MAC: {}:{}:{}:{}:{}:{} join, AID={}",
                                         data->mac[0],
                                         data->mac[1],
                                         data->mac[2],
                                         data->mac[3],
                                         data->mac[4],
                                         data->mac[5],
                                         data->aid);
            }
            else if (event_id == WIFI_EVENT_AP_STADISCONNECTED)
            {
                auto data = reinterpret_cast<wifi_event_ap_stadisconnected_t*>(event_data);

                Log::info("SoftAP", "Station disconnected. MAC: {}:{}:{}:{}:{}:{} join, AID={}",
                                         data->mac[0],
                                         data->mac[1],
                                         data->mac[2],
                                         data->mac[3],
                                         data->mac[4],
                                         data->mac[5],
                                         data->aid);
            }
        }
        else if (event_base == IP_EVENT)
        {
            if (event_id == IP_EVENT_STA_GOT_IP
                || event_id == IP_EVENT_GOT_IP6
                || event_id == IP_EVENT_ETH_GOT_IP)
            {
                auto ip_changed = event_id == IP_EVENT_STA_GOT_IP ?
                                  reinterpret_cast<ip_event_got_ip_t*>(event_data)->ip_changed : true;
                publish_status(true, ip_changed);
                wifi->ip_info = reinterpret_cast<ip_event_got_ip_t*>(event_data)->ip_info;
            }
            else if (event_id == IP_EVENT_STA_LOST_IP)
            {
                wifi->ip_info.ip.addr = 0;
                wifi->ip_info.netmask = wifi->ip_info.ip;
                wifi->ip_info.gw = wifi->ip_info.ip;
                publish_status(false, true);
            }
        }
        else if (event_base == SC_EVENT) 
        {
            if (event_id == SC_EVENT_SCAN_DONE)
            {
                Log::info("Application", "Scan done");
            }
            else if (event_id == SC_EVENT_FOUND_CHANNEL)
            {
                Log::info("Application", "Found channel");
            }
            else if (event_id == SC_EVENT_GOT_SSID_PSWD)
            {
                Log::info("Application", "Got SSID and password");
                smartconfig_event_got_ssid_pswd_t *evt = 
                    reinterpret_cast<smartconfig_event_got_ssid_pswd_t *>(event_data);
                
                Log::info("Application", "ssid: {}", evt->ssid);
                Log::info("Application", "password: {}", evt->password);
                
                wifi_config_t config;
                memset(&config, 0, sizeof(config));

                memcpy(config.sta.ssid, evt->ssid, sizeof(config.sta.ssid));
                memcpy(config.sta.password, evt->password, sizeof(config.sta.password));

                config.sta.bssid_set = evt->bssid_set;
                if (config.sta.bssid_set == true) {
                    memcpy(config.sta.bssid, evt->bssid, sizeof(config.sta.bssid));
                }

                // Store Wifi settings in RAM - it is the applications responsibility to store settings.
                esp_wifi_set_storage(WIFI_STORAGE_RAM);
                ESP_ERROR_CHECK( esp_wifi_disconnect() );
                esp_wifi_set_config(WIFI_IF_STA, &config);
                esp_wifi_connect();
                wifi->is_smartconfig = false;
            }
            else if (event_id == SC_EVENT_SEND_ACK_DONE)
            {
                Log::info("Application", "send ack done");
                esp_smartconfig_stop();
            }
        }
        else if (event_base == WIFI_PROV_EVENT) {
            switch (event_id) {
                case WIFI_PROV_START:
                    Log::info("Application", "Provisioning started");
                    break;
                case WIFI_PROV_CRED_RECV: {
                    wifi_sta_config_t *wifi_sta_cfg = 
                        reinterpret_cast<wifi_sta_config_t *>(event_data);
                
                    Log::info("Application", "Received Wi-Fi credentials");
                    Log::info("Application", "ssid: {}", wifi_sta_cfg->ssid);
                    Log::info("Application", "password: {}", wifi_sta_cfg->password);
                    
                    wifi_prov_mgr_deinit();

                    wifi_config_t config;
                    memset(&config, 0, sizeof(config));

                    memcpy(config.sta.ssid, wifi_sta_cfg->ssid, sizeof(config.sta.ssid));
                    memcpy(config.sta.password, wifi_sta_cfg->password, sizeof(config.sta.password));

                    config.sta.bssid_set = false;
                    esp_wifi_set_config(WIFI_IF_STA, &config);
                    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
                    esp_wifi_stop();
                    wifi->connect();
                    break;
                }
                case WIFI_PROV_CRED_FAIL: {
                    wifi_prov_sta_fail_reason_t *reason =
                        reinterpret_cast<wifi_prov_sta_fail_reason_t *>(event_data);
                    Log::info("Application", "Provisioning failed!\n\tReason : {0}"
                            "\n\tPlease reset to factory and retry provisioning",
                            (*reason == WIFI_PROV_STA_AUTH_ERROR) ?
                            "Wi-Fi station authentication failed" : "Wi-Fi access-point not found");
                    break;
                }
                case WIFI_PROV_CRED_SUCCESS:
                    Log::info("Application", "Provisioning successful");
                    break;
                case WIFI_PROV_END:
                    /* De-initialize manager once provisioning is finished */
                    wifi_prov_mgr_deinit();
                    break;
                default:
                    break;
            }
        }
    }

    void Wifi::start_smartconfig()
    {
#ifdef ESP_PLATFORM
        is_smartconfig = true;
        esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
        assert(sta_netif);
        wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
        esp_wifi_init(&init);
        esp_wifi_set_mode(WIFI_MODE_STA);
        esp_wifi_start();
        
        std::this_thread::sleep_for(std::chrono::seconds{ 1 });

        ESP_ERROR_CHECK( esp_smartconfig_set_type(SC_TYPE_ESPTOUCH) );
        smartconfig_start_config_t cfg = SMARTCONFIG_START_CONFIG_DEFAULT();
        ESP_ERROR_CHECK( esp_smartconfig_start(&cfg) );
#endif
    }

    void Wifi::start_provision()
    {
        /* Initialize Wi-Fi including netif with default config */
        esp_netif_create_default_wifi_sta();
        esp_netif_create_default_wifi_ap();
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        ESP_ERROR_CHECK(esp_wifi_init(&cfg));

        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wmissing-field-initializers" 
        /* Configuration for the provisioning manager */
        static wifi_prov_mgr_config_t config = {
            .scheme = wifi_prov_scheme_softap,
            .scheme_event_handler = WIFI_PROV_EVENT_HANDLER_NONE
        };
        /* Initialize provisioning manager with the
        * configuration parameters set above */
        ESP_ERROR_CHECK(wifi_prov_mgr_init(config));

        #pragma GCC diagnostic pop


        bool provisioned = false;
        /* Let's find out if the device is provisioned */
        // ESP_ERROR_CHECK(wifi_prov_mgr_is_provisioned(&provisioned));

        /* If device is not yet provisioned start provisioning service */
        if (!provisioned) {
            publish_status(false, true);
            Log::info("Application",  "Starting provisioning");

            /* What is the Device Service Name that we want
            * This translates to :
            *     - Wi-Fi SSID when scheme is wifi_prov_scheme_softap
            *     - device name when scheme is wifi_prov_scheme_ble
            */
            char service_name[12];
            get_device_service_name(service_name, sizeof(service_name));

            /* What is the security level that we want (0 or 1):
            *      - WIFI_PROV_SECURITY_0 is simply plain text communication.
            *      - WIFI_PROV_SECURITY_1 is secure communication which consists of secure handshake
            *          using X25519 key exchange and proof of possession (pop) and AES-CTR
            *          for encryption/decryption of messages.
            */
            wifi_prov_security_t security = WIFI_PROV_SECURITY_1;

            /* Do we want a proof-of-possession (ignored if Security 0 is selected):
            *      - this should be a string with length > 0
            *      - NULL if not used
            */
            const char *pop = "skytech@";
            // const char *pop = "abcd1234";
            
            /* What is the service key (could be NULL)
            * This translates to :
            *     - Wi-Fi password when scheme is wifi_prov_scheme_softap
            *     - simply ignored when scheme is wifi_prov_scheme_ble
            */
            const char *service_key = NULL;

            /* An optional endpoint that applications can create if they expect to
            * get some additional custom data during provisioning workflow.
            * The endpoint name can be anything of your choice.
            * This call must be made before starting the provisioning.
            */
            wifi_prov_mgr_endpoint_create("custom-data");
            /* Start provisioning service */
            wifi_prov_mgr_start_provisioning(security, pop, service_name, service_key);

            /* The handler for the optional endpoint created above.
            * This call must be made after starting the provisioning, and only if the endpoint
            * has already been created above.
            */
            wifi_prov_mgr_endpoint_register("custom-data", custom_prov_data_handler, NULL);

            /* Uncomment the following to wait for the provisioning to finish and then release
            * the resources of the manager. Since in this case de-initialization is triggered
            * by the default event loop handler, we don't need to call the following */
            // wifi_prov_mgr_wait();
            // wifi_prov_mgr_deinit();
        } else {
            Log::info("Application", "Already provisioned, starting Wi-Fi STA");

            /* We don't need the manager as device is already provisioned,
            * so let's release it's resources */
            wifi_prov_mgr_deinit();

            /* Start Wi-Fi in station mode */
            ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
            ESP_ERROR_CHECK(esp_wifi_start());
        }
    }

    std::tuple<bool, std::string, std::string> Wifi::get_config()
    {
        /* Get Wi-Fi Station configuration */
        wifi_config_t wifi_cfg;

        if (esp_wifi_get_config(WIFI_IF_STA, &wifi_cfg) != ESP_OK) {
            Log::error("Wifi", "wifi get config failed ssid: {} password: {}", 
                wifi_cfg.sta.ssid, wifi_cfg.sta.password);
            return std::make_tuple( false, "", "");
        }

        std::string wifi_ssid = reinterpret_cast<char*>(wifi_cfg.sta.ssid);
        std::string wifi_password = reinterpret_cast<char*>(wifi_cfg.sta.password);

        return std::make_tuple(true, std::move(wifi_ssid),std::move(wifi_password));
    }

    int Wifi::get_rssi()
    {
        #ifdef ESP_PLATFORM
        wifi_ap_record_t ap;
        esp_wifi_sta_get_ap_info(&ap);
        return ap.rssi;
        #else
        return 0;
        #endif
    }

    void Wifi::close_if()
    {
        if (interface)
        {
            esp_netif_destroy(interface);
            interface = nullptr;
        }
    }

    std::string Wifi::get_mac_address()
    {
        std::stringstream mac;

        std::array<uint8_t, 6> m;
        bool ret = get_local_mac_address(m);

        if (ret)
        {
            for (const auto& v : m)
            {
                if (mac.tellp() > 0)
                {
                    mac << "_";
                }

                mac << std::hex << static_cast<int>(v);
            }
        }

        return mac.str();
    }

    bool Wifi::get_local_mac_address(std::array<uint8_t, 6>& m)
    {
        wifi_mode_t mode;
        esp_err_t err = esp_wifi_get_mode(&mode);

        if (err == ESP_OK)
        {
            if (mode == WIFI_MODE_STA)
            {
                err = esp_wifi_get_mac(WIFI_IF_STA, m.data());
            }
            else if (mode == WIFI_MODE_AP)
            {
                err = esp_wifi_get_mac(WIFI_IF_AP, m.data());
            }
            else
            {
                err = ESP_FAIL;
            }
        }

        if (err != ESP_OK)
        {
            Log::error("Wifi", "get_local_mac_address(): {}", esp_err_to_name(err));
        }

        return err == ESP_OK;
    }

    // attention: access to this function might have a threading issue.
    // It should be called from the main thread only!
    uint32_t Wifi::get_local_ip()
    {
        return ip_info.ip.addr;
    }

    std::string Wifi::get_local_ip_address()
    {
        std::array<char, 16> str_ip;

        return esp_ip4addr_ntoa(&ip_info.ip, str_ip.data(), 16);
    }

    std::string Wifi::get_netmask()
    {
        std::array<char, 16> str_mask;

        return esp_ip4addr_ntoa(&ip_info.netmask, str_mask.data(), 16);
    }

    std::string Wifi::get_gateway()
    {
        std::array<char, 16> str_gw;

        return esp_ip4addr_ntoa(&ip_info.gw, str_gw.data(), 16);
    }

    void Wifi::start_softap(uint8_t max_conn)
    {
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        esp_wifi_init(&cfg);

        wifi_config_t config{};

        copy_min_to_buffer(ssid.begin(), ssid.length(), config.ap.ssid);
        copy_min_to_buffer(password.begin(), password.length(), config.ap.password);

        config.ap.max_connection = max_conn;
        config.ap.authmode = password.empty() ? WIFI_AUTH_OPEN : WIFI_AUTH_WPA_WPA2_PSK;

        close_if();
        interface = esp_netif_create_default_wifi_ap();

        esp_wifi_set_mode(WIFI_MODE_AP);
        esp_wifi_set_config(WIFI_IF_AP, &config);
        esp_wifi_start();

        Log::info("SoftAP", "SSID: {}; Auth {}", ssid, (password.empty() ? "Open" : "WPA2/PSK"));

#ifndef ESP_PLATFORM

        // Assume network is available when running under POSIX system.
        publish_status(true, true);
#endif
    }

    void Wifi::publish_status(bool connected, bool ip_changed)
    {
        network::NetworkStatus status(connected
                                      ? network::NetworkEvent::GOT_IP : network::NetworkEvent::DISCONNECTED,
                                      ip_changed);
        core::ipc::Publisher<network::NetworkStatus>::publish(status);
    }
}
