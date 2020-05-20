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

#include "mqtts.h"
#include "smooth/core/task_priorities.h"

#include "smooth/core/network/Wifi.h"
#include "wifi_creds.h"

using namespace smooth;
using namespace smooth::core;
using namespace smooth::core::logging;
using namespace std::chrono;
using namespace smooth::application::network::mqtt;


    constexpr const char* const cert =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDjzCCAnegAwIBAgIUQ1AagVQXCuOIzmGXm+KhsbyBc18wDQYJKoZIhvcNAQEN\n"
        "BQAwVzESMBAGA1UEAwwJbG9jYWxob3N0MREwDwYDVQQKDAhNYWluZmx1eDEMMAoG\n"
        "A1UECwwDSW9UMSAwHgYJKoZIhvcNAQkBFhFpbmZvQG1haW5mbHV4LmNvbTAeFw0x\n"
        "OTA0MDEwOTI3MDFaFw0yMjAzMzEwOTI3MDFaMFcxEjAQBgNVBAMMCWxvY2FsaG9z\n"
        "dDERMA8GA1UECgwITWFpbmZsdXgxDDAKBgNVBAsMA0lvVDEgMB4GCSqGSIb3DQEJ\n"
        "ARYRaW5mb0BtYWluZmx1eC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n"
        "AoIBAQCq6O4PHwgGOmEafjea5KocG80GYSYbvN37ums6fQ1wcmCxn8LtZek8WkfJ\n"
        "S2NQQPDvn8QWRY7aUkTAW7cEB4vxpT25bevP7KJNFAS8XZO7NTfF8fscJS+YWSXz\n"
        "VS0OFZ2YuqTnjCiqWf5mvjAkkXBGIYq+k2ONM1tHlEA0lzbLun2a9H/XarCG+znj\n"
        "pfYpW6R08zFzXyGb4sI2pyYpP7iZLla7PTSZTt9h6jkY3qqMDhEHhPdlXDhO1O9/\n"
        "lA8yWMO9vKCzC7ngDXnV99Nl+tFhp9z9VkTUveLMuN9+riDJRfP25fOzHuRYzmsR\n"
        "emYjD1NvSgsvFqSbFDVXB8kcyrXPAgMBAAGjUzBRMB0GA1UdDgQWBBRs4xR91qEj\n"
        "NRGmw391xS7x6Tc+8jAfBgNVHSMEGDAWgBRs4xR91qEjNRGmw391xS7x6Tc+8jAP\n"
        "BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4IBAQAAPMf7bVFhzUG8AYq0\n"
        "VS9BWVwVtdNzZ3X9FkG9O+tZZO43GlaToym8PmhJHF9wk3AA+pmgfcmBrHcTG0me\n"
        "PeincN2euO0c4iv1f/i4bAY5/iq/Q0w/GiuTL5VLVpaH1SQrWhc0ZD7Ii+lVPpFQ\n"
        "bJXKHFQBnZU7mWeQnL9W1SVhWfsSKShBkAEUeGXo3YMC7nYsFJkl/heC3sYqfrW4\n"
        "7fq80u+TU6HjGetSAWKacae7eeNmprMn0lFw2VqPQG3M4M0l9pEfcrRygOAnqNKO\n"
        "aNi2UYKBla3XeDjObovOsXRScTKmJZwJ/STJlu+x5UAwF34ZBJy0O2qdd+kOxAhj\n"
        "5Yq2\n"
        "-----END CERTIFICATE-----\n";

namespace mqtts
{
    static const char* broker = "192.168.1.49";
#ifdef ESP_PLATFORM
    static const char* client_id = "ESP32";
#else
    static const char* client_id = "Linux";
#endif

    App::App()
            : Application(APPLICATION_BASE_PRIO, seconds(10)),
              mqtt_data(MQTTDataQueue::create(10, *this, *this)),
              client(client_id, seconds(10), 8192, 10, mqtt_data)
    {
    }

    std::unique_ptr<std::vector<unsigned char>> App::get_certs() const
    {
        auto ca_cert = std::make_unique<std::vector<unsigned char>>();

        for (size_t i = 0; i < strlen(cert); ++i)
        {
            ca_cert->push_back(static_cast<unsigned char>(cert[i]));
        }

        // the mbedtls_x509_crt_parse function wants the size of the buffer, including the terminating 0 so we
        // add that too.
        ca_cert->push_back('\0');

        return ca_cert;
    }

    void App::init()
    {
        Application::init();

        Log::info("App::Init", "Starting wifi...");
        network::Wifi& wifi = get_wifi();
        wifi.set_host_name("Smooth-ESP");
        wifi.set_auto_connect(true);
        wifi.set_ap_credentials(WIFI_SSID, WIFI_PASSWORD);
        wifi.connect_to_ap();
        
        auto ca_cert = get_certs();

        client.load_certificate(*ca_cert);

        client.set_authorization(
            "9c3af059-0c76-48af-a02d-7e12804c14d5",
            "6979a49a-17ea-4ceb-bb33-eb3d6bb14481");

        client.connect_to(std::make_shared<smooth::core::network::IPv4>(broker, 8883), true);
        client.subscribe("test", QoS::AT_LEAST_ONCE);
        client.subscribe("test", QoS::AT_MOST_ONCE);
        send_message();
    }

    void App::event(const smooth::application::network::mqtt::MQTTData& event)
    {
        std::stringstream ss{};
        std::for_each(event.second.begin(), event.second.end(), [&ss](auto c) { ss << static_cast<char>(c);});
        Log::info("Rec", "T:{}, M:{}", event.first, ss.str());

        send_message();
    }

    void App::tick()
    {
        std::string payload = "[{\"bn\":\"hi:\",\"bt\":1.5, \"bu\":\"A\",\"bver\":5, \"n\":\"voltage\",\"u\":\"V\",\"v\":120.1}, {\"n\":\"current\",\"t\":-5,\"v\":1.2}, {\"n\":\"current\",\"t\":-4,\"v\":1.3}]";

        client.publish("test", payload, QoS::AT_LEAST_ONCE, false);
    }

    void App::send_message()
    {
        static uint32_t len = 0;

        std::string rep(len, 'Q');
        auto v = dis(gen);
        std::string payload = "[{\"bn\":\"hi:\",\"bt\":1.5, \"bu\":\"A\",\"bver\":5, \"n\":\"voltage\",\"u\":\"V\",\"v\":120.1}, {\"n\":\"current\",\"t\":-5,\"v\":1.2}, {\"n\":\"current\",\"t\":-4,\"v\":1.3}]";

        if (v == 1)
        {
            client.publish("test", payload, QoS::AT_LEAST_ONCE, false);
        }
        else if (v == 2)
        {
            client.publish("test", payload, QoS::AT_MOST_ONCE, false);
        }
        else
        {
            client.publish("test", payload, QoS::AT_LEAST_ONCE, false);
        }

        if (++len == 3000)
        {
            len = 1;
        }
    }
}
