//
// Created by permal on 8/19/17.
//

#include <algorithm>
#include <smooth/core/Task.h>
#include <smooth/core/io/i2c/I2CMasterDevice.h>
#include <smooth/core/io/i2c/I2CCommandLink.h>
#include "esp_log.h"
#include "esp_intr_alloc.h"

namespace smooth
{
    namespace core
    {
        namespace io
        {
            namespace i2c
            {
                // Understanding I2C: http://www.ti.com/lit/an/slva704/slva704.pdf
                // I2C specification: http://www.nxp.com/docs/en/user-guide/UM10204.pdf

                static const char* log_tag = "I2CMasterDevice";
                static const std::chrono::milliseconds timeout(1000);

                bool I2CMasterDevice::write(uint8_t address, std::vector<uint8_t>& data, bool enable_ack)
                {
                    I2CCommandLink link(*this);

                    // Set R/W bit to 0 for write.
                    address = address << 1;

                    auto res = i2c_master_start(link);
                    res |= i2c_master_write_byte(link, address, enable_ack);
                    res |= i2c_master_write(link, data.data(), data.size(), enable_ack);
                    res |= i2c_master_stop(link);

                    bool write_result = false;

                    if (res == ESP_OK)
                    {
                        res = i2c_master_cmd_begin(port, link, Task::to_tick(timeout));
                        log_error(res, "Error during write");
                        write_result = res == ESP_OK;
                    }
                    else
                    {
                        log_error(res, "Failed to prepare write");
                    }

                    if (!write_result)
                    {
                        i2c_reset_tx_fifo(port);
                        i2c_reset_rx_fifo(port);
                    }

                    return write_result;
                }

                bool I2CMasterDevice::read(uint8_t address, uint8_t slave_register,
                                           core::util::FixedBufferBase<uint8_t>& data)
                {
                    I2CCommandLink link(*this);

                    // Set R/W bit to 0 for write.
                    uint8_t write_address = address << 1;
                    // Set R/W bit to 1 for read.
                    uint8_t read_address = (address << 1) | 0x1;

                    // Generate start condition
                    auto res = i2c_master_start(link);

                    // Write the slave write address followed by the register address.
                    res |= i2c_master_write_byte(link, write_address, true);
                    res |= i2c_master_write_byte(link, slave_register, true);
                    // Generate another start condition
                    res = i2c_master_start(link);

                    // Write the read address, then read the desired amount,
                    // ending the read with a NACK (0) to signal the slave to stop sending data.
                    res |= i2c_master_write_byte(link, read_address, true);
                    res |= i2c_master_read(link, data.data(), data.size(), 0);

                    // Complete the read with a stop condition.
                    res |= res && i2c_master_stop(link);
                    res |= i2c_master_cmd_begin(port, link, Task::to_tick(timeout));

                    if (res != ESP_OK)
                    {
                        log_error(res, "Error during read");
                        i2c_reset_tx_fifo(port);
                        i2c_reset_rx_fifo(port);
                    }

                    return res == ESP_OK;
                }

                bool I2CMasterDevice::is_present() const
                {
                    std::vector<uint8_t> found;
                    scan_i2c_bus(found);
                    auto dev = std::find(found.begin(), found.end(), address);
                    return dev != found.end();
                }

                void I2CMasterDevice::scan_i2c_bus(std::vector<uint8_t>& found_devices) const
                {
                    // Write the address of each possible device and see if an ACK is received or not.
                    for (uint8_t address = 2; address <= 127; ++address)
                    {
                        I2CCommandLink link(*this);
                        auto read_address = address << 1;

                        auto res = i2c_master_start(link);
                        res |= i2c_master_write_byte(link, read_address, true);
                        res |= i2c_master_stop(link);
                        res |= i2c_master_cmd_begin(port, link, Task::to_tick(timeout));

                        if (res != ESP_OK)
                        {
                            // No ACK, no device on this address
                        }
                        else
                        {
                            found_devices.push_back(address);
                        }
                    }

                    // Cleanup
                    i2c_reset_tx_fifo(port);
                    i2c_reset_rx_fifo(port);
                }

                void I2CMasterDevice::log_error(esp_err_t err, const char* msg)
                {
                    if (err == ESP_ERR_INVALID_ARG)
                    {
                        ESP_LOGE(log_tag, "%s - Parameter error", msg);
                    }
                    else if (err == ESP_FAIL)
                    {
                        ESP_LOGE(log_tag, "%s - Send command error, no ACK from slave", msg);
                    }
                    else if (err == ESP_ERR_INVALID_STATE)
                    {
                        ESP_LOGE(log_tag, "%s - I2C driver not installed or not in master mode", msg);
                    }
                    else if (err == ESP_ERR_TIMEOUT)
                    {
                        ESP_LOGE(log_tag, "%s - Operation timeout, bus busy", msg);
                    }
                    else if (err != ESP_OK)
                    {
                        ESP_LOGE(log_tag, "%s - unknown error: %d", msg, err);
                    }
                }
            }
        }
    }
}