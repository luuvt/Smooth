#pragma once

#include <smooth/core/Application.h>

namespace json_test
{
    class App
            : public smooth::core::Application
    {
    public:
        App();

        void tick() override;

    private:
    };
}