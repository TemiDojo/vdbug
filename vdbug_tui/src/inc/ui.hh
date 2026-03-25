#pragma once

#include "ftxui/screen/screen.hpp"
#include "ftxui/screen/color.hpp"
#include "ftxui/screen/pixel.hpp"
#include "ftxui/component/screen_interactive.hpp"
#include "ftxui/component/captured_mouse.hpp"     // for ftxui
#include "ftxui/component/component.hpp"          // for Menu
#include "ftxui/component/component_options.hpp"  // for MenuOption

class UserInterface {

    private:
        ftxui::Element render_stack();
        ftxui::Element render_registers();
        ftxui::Element render_instructions();


};
