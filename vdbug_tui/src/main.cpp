#include <functional>  // for function
#include <iostream>  // for basic_ostream::operator<<, operator<<, endl, basic_ostream, basic_ostream<>::__ostream_type, cout, ostream
#include <string>    // for string, basic_string, allocator
#include <vector>    // for vector

#include "ftxui/screen/screen.hpp"
#include "ftxui/screen/color.hpp"
#include "ftxui/screen/pixel.hpp"

#include "ftxui/component/screen_interactive.hpp"
#include "ftxui/component/captured_mouse.hpp"     // for ftxui
#include "ftxui/component/component.hpp"          // for Menu
#include "ftxui/component/component_options.hpp"  // for MenuOption
#include "inc/ui.hh"
#include "inc/helpers.hh"
#include "inc/d_state.hh"
#include "inc/padding.hh"
#include <sys/ptrace.h>
#include <sys/user.h>
#include <thread>

using namespace ftxui;

int main() {
    using namespace ftxui;
    auto screen = ScreenInteractive::Fullscreen();

    std::string input_value;
    int selected = 0;

    // create components
    auto input = Input(&input_value, "Placeholder");
    // auto menu = Menu({
    //
    //         }, &selected);

    std::vector<std::string> entries = {
            "Option 1",
            "Option 2",
            "Option 3",
    };

    MenuOption option;
    auto menu = Menu(&entries, &selected, option);

    auto container = Container::Horizontal({
            input,
            menu,
            });


    auto renderer = Renderer(container, [&] {
        return vbox({
            text("vdbug") | hcenter | bold,
            hbox({

                hbox({
                    window(text("Address Space") | bold, 
                            vbox({
                                window(text(" Stack "), text(" [ 0x7fffffffe000 ] ")) | color(Color::RedLight),
                                filler() | size(HEIGHT, GREATER_THAN, 2),
                                window(text(" Heap "), text(" [ 0x55555600000 ] ")) | color(Color::GreenLight),
                                separator(),


                            })
                    ) | size(WIDTH, EQUAL, 150) // This makes the window expand horizontally
                }), // This makes the hbox expand vertically
                vbox({
                    window(text("Debug info") | bold,
                            text("Content goes here")
                    ) | size(HEIGHT, EQUAL, 50),
                    window(text("Terminal") | bold,
                            text("Content goes here")
                    ) | yflex,
                }) | xflex,
            }) | flex // No pipe here!
        });
    });

    auto closure = screen.ExitLoopClosure();
    auto component = CatchEvent(renderer,[&](Event event) {
        if (event == Event::CtrlQ) {
            event.screen_->Exit();
            return true;
        }
        if (event == Event::Character('s')) {

            return true;
        }
        return false;

    });


    screen.Loop(component);

    return 0;
}

ftxui::Element UserInterface::render_registers(DebuggerState *dstate) {

    Elements elements;

    Elements current_line;
    auto value = helpers::to_wstring(helpers::zero_extend(helpers::to_hex(dstate->regs.rax, ""), 16));
    current_line.push_back(
            hbox(text("rax") | align_right | size(WIDTH, EQUAL, 5),
            text(value) | color(Color::GrayDark)) | padding(1) | notflex 
    );

    return vbox(std::move(elements)) | border;

}
