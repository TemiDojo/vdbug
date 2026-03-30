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
#include "../inc/ui.hh"
#include "../inc/helpers.hh"
#include "../inc/d_state.hh"
#include "../inc/padding.hh"
#include <sys/ptrace.h>
#include <sys/user.h>
#include <thread>

using namespace ftxui;

UserInterface::UserInterface(std::shared_ptr<DebuggerState> s): state(s) {

}

void UserInterface::start() {
    using namespace ftxui;
    //auto screen = ScreenInteractive::Fullscreen();

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
        auto reg = render_registers();
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
                    ) | size(WIDTH, EQUAL, 100) // This makes the window expand horizontally
                }), // This makes the hbox expand vertically
                vbox({
                    vbox({
                        reg
                    }) ,
                    window(text("Note.md") | bold,
                            text("Content goes here")
                    ) | yflex,
                }) | xflex,
            }) | flex, // No pipe here!
            vbox({
                text("[s] step | [n] next | [c] continue | [f] finish | [b] breakpoint") | hcenter | bold,
            }) | border,
        });
    });

    auto closure = state->screen->ExitLoopClosure();
    auto component = CatchEvent(renderer,[&](Event event) {
        if (event == Event::CtrlQ) {
            std::lock_guard<std::mutex> lock(state->d_mutex);
            state->current_cmd=DebugCommand::KILL;
            state->cv.notify_one();
            event.screen_->Exit();
            return true;
        }
        if (event == Event::Character('s')) {
            std::lock_guard<std::mutex> lock(state->d_mutex);
            state->current_cmd = DebugCommand::STEP;    
            state->cv.notify_one();
            return true;
        }
        if (event == Event::Character('c')) {
            std::lock_guard<std::mutex> lock(state->d_mutex);
            state->current_cmd = DebugCommand::CONTINUE;
            state->cv.notify_one();
            return true;
        }
        return false;

    });



    state->screen->Loop(component);


}

ftxui::Element UserInterface::render_registers() {
    // 1. Lock the mutex! 
    // The tracer is writing to 'state->regs' while we are reading it here.
    std::lock_guard<std::mutex> lock(state->d_mutex);

    // 2. Map your struct members to a temporary list for looping
    struct RegDisplay { std::string name; uint64_t value; };
    std::vector<RegDisplay> display_list = {
        {"rax", state->regs.rax}, {"rbx", state->regs.rbx},
        {"rcx", state->regs.rcx}, {"rdx", state->regs.rdx},
        {"rsi", state->regs.rsi}, {"rdi", state->regs.rdi},
        {"r8", state->regs.r8}, {"r9", state->regs.r9},
        {"r10", state->regs.r10}, {"r11", state->regs.r11},
        {"r12", state->regs.r12}, {"r13", state->regs.r13},
        {"r14", state->regs.r14}, {"r15", state->regs.r15},
        {"rbp", state->regs.rbp}, {"rsp", state->regs.rsp},
        {"rip", state->regs.rip}
    };

    ftxui::Elements elements;
    ftxui::Elements current_line;

    for (int i = 0; i < display_list.size(); ++i) {
        // If we've filled a row, push it and start a new one
        if (i > 0 && i % REGISTERS_PER_LINE == 0) {
            elements.push_back(ftxui::hbox(std::move(current_line)));
            current_line = {};
        }

        // Format name and value
        auto name  = helpers::to_wstring(display_list[i].name);
        auto value = helpers::to_wstring(helpers::zero_extend(helpers::to_hex(display_list[i].value, ""), 16));

        // Create the "Cell"
        current_line.push_back(
            ftxui::hbox({
                ftxui::text(name) | ftxui::align_right | ftxui::size(ftxui::WIDTH, ftxui::EQUAL, 5),
                ftxui::text(L" "),
                ftxui::text(value) | ftxui::color(ftxui::Color::GrayDark)
            }) | padding(1)
        );
    }

    // Push the last remaining line
    if (!current_line.empty()) {
        elements.push_back(ftxui::hbox(std::move(current_line)));
    }

    return ftxui::vbox(
            text(L"Registers") | padding(1), separator(), std::move(elements)) | ftxui::border;
}

