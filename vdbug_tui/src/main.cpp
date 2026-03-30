extern "C" {
#include "../dwarf/inc/dl_parser.h"
}
#include <memory>
#include <string>
#include "inc/d_state.hh"
#include "inc/ui.hh"
#include "inc/tracer.hh"
#include <thread>
#include "ftxui/component/screen_interactive.hpp"

int main(int argc, char** argv) {

    if (argc <= 1) {
        puts("Usage: tracer <target>");
        return -1;
    }
    auto s = std::make_shared<DebuggerState>();
    s->target_file = argv[1];
    s->m = initialize_matrix();
    dump_dl(argv[1], s->m);

    std::thread t1(ptrace_init, s);
    auto screen = ftxui::ScreenInteractive::Fullscreen();
    s->screen = &screen;

    UserInterface ui(s);
    ui.start();

    t1.join();

}
