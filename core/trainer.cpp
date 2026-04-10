#include "core/trainer.hpp"
#include <sstream>
#include <fstream>
#include <cstdlib>

namespace ce {

std::string TrainerGenerator::generateSource(const CheatTable& table) const {
    std::ostringstream src;

    src << "// Auto-generated trainer for: " << table.gameName << "\n";
    src << "// Author: " << table.author << "\n";
    src << "#include <stdio.h>\n";
    src << "#include <stdlib.h>\n";
    src << "#include <string.h>\n";
    src << "#include <unistd.h>\n";
    src << "#include <sys/uio.h>\n";
    src << "#include <signal.h>\n";
    src << "#include <termios.h>\n\n";

    src << "static int target_pid = 0;\n\n";

    src << "static int rpm(void* addr, void* buf, size_t sz) {\n";
    src << "    struct iovec l = {buf, sz}, r = {addr, sz};\n";
    src << "    return process_vm_readv(target_pid, &l, 1, &r, 1, 0) >= 0;\n";
    src << "}\n\n";

    src << "static int wpm(void* addr, void* buf, size_t sz) {\n";
    src << "    struct iovec l = {buf, sz}, r = {addr, sz};\n";
    src << "    return process_vm_writev(target_pid, &l, 1, &r, 1, 0) >= 0;\n";
    src << "}\n\n";

    // Generate toggle functions for each entry
    for (size_t i = 0; i < table.entries.size(); ++i) {
        auto& e = table.entries[i];
        if (e.isGroup || e.address == 0) continue;

        src << "static int cheat_" << i << "_enabled = 0;\n";
        src << "static void toggle_cheat_" << i << "() {\n";
        src << "    cheat_" << i << "_enabled = !cheat_" << i << "_enabled;\n";
        src << "    printf(\"[%s] " << e.description << "\\n\", cheat_" << i << "_enabled ? \"ON\" : \"OFF\");\n";
        src << "}\n\n";
    }

    // Freeze loop
    src << "static volatile int running = 1;\n";
    src << "static void sighandler(int s) { running = 0; }\n\n";

    src << "static void freeze_loop() {\n";
    src << "    while (running) {\n";
    for (size_t i = 0; i < table.entries.size(); ++i) {
        auto& e = table.entries[i];
        if (e.isGroup || e.address == 0 || e.value.empty()) continue;
        src << "        if (cheat_" << i << "_enabled) {\n";
        src << "            int v = " << e.value << ";\n";
        src << "            wpm((void*)0x" << std::hex << e.address << std::dec << ", &v, 4);\n";
        src << "        }\n";
    }
    src << "        usleep(100000);\n";
    src << "    }\n";
    src << "}\n\n";

    // Main
    src << "int main(int argc, char** argv) {\n";
    src << "    if (argc < 2) { printf(\"Usage: %s <pid>\\n\", argv[0]); return 1; }\n";
    src << "    target_pid = atoi(argv[1]);\n";
    src << "    signal(SIGINT, sighandler);\n";
    src << "    printf(\"Trainer for: " << table.gameName << "\\n\");\n";
    src << "    printf(\"Target PID: %d\\n\\n\", target_pid);\n";
    src << "    printf(\"Hotkeys:\\n\");\n";

    int keyIdx = 0;
    for (size_t i = 0; i < table.entries.size(); ++i) {
        auto& e = table.entries[i];
        if (e.isGroup || e.address == 0) continue;
        src << "    printf(\"  " << (keyIdx + 1) << ": " << e.description << "\\n\");\n";
        ++keyIdx;
    }

    src << "    printf(\"\\nPress number keys to toggle. Ctrl+C to exit.\\n\\n\");\n\n";

    src << "    // Non-blocking terminal input\n";
    src << "    struct termios oldt, newt;\n";
    src << "    tcgetattr(0, &oldt);\n";
    src << "    newt = oldt;\n";
    src << "    newt.c_lflag &= ~(ICANON | ECHO);\n";
    src << "    tcsetattr(0, TCSANOW, &newt);\n\n";

    src << "    while (running) {\n";
    src << "        fd_set fds; FD_ZERO(&fds); FD_SET(0, &fds);\n";
    src << "        struct timeval tv = {0, 100000};\n";
    src << "        if (select(1, &fds, NULL, NULL, &tv) > 0) {\n";
    src << "            char c = getchar();\n";

    keyIdx = 0;
    for (size_t i = 0; i < table.entries.size(); ++i) {
        auto& e = table.entries[i];
        if (e.isGroup || e.address == 0) continue;
        src << "            if (c == '" << (keyIdx + 1) << "') toggle_cheat_" << i << "();\n";
        ++keyIdx;
    }

    src << "        }\n";
    src << "        // Freeze active cheats\n";
    for (size_t i = 0; i < table.entries.size(); ++i) {
        auto& e = table.entries[i];
        if (e.isGroup || e.address == 0 || e.value.empty()) continue;
        src << "        if (cheat_" << i << "_enabled) {\n";
        src << "            int v = " << e.value << ";\n";
        src << "            wpm((void*)0x" << std::hex << e.address << std::dec << ", &v, 4);\n";
        src << "        }\n";
    }
    src << "    }\n\n";
    src << "    tcsetattr(0, TCSANOW, &oldt);\n";
    src << "    printf(\"\\nTrainer exited.\\n\");\n";
    src << "    return 0;\n";
    src << "}\n";

    return src.str();
}

std::string TrainerGenerator::generateBinary(const CheatTable& table, const std::string& outputPath) const {
    auto source = generateSource(table);
    auto srcPath = outputPath + ".c";

    std::ofstream f(srcPath);
    if (!f) return "Failed to write source file";
    f << source;
    f.close();

    auto cmd = "gcc -O2 -o " + outputPath + " " + srcPath + " 2>&1";
    auto* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "Failed to run gcc";

    char buf[256];
    std::string output;
    while (fgets(buf, sizeof(buf), pipe)) output += buf;
    int ret = pclose(pipe);

    std::remove(srcPath.c_str());

    if (ret != 0) return "Compilation failed: " + output;
    return {};
}

} // namespace ce
