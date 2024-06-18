#pragma once

#include <Windows.h>
#include <string>
#include <dbghelp.h>
#include <sstream>
#include <format>

#pragma comment(lib, "DbgHelp.lib")

static std::string get_stack_trace(const CONTEXT* ctx = nullptr)
{
    const auto process = GetCurrentProcess();
    const auto hThread = GetCurrentThread();

    CONTEXT context{};

    if (ctx) {
        context = *ctx;
    }
    else {
        RtlCaptureContext(&context);
    }

    STACKFRAME frame{};
    frame.AddrPC.Offset = context.Eip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrStack.Offset = context.Esp;
    frame.AddrStack.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = context.Ebp;
    frame.AddrFrame.Mode = AddrModeFlat;

    const auto handle = ImageNtHeader(GetModuleHandle(nullptr));
    const auto image_type = handle->FileHeader.Machine;

    SymInitialize(process, nullptr, TRUE);
    SymSetOptions(SYMOPT_LOAD_LINES);

    std::stringstream str;

    for (auto i = 0; i < 16; i++)
    {
        if (!StackWalk(image_type, process, hThread, &frame, &context, nullptr, SymFunctionTableAccess, SymGetModuleBase, nullptr))
            break;

        if (frame.AddrPC.Offset == 0)
            break;

        HMODULE module = nullptr;
        char buffer[MAX_PATH];
        if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, reinterpret_cast<const char*>(frame.AddrPC.Offset), &module))
        {
            GetModuleFileName(module, buffer, MAX_PATH - 1);
        }

        DWORD displacement;
        IMAGEHLP_LINE line;

        // Do we have symbols?
        if (module && SymGetLineFromAddr(GetCurrentProcess(), frame.AddrPC.Offset, &displacement, &line))
        {
            str << std::format("{}: Line {}", line.FileName, line.LineNumber) << std::endl;
        }
        // Is the address in a module?
        else if (module) {
            str << std::format("{}+0x{:X} [0x{:X}]", buffer, frame.AddrPC.Offset - reinterpret_cast<DWORD>(module), frame.AddrPC.Offset) << std::endl;
        }
        // No symbols or module, just use address.
        else
        {
            str << std::format("0x{:X} [0x{:X}]", frame.AddrPC.Offset - reinterpret_cast<DWORD>(module), frame.AddrPC.Offset) << std::endl;
        }
    }

    SymCleanup(process);

    return str.str();
};