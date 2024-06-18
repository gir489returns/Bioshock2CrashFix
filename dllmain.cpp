// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <fstream>
#include <chrono>
#include <codecvt>
#include <intrin.h>

#pragma region DXGI_WRAPPER
#ifdef _WIN64
#define DLLPATH "\\\\.\\GLOBALROOT\\SystemRoot\\System32\\dxgi.dll"
#else
#define DLLPATH "\\\\.\\GLOBALROOT\\SystemRoot\\SysWOW64\\dxgi.dll"
#endif // _WIN64

#pragma comment(linker, "/EXPORT:ApplyCompatResolutionQuirking=" DLLPATH ".ApplyCompatResolutionQuirking")
#pragma comment(linker, "/EXPORT:CompatString=" DLLPATH ".CompatString")
#pragma comment(linker, "/EXPORT:CompatValue=" DLLPATH ".CompatValue")
#pragma comment(linker, "/EXPORT:CreateDXGIFactory=" DLLPATH ".CreateDXGIFactory")
#pragma comment(linker, "/EXPORT:CreateDXGIFactory1=" DLLPATH ".CreateDXGIFactory1")
#pragma comment(linker, "/EXPORT:CreateDXGIFactory2=" DLLPATH ".CreateDXGIFactory2")
#pragma comment(linker, "/EXPORT:DXGID3D10CreateDevice=" DLLPATH ".DXGID3D10CreateDevice")
#pragma comment(linker, "/EXPORT:DXGID3D10CreateLayeredDevice=" DLLPATH ".DXGID3D10CreateLayeredDevice")
#pragma comment(linker, "/EXPORT:DXGID3D10GetLayeredDeviceSize=" DLLPATH ".DXGID3D10GetLayeredDeviceSize")
#pragma comment(linker, "/EXPORT:DXGID3D10RegisterLayers=" DLLPATH ".DXGID3D10RegisterLayers")
#pragma comment(linker, "/EXPORT:DXGIDeclareAdapterRemovalSupport=" DLLPATH ".DXGIDeclareAdapterRemovalSupport")
#pragma comment(linker, "/EXPORT:DXGIDisableVBlankVirtualization=" DLLPATH ".DXGIDisableVBlankVirtualization")
#pragma comment(linker, "/EXPORT:DXGIDumpJournal=" DLLPATH ".DXGIDumpJournal")
#pragma comment(linker, "/EXPORT:DXGIGetDebugInterface1=" DLLPATH ".DXGIGetDebugInterface1")
#pragma comment(linker, "/EXPORT:DXGIReportAdapterConfiguration=" DLLPATH ".DXGIReportAdapterConfiguration")
#pragma comment(linker, "/EXPORT:PIXBeginCapture=" DLLPATH ".PIXBeginCapture")
#pragma comment(linker, "/EXPORT:PIXEndCapture=" DLLPATH ".PIXEndCapture")
#pragma comment(linker, "/EXPORT:PIXGetCaptureState=" DLLPATH ".PIXGetCaptureState")
#pragma comment(linker, "/EXPORT:SetAppCompatStringPointer=" DLLPATH ".SetAppCompatStringPointer")
#pragma comment(linker, "/EXPORT:UpdateHMDEmulationStatus=" DLLPATH ".UpdateHMDEmulationStatus")
#pragma endregion

DWORD crash_one_failure_return;
DWORD crash_one_return;
DWORD crash_three_failure_return;
DWORD crash_three_return;
DWORD crash_four_return;
DWORD crash_five_failure_return;
DWORD crash_five_return;

#ifdef LOGGING_ENABLED
#include "StackWalker.hpp"
int crash_one_times{};
int crash_three_times{};
int crash_four_times{};
int crash_five_times{};
#endif

#define HEX_TO_UPPER(value) "0x" << std::hex << std::uppercase << (DWORD)value << std::dec << std::nouppercase

bool __fastcall isReadableWritablePointer(PVOID p)
{
	MEMORY_BASIC_INFORMATION info;
	if (VirtualQuery(p, &info, sizeof(info)) == sizeof(info)) {
		if (info.State == MEM_COMMIT) {
			DWORD protect = info.Protect;
			if (!(protect & PAGE_GUARD) && !(protect & PAGE_NOACCESS)) {
				if (protect & PAGE_READONLY || protect & PAGE_READWRITE ||
					protect & PAGE_WRITECOPY || protect & PAGE_EXECUTE_READ ||
					protect & PAGE_EXECUTE_READWRITE || protect & PAGE_EXECUTE_WRITECOPY) {
					return true;
				}
			}
		}
	}
	return false;
}

void crash_one_fix()
{
	__asm
	{
		mov eax, [edi+0x44]
		pushad
		mov ecx, eax
		call isReadableWritablePointer
		test al, al
		popad
		jz crash_one_failure_return_label
		cmp dword ptr[eax], 0
	jmp crash_one_return
crash_one_failure_return_label:
#ifdef LOGGING_ENABLED
		inc crash_one_times
#endif
		jmp crash_one_failure_return
	}
}

void crash_three_fix()
{
	__asm
	{
		mov eax, [eax+0x44]
		pushad
		mov ecx, eax
		call isReadableWritablePointer
		test al, al
		popad
		jz crash_three_failure_return_label
		mov ecx, [eax]
	jmp crash_three_return
crash_three_failure_return_label:
#ifdef LOGGING_ENABLED
		inc crash_three_times
#endif
		jmp crash_three_failure_return
	}
}

void crash_four_fix()
{
	__asm
	{
		add ecx, [edi+edx*4+0x208]
		pushad
		call isReadableWritablePointer
		test al, al
		popad
		jz crash_four_failure_return_label
		cmp[ecx+0x10], eax
	jmp crash_four_return
crash_four_failure_return_label:
#ifdef LOGGING_ENABLED
		inc crash_four_times
#endif
		jmp crash_four_return
	}
}

void crash_five_fix()
{
	__asm
	{
		mov eax, [edi]
		pushad
		mov ecx, eax
		call isReadableWritablePointer
		test al, al
		popad
		mov eax, [esi+0x0C]
		jz crash_five_failure_return_label
		push [edi]
	jmp crash_five_return
crash_five_failure_return_label:
#ifdef LOGGING_ENABLED
		inc crash_five_times
#endif
		jmp crash_five_failure_return
	}
}

#ifdef LOGGING_ENABLED
void log_crash(std::string crash_type)
{
	static std::ofstream log("crash.log", std::ios::app);

	auto now = std::chrono::system_clock::now();
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
	auto timer = std::chrono::system_clock::to_time_t(now);
	auto local_time = *std::localtime(&timer);

	log << "[" << std::put_time(&local_time, "%m/%d/%Y %I:%M:%S") << ":" << std::setfill('0') << std::setw(3) << ms.count() << " " << std::put_time(&local_time, "%p") << "] Caught " << crash_type << " crash." << std::endl;
}
#endif

void error_logger_function(const wchar_t* a1, ...)
{
#ifdef LOGGING_ENABLED
	wchar_t Buffer[4096];
	va_list ArgList;

	va_start(ArgList, a1);
	vswprintf(Buffer, 4096, a1, ArgList);
	va_end(ArgList);

	std::wstring wstr(Buffer);
	std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
	std::string str = converter.to_bytes(wstr);

	std::ostringstream o;
	o << "[ERROR_LOGGER]: message " << str << " Stack Trace: " << get_stack_trace();
	log_crash(o.str());
#endif
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hModule);
		CreateThread(nullptr, 0, [](PVOID) -> DWORD {
			const auto Bioshock2HDEXE = reinterpret_cast<DWORD>(GetModuleHandle(NULL));
			crash_one_failure_return = Bioshock2HDEXE+0xC1CADB;
			crash_one_return = Bioshock2HDEXE+0xC1C96D;
			crash_three_failure_return = Bioshock2HDEXE+0x4FF1C8;
			crash_three_return = Bioshock2HDEXE+0x4FF100;
			crash_four_return = Bioshock2HDEXE+0x3087B2;
			crash_five_failure_return = Bioshock2HDEXE+0xBE17DB;
			crash_five_return = Bioshock2HDEXE+0xBE17D5;

			DWORD oldProtect;
			DWORD relativeAddress;

			PVOID crash_one_location = reinterpret_cast<PVOID>(Bioshock2HDEXE+0xC1C967);
			BYTE crash_one_array[] = { 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90 };
			VirtualProtect(crash_one_location, sizeof(crash_one_array), PAGE_EXECUTE_READWRITE, &oldProtect);
			relativeAddress = ((((DWORD)&crash_one_fix)+6) - (DWORD)crash_one_location) - 5;
			*(DWORD*)(crash_one_array+1) = relativeAddress;
			memcpy(crash_one_location, crash_one_array, sizeof(crash_one_array));
			VirtualProtect(crash_one_location, sizeof(crash_one_array), oldProtect, &oldProtect);

			PVOID crash_three_location = reinterpret_cast<PVOID>(Bioshock2HDEXE+0x4FF0FB);
			BYTE crash_three_array[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
			VirtualProtect(crash_three_location, sizeof(crash_three_array), PAGE_EXECUTE_READWRITE, &oldProtect);
			relativeAddress = ((((DWORD)&crash_three_fix)+6) - (DWORD)crash_three_location) - 5;
			*(DWORD*)(crash_three_array + 1) = relativeAddress;
			memcpy(crash_three_location, crash_three_array, sizeof(crash_three_array));
			VirtualProtect(crash_three_location, sizeof(crash_three_array), oldProtect, &oldProtect);
			
			PVOID crash_four_location = reinterpret_cast<PVOID>(Bioshock2HDEXE+0x3087A8);
			BYTE crash_four_array[] = { 0xE9, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00 };
			VirtualProtect(crash_four_location, sizeof(crash_four_array), PAGE_EXECUTE_READWRITE, &oldProtect);
			relativeAddress = ((((DWORD)&crash_four_fix)+6) - (DWORD)crash_four_location) - 5;
			*(DWORD*)(crash_four_array + 1) = relativeAddress;
			memcpy(crash_four_location, crash_four_array, sizeof(crash_four_array));
			VirtualProtect(crash_four_location, sizeof(crash_four_array), oldProtect, &oldProtect);
			
			PVOID crash_five_location = reinterpret_cast<PVOID>(Bioshock2HDEXE+0xBE17D0);
			BYTE crash_five_array[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
			VirtualProtect(crash_five_location, sizeof(crash_five_array), PAGE_EXECUTE_READWRITE, &oldProtect);
			relativeAddress = ((((DWORD)&crash_five_fix)+6) - (DWORD)crash_five_location) - 5;
			*(DWORD*)(crash_five_array + 1) = relativeAddress;
			memcpy(crash_five_location, crash_five_array, sizeof(crash_five_array));
			VirtualProtect(crash_five_location, sizeof(crash_five_array), oldProtect, &oldProtect);

			PVOID reverb_bytes_location = reinterpret_cast<PVOID>(Bioshock2HDEXE+0xC2EE5D);
			BYTE reverb_bytes_array[] = { 0x90, 0xE9 };
			VirtualProtect(reverb_bytes_location, sizeof(reverb_bytes_array), PAGE_EXECUTE_READWRITE, &oldProtect);
			memcpy(reverb_bytes_location, reverb_bytes_array, sizeof(reverb_bytes_array));
			VirtualProtect(reverb_bytes_location, sizeof(reverb_bytes_array), oldProtect, &oldProtect);

			PVOID app_error_location = reinterpret_cast<PVOID>(Bioshock2HDEXE+0xB55970);
			BYTE app_error_array[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
			VirtualProtect(app_error_location, sizeof(app_error_array), PAGE_EXECUTE_READWRITE, &oldProtect);
			relativeAddress = (((DWORD)&error_logger_function) - (DWORD)app_error_location) - 5;
			*(DWORD*)(app_error_array + 1) = relativeAddress;
			memcpy(app_error_location, app_error_array, sizeof(app_error_array));
			VirtualProtect(app_error_location, sizeof(app_error_array), oldProtect, &oldProtect);

#ifdef LOGGING_ENABLED
			while (TRUE)
			{
				static int last_crash_one_times{}, last_crash_three_times{}, last_crash_four_times{}, last_crash_five_times{};

				if (last_crash_one_times != crash_one_times)
				{
					log_crash("FMOD");
					last_crash_one_times = crash_one_times;
				}

				if (last_crash_three_times != crash_three_times)
				{
					log_crash("ALT+TAB");
					last_crash_three_times = crash_three_times;
				}

				if (last_crash_four_times != crash_four_times)
				{
					log_crash("Memory release");
					last_crash_four_times = crash_four_times;
				}

				if (last_crash_five_times != crash_five_times)
				{
					log_crash("D3D11DeviceContext_End");
					last_crash_five_times = crash_five_times;
				}

				Sleep(100);
			}
#endif
			ExitThread(0);
		}, nullptr, 0, nullptr);
	}
	return TRUE;
}