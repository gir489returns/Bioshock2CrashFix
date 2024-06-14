// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>

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
		jz crash_four_return_label
		cmp[ecx+0x10], eax
crash_four_return_label:
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
		jmp crash_five_failure_return
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hModule);
		CreateThread(nullptr, 0, [](PVOID) -> DWORD {
			auto Bioshock2HDEXE = reinterpret_cast<DWORD>(GetModuleHandle(NULL));
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

			ExitThread(0);
		}, nullptr, 0, nullptr);
	}
	return TRUE;
}