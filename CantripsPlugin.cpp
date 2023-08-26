#include "CantripsPlugin.h"
#include <cassert>

CantripsPlugin* plugin;

DLLEXPORT Plugin* GetPluginPointerV2() { return plugin; }

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		plugin = new CantripsPlugin();

		char szPath[MAX_PATH];
		GetModuleFileNameA(hModule, szPath, MAX_PATH);
		plugin->SetPluginFullPath(szPath);
	}
	else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
		delete plugin;
	}
	return TRUE;
}

CantripsPlugin::CantripsPlugin()
{
	version = "1.0";
	subClass = "CANTRIPS";
	description = "Allows cantrips to be cast without expending a spell slot.";
}

void CantripsPlugin::GetFunctionClass(char* fClass)
{
	strncpy_s(fClass, 128, "CANTRIPS", 8);
}

unsigned char CantripsPlugin::preparedPayload[] =
{
	0x3c, 0x00,						// cmp al, 0
	0x74, 0x2e,						// je end of function
	0xe9, 0x00, 0x00, 0x00, 0x00,   // jmp to old code
};

unsigned char CantripsPlugin::spontaneousPayload[] =
{
	0x3c, 0x00,						// cmp al, 0
	0x74, 0x0e,						// je end of function
	0xe9, 0x00, 0x00, 0x00, 0x00,   // jmp to old code
};
unsigned char CantripsPlugin::preparedOldCode[] = { 0 };

unsigned char CantripsPlugin::spontaneousOldCode[] = { 0 };

void CantripsPlugin::MoveOldCode()
{
	memcpy(preparedOldCode, (void*)preparedHookPoint, preparedHookSize);
	preparedOldCode[preparedHookSize] = 0xe9; // jmp
	DWORD_PTR jumpOffset = preparedAfterHookPoint - (DWORD_PTR)&preparedOldCode[preparedHookSize + 5];
	memcpy(&preparedOldCode[preparedHookSize + 1], &jumpOffset, sizeof(DWORD_PTR));
	DWORD oldProtect = 0;
	VirtualProtect(preparedOldCode, sizeof(preparedOldCode), PAGE_EXECUTE_READ, &oldProtect);

	memcpy(spontaneousOldCode, (void*)spontaneousHookPoint, spontaneousHookSize);
	spontaneousOldCode[spontaneousHookSize] = 0xe9; // jmp
	jumpOffset = spontaneousAfterHookPoint - (DWORD_PTR)&spontaneousOldCode[spontaneousHookSize + 5];
	memcpy(&spontaneousOldCode[spontaneousHookSize + 1], &jumpOffset, sizeof(DWORD_PTR));
	oldProtect = 0;
	VirtualProtect(spontaneousOldCode, sizeof(spontaneousOldCode), PAGE_EXECUTE_READ, &oldProtect);
}

void CantripsPlugin::ApplyHook()
{
	DWORD_PTR jumpOffset = (DWORD_PTR)preparedOldCode - (preparedHookPoint + 9);
	memcpy(&preparedPayload[5], &jumpOffset, sizeof(DWORD_PTR));
	DWORD oldProtect = 0;
	VirtualProtect((void*)preparedHookPoint, preparedHookSize, PAGE_READWRITE, &oldProtect);
	memcpy((void*)preparedHookPoint, preparedPayload, preparedPayloadSize);
	VirtualProtect((void*)preparedHookPoint, preparedHookSize, PAGE_EXECUTE_READ, &oldProtect);

	jumpOffset = (DWORD_PTR)spontaneousOldCode - (spontaneousHookPoint + 9);
	memcpy(&spontaneousPayload[5], &jumpOffset, sizeof(DWORD_PTR));
	oldProtect = 0;
	VirtualProtect((void*)spontaneousHookPoint, spontaneousHookSize, PAGE_READWRITE, &oldProtect);
	memcpy((void*)spontaneousHookPoint, spontaneousPayload, spontaneousPayloadSize);
	VirtualProtect((void*)spontaneousHookPoint, spontaneousHookSize, PAGE_EXECUTE_READ, &oldProtect);
}

bool CantripsPlugin::Init(char * nwnxhome)
{
	assert(GetPluginFileName());
	MoveOldCode();
	ApplyHook();
	return true;
}