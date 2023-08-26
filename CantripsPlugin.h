#pragma once
#include "plugin.h"

#define DLLEXPORT extern "C" __declspec(dllexport)

class CantripsPlugin :
    public Plugin
{
public:
	static const DWORD_PTR preparedHookPoint = 0x5a1eb8;
	static const DWORD_PTR preparedAfterHookPoint = 0x05a1ec2;
	static const DWORD_PTR preparedHookSize = preparedAfterHookPoint - preparedHookPoint;
	static const DWORD_PTR preparedPayloadSize = 9;
	static unsigned char preparedPayload[4096];
	static unsigned char preparedOldCode[4096];

	static const DWORD_PTR spontaneousHookPoint = 0x752dc8;
	static const DWORD_PTR spontaneousAfterHookPoint = 0x752dd3;
	static const DWORD_PTR spontaneousHookSize = spontaneousAfterHookPoint - spontaneousHookPoint;
	static const DWORD_PTR spontaneousPayloadSize = 10;
	static unsigned char spontaneousPayload[4096];
	static unsigned char spontaneousOldCode[4096];

    CantripsPlugin();
	~CantripsPlugin() {};

	bool Init(char* nwnxhome);
	void ApplyHook();
	void MoveOldCode();

	int GetInt(char* sFunction, char* sParam1, int nParam2) { return 0; }
	void SetInt(char* sFunction, char* sParam1, int nParam2, int nValue) {};
	float GetFloat(char* sFunction, char* sParam1, int nParam2) { return 0.0; }
	void SetFloat(char* sFunction, char* sParam1, int nParam2, float fValue) {};
	void SetString(char* sFunction, char* sParam1, int nParam2, char* sValue) { return; }
	char* GetString(char* sFunction, char* sParam1, int nParam2) { return NULL; }
	void GetFunctionClass(char* fClass);
};

