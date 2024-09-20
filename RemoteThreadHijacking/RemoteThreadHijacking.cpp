#include "Functions.h"


BOOL CreateSuspendedProcess(IN LPCSTR ProcessName) {

	CHAR WnDr[MAX_PATH];
	CHAR lpPath[MAX_PATH * 2];

	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		warning("Get Environment Variable failed error : 0x%lx", GetLastError());
		return FALSE;
	}


	okay("We got the env var");
	//Creating full target
	sprintf(lpPath, "%s\\System32\\%s", WnDr, ProcessName);
	info("Running : %s", lpPath);



	if(!CreateProcessA(NULL,){}
}

int main(int argc, char* argv[]) {



}