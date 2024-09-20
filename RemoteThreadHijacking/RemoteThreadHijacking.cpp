#include "Functions.h"


BOOL CreateSuspendedProcess() {

	CHAR WnDr[MAX_PATH];


	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		warning("Get Environment Variable failed error : 0x%lx", GetLastError());
		return FALSE;
	}


	okay("We got the env var");
	//Creating full target
	if()

	if(!CreateProcessA(NULL,){}
}

int main(int argc, char* argv[]) {



}