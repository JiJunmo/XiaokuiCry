#include "XiaokuiCry.h"

int main() {
	HWND hwnd = ::FindWindow(L"ConsoleWindowClass", NULL);
	if (hwnd) {
		::ShowWindow(hwnd, SW_HIDE);
	}

	HANDLE mutex = OpenMutexA(MUTEX_ALL_ACCESS, FALSE, "xiaokuicry");
	if (mutex == NULL) {
		CreateMutexA(NULL, FALSE, "xiaokuicry");
	}
	else {
		return 0;
	}
	XiaokuiCry xiao_kui;
	xiao_kui.cry();
	return 0;
}