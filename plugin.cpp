#include "stdinc.h"
#include "PluginController.h"

using namespace wtwCrypto;

extern "C" {

    BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
        PluginController::getInstance().setDllHINSTANCE(hinstDLL);
        return 1;
    }

    WTWPLUGINFO* __stdcall queryPlugInfo(DWORD /*apiVersion*/, DWORD /*masterVersion*/) {
        return const_cast<WTWPLUGINFO*>(PluginController::getInstance().getPlugInfo());
    }

    int __stdcall pluginLoad(DWORD /*callReason*/, WTWFUNCTIONS* fn) {    
        return PluginController::getInstance().onLoad(fn);
    }

    int __stdcall pluginUnload(DWORD /*callReason*/) {
        return PluginController::getInstance().onUnload();
    }

} // extern "C"
