#include "network_check.h"

#ifdef _WIN32
#include <windows.h>
#include <netlistmgr.h>
#endif

namespace Intercli {

bool onPublicNetwork() {
#ifdef _WIN32
    // Network List Manager: the same categories Windows Settings shows.
    const HRESULT init = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool uninit = SUCCEEDED(init);
    bool isPublic = false;
    INetworkListManager* manager = nullptr;
    if (SUCCEEDED(CoCreateInstance(CLSID_NetworkListManager, nullptr, CLSCTX_ALL, IID_INetworkListManager,
                                   reinterpret_cast<void**>(&manager)))) {
        IEnumNetworks* networks = nullptr;
        if (SUCCEEDED(manager->GetNetworks(NLM_ENUM_NETWORK_CONNECTED, &networks))) {
            INetwork* network = nullptr;
            ULONG fetched = 0;
            while (networks->Next(1, &network, &fetched) == S_OK && fetched == 1) {
                NLM_NETWORK_CATEGORY category = NLM_NETWORK_CATEGORY_PRIVATE;
                if (SUCCEEDED(network->GetCategory(&category)) && category == NLM_NETWORK_CATEGORY_PUBLIC) {
                    isPublic = true;
                }
                network->Release();
            }
            networks->Release();
        }
        manager->Release();
    }
    if (uninit) {
        CoUninitialize();
    }
    return isPublic;
#else
    return false;
#endif
}

} // namespace Intercli
