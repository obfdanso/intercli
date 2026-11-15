#pragma once

namespace Intercli {

// True when Windows treats a network this PC is connected to as Public. On a
// Public network, allowing intercli through the firewall usually covers only
// Private networks, so nobody else can reach a chat hosted here. Always false
// on other systems.
bool onPublicNetwork();

} // namespace Intercli
