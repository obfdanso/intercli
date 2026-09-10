// Regression test for directional session keys.
// Guards the rotation race: with one shared key, a message already in flight
// fails to decrypt when the peer rotates. Each direction must be rotated only
// by its own sender.

#include "crypto_utils.h"
#include <iostream>
#include <string>

using namespace SecureComm;

static int failures = 0;

static void check(bool condition, const std::string& what) {
    if (condition) {
        std::cout << "  PASS: " << what << std::endl;
    } else {
        std::cout << "  FAIL: " << what << std::endl;
        ++failures;
    }
}

int main() {
    CryptoManager crypto;

    try {
        std::vector<uint8_t> shared_secret = crypto.generate_random_bytes(32);
        std::vector<uint8_t> nonce = crypto.generate_random_bytes(IV_SIZE);

        std::cout << "Mirrored derivation" << std::endl;
        SessionKeys server = crypto.derive_directional_keys(shared_secret, nonce, true);
        SessionKeys client = crypto.derive_directional_keys(shared_secret, nonce, false);

        check(server.tx_key.size() == KEY_SIZE, "tx key is KEY_SIZE bytes");
        check(server.rx_key.size() == KEY_SIZE, "rx key is KEY_SIZE bytes");
        check(server.tx_key == client.rx_key, "server tx matches client rx");
        check(server.rx_key == client.tx_key, "server rx matches client tx");
        check(server.tx_key != server.rx_key, "the two directions use different keys");

        std::cout << "Determinism" << std::endl;
        SessionKeys again = crypto.derive_directional_keys(shared_secret, nonce, true);
        check(again.tx_key == server.tx_key, "derivation is deterministic");

        std::cout << "Rotating one direction leaves the other alone" << std::endl;
        std::vector<uint8_t> session_id_bytes = {0x01, 0x02, 0x03, 0x04};

        std::vector<uint8_t> server_tx_before = server.tx_key;
        std::vector<uint8_t> server_rx_before = server.rx_key;

        // The server owns the server-to-client direction; the client rotates the
        // matching rx key when it reads the in-band marker.
        server.tx_key = crypto.rotate_session_key(server.tx_key, session_id_bytes);
        client.rx_key = crypto.rotate_session_key(client.rx_key, session_id_bytes);

        check(server.tx_key != server_tx_before, "rotation changes the key");
        check(server.tx_key == client.rx_key, "rotated direction still matches");
        check(server.rx_key == server_rx_before, "opposite direction is untouched");
        check(server.rx_key == client.tx_key, "opposite direction still matches");

        std::cout << "Rotating the other direction independently" << std::endl;
        client.tx_key = crypto.rotate_session_key(client.tx_key, session_id_bytes);
        server.rx_key = crypto.rotate_session_key(server.rx_key, session_id_bytes);

        check(server.rx_key == client.tx_key, "second direction matches after its own rotation");
        check(server.tx_key == client.rx_key, "first direction still matches");

        std::cout << "Different nonce gives different keys" << std::endl;
        std::vector<uint8_t> other_nonce = crypto.generate_random_bytes(IV_SIZE);
        SessionKeys other = crypto.derive_directional_keys(shared_secret, other_nonce, true);
        check(other.tx_key != server_tx_before, "nonce is mixed into derivation");

    } catch (const std::exception& e) {
        std::cout << "  FAIL: unexpected exception: " << e.what() << std::endl;
        ++failures;
    }

    if (failures == 0) {
        std::cout << "All directional key tests passed" << std::endl;
        return 0;
    }
    std::cout << failures << " directional key test(s) failed" << std::endl;
    return 1;
}
