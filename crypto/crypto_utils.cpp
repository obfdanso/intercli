#include "crypto_utils.h"
#include <cctype>
#include <cstdio>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <random>
#include <algorithm>
#include <cstring>
#include <openssl/kdf.h>

namespace SecureComm {

// EVPContext implementation
EVPContext::EVPContext() : ctx_(EVP_CIPHER_CTX_new()) {
    if (!ctx_) {
        throw CryptoException("Failed to create EVP_CIPHER_CTX");
    }
}

EVPContext::~EVPContext() {
    if (ctx_) {
        EVP_CIPHER_CTX_free(ctx_);
    }
}

EVPMDContext::EVPMDContext() : ctx_(EVP_MD_CTX_new()) {
    if (!ctx_) {
        throw CryptoException("Failed to create EVP_MD_CTX");
    }
}

EVPMDContext::~EVPMDContext() {
    if (ctx_) {
        EVP_MD_CTX_free(ctx_);
    }
}

// CryptoManager implementation
CryptoManager::CryptoManager() {
    initialize_openssl();
}

CryptoManager::~CryptoManager() {
    cleanup_openssl();
}

void CryptoManager::initialize_openssl() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    if (!RAND_poll()) {
        throw CryptoException("Failed to initialize random number generator");
    }
}

void CryptoManager::cleanup_openssl() {
    EVP_cleanup();
    ERR_free_strings();
}

KeyPair CryptoManager::generate_rsa_keypair(size_t bits) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        throw CryptoException("Failed to create RSA key generation context");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw CryptoException("Failed to initialize RSA key generation");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw CryptoException("Failed to set RSA key size");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw CryptoException("Failed to generate RSA key pair");
    }

    EVP_PKEY_CTX_free(ctx);

    KeyPair keypair;
    keypair.private_key = rsa_private_key_to_bytes(pkey);
    keypair.public_key = rsa_public_key_to_bytes(pkey);
    keypair.created_at = get_current_timestamp();
    keypair.expires_at = keypair.created_at + std::chrono::hours(24);

    EVP_PKEY_free(pkey);
    return keypair;
}

KeyPair CryptoManager::generate_dh_keypair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);
    if (!ctx) {
        throw CryptoException("Failed to create DH key generation context");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw CryptoException("Failed to initialize DH key generation");
    }

    // OpenSSL 3.x will not generate a DH key without domain parameters.
    // ffdhe2048 (RFC 7919) gives both peers the same group with no paramgen round trip.
    if (EVP_PKEY_CTX_set_dh_nid(ctx, NID_ffdhe2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw CryptoException("Failed to set DH group parameters");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw CryptoException("Failed to generate DH key pair");
    }

    EVP_PKEY_CTX_free(ctx);

    KeyPair keypair;
    keypair.private_key = rsa_private_key_to_bytes(pkey);
    keypair.public_key = rsa_public_key_to_bytes(pkey);
    keypair.created_at = get_current_timestamp();
    keypair.expires_at = keypair.created_at + std::chrono::hours(1);

    EVP_PKEY_free(pkey);
    return keypair;
}

std::vector<uint8_t> CryptoManager::generate_symmetric_key(size_t size) {
    return generate_random_bytes(size);
}

std::vector<uint8_t> CryptoManager::encrypt_aes_gcm(const std::vector<uint8_t>& data,
                                                   const std::vector<uint8_t>& key,
                                                   const std::vector<uint8_t>& iv,
                                                   const std::vector<uint8_t>& aad) {
    // OpenSSL reads a full key and IV whatever the vectors hold.
    if (key.size() != KEY_SIZE || iv.size() != IV_SIZE) {
        throw CryptoException("AES-GCM needs a 32-byte key and a 12-byte IV");
    }
    EVPContext ctx;
    const EVP_CIPHER* cipher = EVP_aes_256_gcm();

    if (EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, key.data(), iv.data()) != 1) {
        throw CryptoException("Failed to initialize AES-GCM encryption");
    }

    std::vector<uint8_t> encrypted(data.size() + EVP_MAX_BLOCK_LENGTH);
    int len;

    if (!aad.empty() &&
        EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) {
        throw CryptoException("Failed to add associated data");
    }
    
    if (EVP_EncryptUpdate(ctx.get(), encrypted.data(), &len, data.data(), static_cast<int>(data.size())) != 1) {
        throw CryptoException("Failed to encrypt data");
    }

    int final_len;
    if (EVP_EncryptFinal_ex(ctx.get(), encrypted.data() + len, &final_len) != 1) {
        throw CryptoException("Failed to finalize encryption");
    }

    encrypted.resize(len + final_len);

    // GCM is only authenticated if the tag travels with the ciphertext, so append it.
    std::vector<uint8_t> tag(GCM_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(GCM_TAG_SIZE), tag.data()) != 1) {
        throw CryptoException("Failed to get GCM authentication tag");
    }

    encrypted.insert(encrypted.end(), tag.begin(), tag.end());
    return encrypted;
}

std::vector<uint8_t> CryptoManager::decrypt_aes_gcm(const std::vector<uint8_t>& encrypted_data,
                                                   const std::vector<uint8_t>& key,
                                                   const std::vector<uint8_t>& iv,
                                                   const std::vector<uint8_t>& aad) {
    if (key.size() != KEY_SIZE || iv.size() != IV_SIZE) {
        throw CryptoException("AES-GCM needs a 32-byte key and a 12-byte IV");
    }
    EVPContext ctx;
    const EVP_CIPHER* cipher = EVP_aes_256_gcm();

    if (EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, key.data(), iv.data()) != 1) {
        throw CryptoException("Failed to initialize AES-GCM decryption");
    }

    // The trailing GCM_TAG_SIZE bytes are the authentication tag appended by encrypt_aes_gcm.
    if (encrypted_data.size() < GCM_TAG_SIZE) {
        throw CryptoException("Encrypted data is too short to contain a GCM tag");
    }

    const size_t ciphertext_len = encrypted_data.size() - GCM_TAG_SIZE;

    std::vector<uint8_t> decrypted(ciphertext_len);
    int len;

    if (!aad.empty() &&
        EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) {
        throw CryptoException("Failed to add associated data");
    }

    if (EVP_DecryptUpdate(ctx.get(), decrypted.data(), &len, encrypted_data.data(), static_cast<int>(ciphertext_len)) != 1) {
        throw CryptoException("Failed to decrypt data");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(GCM_TAG_SIZE),
                            const_cast<uint8_t*>(encrypted_data.data() + ciphertext_len)) != 1) {
        throw CryptoException("Failed to set GCM authentication tag");
    }

    int final_len;
    if (EVP_DecryptFinal_ex(ctx.get(), decrypted.data() + len, &final_len) != 1) {
        throw CryptoException("Failed to finalize decryption");
    }

    decrypted.resize(len + final_len);
    return decrypted;
}

IdentityKey CryptoManager::generate_identity() {
    return identity_from_private(generate_random_bytes(32));
}

IdentityKey CryptoManager::identity_from_private(const std::vector<uint8_t>& private_raw) {
    if (private_raw.size() != 32) {
        throw CryptoException("Identity private key must be 32 bytes");
    }
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, private_raw.data(), 32);
    if (!pkey) {
        throw CryptoException("Failed to load identity key");
    }
    IdentityKey key;
    key.private_raw = private_raw;
    key.public_raw.resize(32);
    size_t len = 32;
    const int ok = EVP_PKEY_get_raw_public_key(pkey, key.public_raw.data(), &len);
    EVP_PKEY_free(pkey);
    if (ok != 1 || len != 32) {
        throw CryptoException("Failed to derive identity public key");
    }
    return key;
}

std::vector<uint8_t> CryptoManager::identity_sign(const IdentityKey& key, const std::vector<uint8_t>& message) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, key.private_raw.data(),
                                                  key.private_raw.size());
    if (!pkey) {
        throw CryptoException("Failed to load identity key");
    }
    EVPMDContext md;
    std::vector<uint8_t> sig(64);
    size_t sig_len = sig.size();
    const bool ok = EVP_DigestSignInit(md.get(), nullptr, nullptr, nullptr, pkey) == 1 &&
                    EVP_DigestSign(md.get(), sig.data(), &sig_len, message.data(), message.size()) == 1;
    EVP_PKEY_free(pkey);
    if (!ok || sig_len != 64) {
        throw CryptoException("Failed to sign with identity key");
    }
    return sig;
}

bool CryptoManager::identity_verify(const std::vector<uint8_t>& public_raw, const std::vector<uint8_t>& message,
                                    const std::vector<uint8_t>& signature) {
    if (public_raw.size() != 32 || signature.size() != 64) {
        return false;
    }
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_raw.data(), 32);
    if (!pkey) {
        return false;
    }
    EVPMDContext md;
    const bool ok = EVP_DigestVerifyInit(md.get(), nullptr, nullptr, nullptr, pkey) == 1 &&
                    EVP_DigestVerify(md.get(), signature.data(), signature.size(), message.data(),
                                     message.size()) == 1;
    EVP_PKEY_free(pkey);
    return ok;
}

std::string CryptoManager::generate_room_code() {
    static const char alphabet[] = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    constexpr unsigned size = sizeof(alphabet) - 1;  // 31
    std::string code;
    while (code.size() < 6) {
        // Rejection sampling keeps every character equally likely.
        const uint8_t b = generate_random_bytes(1)[0];
        if (b < 248) {  // 248 = 8 * 31
            code.push_back(alphabet[b % size]);
        }
    }
    return code;
}

std::string safety_code(const std::vector<uint8_t>& public_raw) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_Digest(public_raw.data(), public_raw.size(), digest, &len, EVP_sha256(), nullptr);
    std::string out;
    for (int group = 0; group < 5; ++group) {
        // Four digits from two bytes of the hash each.
        const unsigned value = ((static_cast<unsigned>(digest[group * 2]) << 8) | digest[group * 2 + 1]) % 10000;
        char buf[6];
        std::snprintf(buf, sizeof(buf), "%04u", value);
        if (!out.empty()) {
            out += ' ';
        }
        out += buf;
    }
    return out;
}

std::string normalize_room_code(const std::string& code) {
    std::string out;
    for (char c : code) {
        if (c == '-' || c == ' ') {
            continue;
        }
        out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
    return out;
}

std::string format_room_code(const std::string& code) {
    const std::string n = normalize_room_code(code);
    return n.size() == 6 ? n.substr(0, 3) + "-" + n.substr(3) : n;
}

std::vector<uint8_t> x25519_generate_private() {
    EVP_PKEY* key = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    const bool made = ctx != nullptr && EVP_PKEY_keygen_init(ctx) > 0 && EVP_PKEY_keygen(ctx, &key) > 0;
    EVP_PKEY_CTX_free(ctx);
    std::vector<uint8_t> raw(32);
    size_t len = raw.size();
    const bool ok = made && EVP_PKEY_get_raw_private_key(key, raw.data(), &len) > 0 && len == 32;
    EVP_PKEY_free(key);
    if (!ok) {
        throw std::runtime_error("Could not create an X25519 key");
    }
    return raw;
}

std::vector<uint8_t> x25519_public_from_private(const std::vector<uint8_t>& private_raw) {
    if (private_raw.size() != 32) {
        throw std::runtime_error("An X25519 key must be 32 bytes");
    }
    EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_raw.data(), 32);
    std::vector<uint8_t> raw(32);
    size_t len = raw.size();
    const bool ok = key != nullptr && EVP_PKEY_get_raw_public_key(key, raw.data(), &len) > 0 && len == 32;
    EVP_PKEY_free(key);
    if (!ok) {
        throw std::runtime_error("Bad X25519 key");
    }
    return raw;
}

std::vector<uint8_t> e2e_shared_key(const std::vector<uint8_t>& my_private,
                                    const std::vector<uint8_t>& their_public) {
    if (my_private.size() != 32 || their_public.size() != 32) {
        throw std::runtime_error("An X25519 key must be 32 bytes");
    }
    const std::vector<uint8_t> my_public = x25519_public_from_private(my_private);
    EVP_PKEY* mine = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, my_private.data(), 32);
    EVP_PKEY* theirs = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, their_public.data(), 32);
    EVP_PKEY_CTX* ctx = mine != nullptr && theirs != nullptr ? EVP_PKEY_CTX_new(mine, nullptr) : nullptr;
    std::vector<uint8_t> secret(32);
    size_t len = secret.size();
    // OpenSSL refuses a peer key that would give an all-zero secret.
    bool ok = ctx != nullptr && EVP_PKEY_derive_init(ctx) > 0 && EVP_PKEY_derive_set_peer(ctx, theirs) > 0 &&
              EVP_PKEY_derive(ctx, secret.data(), &len) > 0 && len == 32;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(mine);
    EVP_PKEY_free(theirs);

    // Both public keys go into the key, lower one first so both sides agree.
    std::string info = "intercli e2e v1";
    const bool mine_first = my_public < their_public;
    const std::vector<uint8_t>& first = mine_first ? my_public : their_public;
    const std::vector<uint8_t>& second = mine_first ? their_public : my_public;
    info.append(first.begin(), first.end());
    info.append(second.begin(), second.end());

    std::vector<uint8_t> key(KEY_SIZE);
    size_t key_len = key.size();
    EVP_PKEY_CTX* kdf = ok ? EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr) : nullptr;
    ok = kdf != nullptr && EVP_PKEY_derive_init(kdf) > 0 &&
         EVP_PKEY_CTX_set_hkdf_md(kdf, EVP_sha256()) > 0 &&
         EVP_PKEY_CTX_set1_hkdf_key(kdf, secret.data(), static_cast<int>(secret.size())) > 0 &&
         EVP_PKEY_CTX_add1_hkdf_info(kdf, reinterpret_cast<const unsigned char*>(info.data()),
                                     static_cast<int>(info.size())) > 0 &&
         EVP_PKEY_derive(kdf, key.data(), &key_len) > 0 && key_len == KEY_SIZE;
    EVP_PKEY_CTX_free(kdf);
    OPENSSL_cleanse(secret.data(), secret.size());
    if (!ok) {
        throw std::runtime_error("Could not agree on a key");
    }
    return key;
}

std::string pair_safety_code(const std::vector<uint8_t>& public_a, const std::vector<uint8_t>& public_b) {
    std::vector<uint8_t> both = public_a < public_b ? public_a : public_b;
    const std::vector<uint8_t>& second = public_a < public_b ? public_b : public_a;
    both.insert(both.end(), second.begin(), second.end());
    return safety_code(both);
}

std::vector<uint8_t> CryptoManager::perform_dh_key_exchange(const std::vector<uint8_t>& private_key,
                                                           const std::vector<uint8_t>& peer_public_key) {
    EVP_PKEY* priv_key = bytes_to_rsa_private_key(private_key);
    EVP_PKEY* pub_key = nullptr;
    try {
        // The peer's key comes off the network; a bad one must not leak ours.
        pub_key = bytes_to_rsa_public_key(peer_public_key);
    } catch (...) {
        EVP_PKEY_free(priv_key);
        throw;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(pub_key);
        throw CryptoException("Failed to create DH key exchange context");
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(pub_key);
        throw CryptoException("Failed to initialize DH key derivation");
    }

    if (EVP_PKEY_derive_set_peer(ctx, pub_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(pub_key);
        throw CryptoException("Failed to set peer public key");
    }

    size_t secret_len;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(pub_key);
        throw CryptoException("Failed to get secret length");
    }

    std::vector<uint8_t> secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(pub_key);
        throw CryptoException("Failed to derive shared secret");
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(pub_key);

    return secret;
}

std::vector<uint8_t> CryptoManager::derive_shared_secret(const std::vector<uint8_t>& dh_result,
                                                        const std::vector<uint8_t>& salt) {
    return derive_key(dh_result, salt, KEY_SIZE);
}

SessionKeys CryptoManager::derive_directional_keys(const std::vector<uint8_t>& shared_secret,
                                                   const std::vector<uint8_t>& nonce,
                                                   bool is_server) {
    // Two distinct salts give two independent keys from one shared secret, so each
    // direction can be rotated by its own sender without disturbing the other.
    std::vector<uint8_t> c2s_salt = nonce;
    c2s_salt.push_back(0x01);
    std::vector<uint8_t> s2c_salt = nonce;
    s2c_salt.push_back(0x02);

    std::vector<uint8_t> client_to_server = derive_shared_secret(shared_secret, c2s_salt);
    std::vector<uint8_t> server_to_client = derive_shared_secret(shared_secret, s2c_salt);

    SessionKeys keys;
    if (is_server) {
        keys.tx_key = server_to_client;
        keys.rx_key = client_to_server;
    } else {
        keys.tx_key = client_to_server;
        keys.rx_key = server_to_client;
    }
    return keys;
}

std::vector<uint8_t> CryptoManager::sha256_hash(const std::vector<uint8_t>& data) {
    EVPMDContext ctx;
    unsigned int hash_len = EVP_MD_size(EVP_sha256());
    std::vector<uint8_t> hash(hash_len);

    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        throw CryptoException("Failed to initialize SHA256");
    }

    if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1) {
        throw CryptoException("Failed to update SHA256");
    }

    if (EVP_DigestFinal_ex(ctx.get(), hash.data(), &hash_len) != 1) {
        throw CryptoException("Failed to finalize SHA256");
    }

    return hash;
}

std::vector<uint8_t> CryptoManager::hmac_sha256(const std::vector<uint8_t>& data,
                                               const std::vector<uint8_t>& key) {
    unsigned int hmac_len = EVP_MD_size(EVP_sha256());
    std::vector<uint8_t> hmac(hmac_len);

    if (HMAC(EVP_sha256(), key.data(), key.size(), data.data(), data.size(), 
             hmac.data(), &hmac_len) == nullptr) {
        throw CryptoException("Failed to compute HMAC-SHA256");
    }

    return hmac;
}

std::vector<uint8_t> CryptoManager::sign_data(const std::vector<uint8_t>& data,
                                             const std::vector<uint8_t>& private_key) {
    EVP_PKEY* pkey = bytes_to_rsa_private_key(private_key);
    EVPMDContext ctx;

    if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey) != 1) {
        EVP_PKEY_free(pkey);
        throw CryptoException("Failed to initialize signature");
    }

    size_t sig_len;
    if (EVP_DigestSign(ctx.get(), nullptr, &sig_len, data.data(), data.size()) != 1) {
        EVP_PKEY_free(pkey);
        throw CryptoException("Failed to get signature length");
    }

    std::vector<uint8_t> signature(sig_len);
    if (EVP_DigestSign(ctx.get(), signature.data(), &sig_len, data.data(), data.size()) != 1) {
        EVP_PKEY_free(pkey);
        throw CryptoException("Failed to create signature");
    }

    EVP_PKEY_free(pkey);
    return signature;
}

bool CryptoManager::verify_signature(const std::vector<uint8_t>& data,
                                   const std::vector<uint8_t>& signature,
                                   const std::vector<uint8_t>& public_key) {
    EVP_PKEY* pkey = bytes_to_rsa_public_key(public_key);
    EVPMDContext ctx;

    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey) != 1) {
        EVP_PKEY_free(pkey);
        return false;
    }

    int result = EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), 
                                 data.data(), data.size());
    EVP_PKEY_free(pkey);
    
    return result == 1;
}

std::vector<uint8_t> CryptoManager::generate_random_bytes(size_t size) {
    std::vector<uint8_t> random_bytes(size);
    if (RAND_bytes(random_bytes.data(), size) != 1) {
        throw CryptoException("Failed to generate random bytes");
    }
    return random_bytes;
}

uint32_t CryptoManager::generate_random_uint32() {
    uint32_t value;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(value)) != 1) {
        throw CryptoException("Failed to generate random uint32");
    }
    return value;
}

std::vector<uint8_t> CryptoManager::derive_key(const std::vector<uint8_t>& master_key,
                                              const std::vector<uint8_t>& salt,
                                              size_t key_size) {
    std::vector<uint8_t> derived_key(key_size);
    
    if (PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(master_key.data()), master_key.size(),
                          salt.data(), salt.size(), 10000, EVP_sha256(), key_size, 
                          derived_key.data()) != 1) {
        throw CryptoException("Failed to derive key");
    }
    
    return derived_key;
}

std::vector<uint8_t> CryptoManager::rotate_session_key(const std::vector<uint8_t>& current_key,
                                                      const std::vector<uint8_t>& session_id) {
    std::vector<uint8_t> salt = sha256_hash(session_id);
    return derive_key(current_key, salt, KEY_SIZE);
}

// Private helper methods
std::vector<uint8_t> CryptoManager::rsa_private_key_to_bytes(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw CryptoException("Failed to create BIO for private key");
    }

    if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        BIO_free(bio);
        throw CryptoException("Failed to write private key to BIO");
    }

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::vector<uint8_t> key_data(bptr->data, bptr->data + bptr->length);
    BIO_free(bio);

    return key_data;
}

std::vector<uint8_t> CryptoManager::rsa_public_key_to_bytes(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw CryptoException("Failed to create BIO for public key");
    }

    if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
        BIO_free(bio);
        throw CryptoException("Failed to write public key to BIO");
    }

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::vector<uint8_t> key_data(bptr->data, bptr->data + bptr->length);
    BIO_free(bio);

    return key_data;
}

EVP_PKEY* CryptoManager::bytes_to_rsa_private_key(const std::vector<uint8_t>& data) {
    BIO* bio = BIO_new_mem_buf(data.data(), data.size());
    if (!bio) {
        throw CryptoException("Failed to create BIO from private key data");
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        throw CryptoException("Failed to read private key from BIO");
    }

    return pkey;
}

EVP_PKEY* CryptoManager::bytes_to_rsa_public_key(const std::vector<uint8_t>& data) {
    BIO* bio = BIO_new_mem_buf(data.data(), data.size());
    if (!bio) {
        throw CryptoException("Failed to create BIO from public key data");
    }

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        throw CryptoException("Failed to read public key from BIO");
    }

    return pkey;
}

// KeyManager implementation
KeyManager::KeyManager() = default;
KeyManager::~KeyManager() = default;

void KeyManager::store_key(const std::string& key_id, const std::vector<uint8_t>& key) {
    std::lock_guard<std::mutex> lock(keys_mutex_);
    keys_[key_id] = key;
}

std::vector<uint8_t> KeyManager::get_key(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(keys_mutex_);
    auto it = keys_.find(key_id);
    if (it == keys_.end()) {
        throw CryptoException("Key not found: " + key_id);
    }
    return it->second;
}

void KeyManager::remove_key(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(keys_mutex_);
    keys_.erase(key_id);
    key_expirations_.erase(key_id);
}

bool KeyManager::key_exists(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(keys_mutex_);
    return keys_.find(key_id) != keys_.end();
}

void KeyManager::rotate_key(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(keys_mutex_);
    auto it = keys_.find(key_id);
    if (it != keys_.end()) {
        // Generate new key based on current key
        CryptoManager crypto;
        std::vector<uint8_t> salt = crypto.generate_random_bytes(32);
        it->second = crypto.derive_key(it->second, salt, KEY_SIZE);
    }
}

std::vector<uint8_t> KeyManager::generate_new_key(const std::string& key_id) {
    CryptoManager crypto;
    std::vector<uint8_t> new_key = crypto.generate_symmetric_key(KEY_SIZE);
    store_key(key_id, new_key);
    return new_key;
}

void KeyManager::set_key_expiration(const std::string& key_id, 
                                   std::chrono::system_clock::time_point expires_at) {
    std::lock_guard<std::mutex> lock(keys_mutex_);
    key_expirations_[key_id] = expires_at;
}

bool KeyManager::is_key_expired(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(keys_mutex_);
    auto it = key_expirations_.find(key_id);
    if (it == key_expirations_.end()) {
        return false; // No expiration set
    }
    return std::chrono::system_clock::now() > it->second;
}

void KeyManager::backup_keys(const std::string& backup_path) {
    // Implementation for key backup
    // This would typically encrypt and store keys to a secure location
}

void KeyManager::restore_keys(const std::string& backup_path) {
    // Implementation for key restoration
    // This would typically decrypt and load keys from a secure location
}

// SessionManager implementation
SessionManager::SessionManager() = default;
SessionManager::~SessionManager() = default;

SessionInfo SessionManager::create_session(uint32_t client_id) {
    SessionInfo session;
    session.session_id = generate_session_id();
    session.client_id = client_id;
    session.created_at = get_current_timestamp();
    session.last_activity = session.created_at;
    session.message_counter = 0;
    session.authenticated = false;
    session.key_rotated = false;

    std::lock_guard<std::mutex> lock(sessions_mutex_);
    sessions_[session.session_id] = session;
    return session;
}

SessionInfo SessionManager::get_session(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        throw CryptoException("Session not found: " + std::to_string(session_id));
    }
    return it->second;
}

void SessionManager::update_session_activity(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        it->second.last_activity = get_current_timestamp();
        it->second.message_counter++;
    }
}

void SessionManager::remove_session(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    sessions_.erase(session_id);
}

bool SessionManager::session_exists(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    return sessions_.find(session_id) != sessions_.end();
}

bool SessionManager::authenticate_session(uint32_t session_id, const std::vector<uint8_t>& auth_data) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        // Simple authentication - in real implementation, this would verify credentials
        it->second.authenticated = true;
        return true;
    }
    return false;
}

AuthResult SessionManager::verify_session_auth(uint32_t session_id, const std::vector<uint8_t>& signature) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        return AuthResult::UNKNOWN_CLIENT;
    }

    if (!it->second.authenticated) {
        return AuthResult::INVALID_SIGNATURE;
    }

    // Check if session is expired (24 hours)
    auto now = get_current_timestamp();
    if (now - it->second.created_at > std::chrono::hours(24)) {
        return AuthResult::EXPIRED_SESSION;
    }

    return AuthResult::SUCCESS;
}

static std::vector<uint8_t> session_id_to_bytes(uint32_t session_id) {
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&session_id),
                                reinterpret_cast<const uint8_t*>(&session_id) + sizeof(session_id));
}

void SessionManager::set_session_keys(uint32_t session_id, const SessionKeys& keys) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        it->second.tx_key = keys.tx_key;
        it->second.rx_key = keys.rx_key;
    }
}

std::vector<uint8_t> SessionManager::get_tx_key(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        throw CryptoException("Session not found: " + std::to_string(session_id));
    }
    return it->second.tx_key;
}

std::vector<uint8_t> SessionManager::get_rx_key(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        throw CryptoException("Session not found: " + std::to_string(session_id));
    }
    return it->second.rx_key;
}

void SessionManager::rotate_tx_key(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        it->second.tx_key = crypto_manager_.rotate_session_key(it->second.tx_key,
                                                               session_id_to_bytes(session_id));
        it->second.key_rotated = true;
    }
}

void SessionManager::rotate_rx_key(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        it->second.rx_key = crypto_manager_.rotate_session_key(it->second.rx_key,
                                                               session_id_to_bytes(session_id));
    }
}

void SessionManager::cleanup_expired_sessions(std::chrono::seconds max_age) {
    auto now = get_current_timestamp();
    std::vector<uint32_t> expired_sessions;

    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (const auto& pair : sessions_) {
            if (now - pair.second.created_at > max_age) {
                expired_sessions.push_back(pair.first);
            }
        }
    }

    for (uint32_t session_id : expired_sessions) {
        remove_session(session_id);
    }
}

std::vector<uint32_t> SessionManager::get_expired_sessions(std::chrono::seconds max_age) {
    auto now = get_current_timestamp();
    std::vector<uint32_t> expired_sessions;

    std::lock_guard<std::mutex> lock(sessions_mutex_);
    for (const auto& pair : sessions_) {
        if (now - pair.second.created_at > max_age) {
            expired_sessions.push_back(pair.first);
        }
    }

    return expired_sessions;
}

// Utility functions

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw CryptoException("Hex text must have an even number of digits");
    }
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        if (!std::isxdigit(static_cast<unsigned char>(hex[i])) ||
            !std::isxdigit(static_cast<unsigned char>(hex[i + 1]))) {
            throw CryptoException("Hex text contains a character that is not a hex digit");
        }
        bytes.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

std::string base64_encode(const std::vector<uint8_t>& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);

    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    std::string result(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);

    return result;
}

std::vector<uint8_t> base64_decode(const std::string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.c_str(), encoded.length());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    std::vector<uint8_t> decoded(encoded.length());
    int decoded_len = BIO_read(bio, decoded.data(), decoded.size());
    BIO_free_all(bio);

    if (decoded_len < 0) {
        throw CryptoException("Failed to decode base64");
    }

    decoded.resize(decoded_len);
    return decoded;
}

bool constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) {
        return false;
    }
    
    int result = 0;
    for (size_t i = 0; i < a.size(); i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

void log_crypto_error(const std::string& operation) {
    std::cerr << "Crypto error in " << operation << ": " << get_openssl_error_string() << std::endl;
}

std::string get_openssl_error_string() {
    BIO* bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    std::string error_string(buffer_ptr->data, buffer_ptr->length);
    BIO_free(bio);
    return error_string;
}

} // namespace SecureComm 