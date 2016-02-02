#pragma once

#include <vector>

#include "SymmetricKey.h"

namespace openssl
{
	struct evp_pkey_ctx_st;
	typedef evp_pkey_ctx_st EVP_PKEY_CTX;

	struct evp_pkey_st;
	typedef evp_pkey_st EVP_PKEY;
}

class Crypto
{
public:
	//Initalizes the random pool and generates parameters for key generation
	Crypto();
	//Encrypt plaintext with a given key and IV
	std::vector<unsigned char> encryptSymmetric(const SymmetricKey& key, const std::vector<unsigned char>& plaintext);
	//Decrypt ciphertext with a given key and IV
	std::vector<unsigned char> decryptSymmetric(const SymmetricKey& key, const std::vector<unsigned char>& ciphertext);

	//Generate symmetric key from password
	//Salt should be 8 bytes long, and randomly generated
	SymmetricKey deriveKeyFromPassword(const std::vector<unsigned char>& salt, const std::vector<unsigned char>& password);

private:
	openssl::EVP_PKEY_CTX* keyContext;

	openssl::EVP_PKEY_CTX* ephemeralParamContext;
	openssl::EVP_PKEY_CTX* ephemeralKeyContext;
	openssl::EVP_PKEY* ephemeralKeyParams;
};