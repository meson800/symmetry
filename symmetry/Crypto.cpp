//Copyright (c) 2016 Christopher Johnstone(meson800)
//The MIT License - See ../../LICENSE for more info
#include "Crypto.h"
#include "Exceptions.h"
#include "Log.h"

namespace openssl {
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/opensslconf.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/sha.h>

}

Crypto::Crypto()
{
	Log::writeToLog(Log::INFO, "Initalizing crypto...");
	//init openssl
	openssl::ERR_load_crypto_strings();
	openssl::OpenSSL_add_all_algorithms();
	openssl::OPENSSL_config(NULL);
	//seed random number generator
	openssl::RAND_poll();

	Log::writeToLog(Log::INFO, "Done initalizing crypto");
}



std::vector<unsigned char> Crypto::encryptSymmetric(const SymmetricKey& key, const std::vector<unsigned char>& plaintext)
{
	Log::writeToLog(Log::L_DEBUG, "Encrypting plaintext of length ", plaintext.size(), " with key ", key.toString());;
	openssl::EVP_CIPHER_CTX* cipherContext = 0;
	//init context
	if (NULL == (cipherContext = openssl::EVP_CIPHER_CTX_new()))
		throw OpensslException("Couldn't create cipher context");
	if (1 != openssl::EVP_EncryptInit_ex(cipherContext, openssl::EVP_aes_256_cbc(), NULL, key.key.data(), key.iv.data()))
		throw OpensslException("Couldn't init symmetric encryption");

	//create buffer large enough for ciphertext. Let's make it ciphertext + 1024, just in case
	unsigned char * ciphertextBuffer = new unsigned char[plaintext.size() + 1024];

	int usedLength = 0;
	if (1 != openssl::EVP_EncryptUpdate(cipherContext, ciphertextBuffer, &usedLength, plaintext.data(), plaintext.size()))
		throw OpensslException("Couldn't encrypt plaintext");
	//Finalize encryption. Additional ciphertext can be written, for padding
	int additionalLength = 0;
	if (1 != openssl::EVP_EncryptFinal(cipherContext, ciphertextBuffer + usedLength, &additionalLength))
		throw OpensslException("Couldn't finalize encryption");
	usedLength += additionalLength;

	//copy resultant
	std::vector<unsigned char> ciphertext = std::vector<unsigned char>(ciphertextBuffer, ciphertextBuffer + usedLength);
	//cleanup
	openssl::EVP_CIPHER_CTX_free(cipherContext);
	delete[](ciphertextBuffer);

	Log::writeToLog(Log::L_DEBUG, "Encrypted plaintext into ciphertext of length ", ciphertext.size());

	return ciphertext;
}

std::vector<unsigned char> Crypto::decryptSymmetric(const SymmetricKey& key, const std::vector<unsigned char>& ciphertext)
{
	Log::writeToLog(Log::L_DEBUG, "Decrypting ciphertext of length ", ciphertext.size(), " with key ", key.toString());
	openssl::EVP_CIPHER_CTX* cipherContext = 0;
	//init context
	if (NULL == (cipherContext = openssl::EVP_CIPHER_CTX_new()))
		throw OpensslException("Couldn't create cipher context");
	if (1 != openssl::EVP_DecryptInit_ex(cipherContext, openssl::EVP_aes_256_cbc(), NULL, key.key.data(), key.iv.data()))
		throw OpensslException("Couldn't init symmetric decryption");

	//do main decryption
	unsigned char * plaintextBuffer = new unsigned char[ciphertext.size() + 1024];

	int usedLength = 0;
	if (1 != openssl::EVP_DecryptUpdate(cipherContext, plaintextBuffer, &usedLength, ciphertext.data(), ciphertext.size()))
		throw OpensslException("Couldn't decrypt ciphertext");

	//finalize decryption. Additional plaintext can be written, so account for it
 	int additionalLength = 0;
	if (1 != openssl::EVP_DecryptFinal(cipherContext, plaintextBuffer + usedLength, &additionalLength))
		throw OpensslException("Couldn't finalize decryption");
	usedLength += additionalLength;
	
	//get result
	std::vector<unsigned char> plaintext = std::vector<unsigned char>(plaintextBuffer, plaintextBuffer + usedLength);
	//cleanup
	openssl::EVP_CIPHER_CTX_free(cipherContext);
	delete[](plaintextBuffer);

	Log::writeToLog(Log::L_DEBUG, "Decrypted into plaintext of length ", plaintext.size());
	
	return plaintext;
}

SymmetricKey Crypto::deriveKeyFromPassword(const std::vector<unsigned char>& salt, const std::vector<unsigned char>& password)
{
	SymmetricKey resultKey;

	unsigned char* tempKey = new unsigned char[256];
	unsigned char* iv = new unsigned char[16];

	unsigned int keyLength = 0;
	if (0 == (keyLength = openssl::EVP_BytesToKey(openssl::EVP_aes_256_cbc(), openssl::EVP_sha1(), salt.data(),
		password.data(), password.size(), 1, tempKey, iv)))
		throw OpensslException("Couldn't extract key and iv from password");

	resultKey.key = std::vector<unsigned char>(tempKey, tempKey + keyLength);
	resultKey.iv = std::vector<unsigned char>(iv, iv + 16);

	delete[](tempKey);
	delete[](iv);

	return resultKey;
}
