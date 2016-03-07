#ifndef CRYPTFUN_H
#define CRYPTFUN_H

#include "mbedtls/aes.h"
#include "mbedtls/sha512.h"
#include <string>
#include <cstring>

class cryptFun {
private:
	unsigned char* key;
	unsigned char* iv;
	mbedtls_aes_context aesContext;
	mbedtls_sha512_context shaContext;
public:
	cryptFun(unsigned char _key[16], unsigned char _iv[16])
		: key(new unsigned char[16]), iv(new unsigned char[16])
	{
		std::memcpy(key, _key, 16);
		std::memcpy(iv, _iv, 16);
		mbedtls_aes_init(&aesContext);
		mbedtls_sha512_init(&shaContext);	
	};
	~cryptFun() {
		delete[] key;
		delete[] iv;
	}

	int readFile(std::string fileName, unsigned char*& fileContents, size_t& fileSize);
	void writeFile(std::string fileName, unsigned char* fileContents, size_t fileSize);
	int encryptAndHash(unsigned char* input, size_t inputSize, unsigned char*& output, size_t& outputSize);
	int decryptAndVerify(unsigned char* input, size_t inputSize, unsigned char*& output, size_t& outputSize);
private:
	int fixPadding(unsigned char* fileContents, size_t fileSize);
};

#endif CRYPTFUN_H