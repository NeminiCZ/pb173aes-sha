#include "mbedtls/aes.h"
#include "mbedtls/sha512.h"
#include <string>

class cryptFun {
private:
	unsigned char* key;
	unsigned char* iv;
	mbedtls_aes_context aesContext;
	mbedtls_sha512_context shaContext;
public:
	cryptFun(unsigned char key[16], unsigned char iv[16])
	: key(key), iv(iv)
	{
		mbedtls_aes_init(&aesContext);
		mbedtls_sha512_init(&shaContext);	
	};

	int readFile(std::string fileName, unsigned char*& fileContents, size_t& fileSize);
	void writeFile(std::string fileName, unsigned char* fileContents, size_t fileSize);
	int encryptAndHash(unsigned char* input, size_t inputSize, unsigned char*& output, size_t& outputSize);
	int decryptAndVerify(unsigned char* input, size_t inputSize, unsigned char*& output, size_t& outputSize);
private:
	int fixPadding(unsigned char* fileContents, size_t fileSize);
};