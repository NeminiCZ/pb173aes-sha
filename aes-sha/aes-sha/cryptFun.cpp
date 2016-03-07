#include "cryptFun.h"
#include <iostream>
#include <fstream>
#include <vector>

using namespace std;


int cryptFun::fixPadding(unsigned char* fileContents, size_t fileSize) {
	int padding = 16 - (fileSize % 16);
	if (padding != 0) {
		memset(fileContents + fileSize, padding, padding);
	}
	return padding;
}

int cryptFun::readFile(string fileName, unsigned char*& fileContents, size_t& fileSize) {

	ifstream inputFile(fileName, ios_base::binary);

	if (!inputFile.is_open()) {
		return 1;
	}

	inputFile.seekg(0, ios::end);
	fileSize = (size_t)inputFile.tellg();
	inputFile.seekg(0, ios::beg);

	fileContents = new unsigned char[fileSize + 16];
	inputFile.read((char*)fileContents, fileSize);

	return 0;
}

void cryptFun::writeFile(string fileName, unsigned char* fileContents, size_t fileSize) {

	ofstream output(fileName, ios::binary);
	output.write((char*)fileContents, fileSize);
	output.close();

}

int cryptFun::encryptAndHash(unsigned char* input, size_t inputSize,unsigned char*& output, size_t& outputSize) {
	unsigned char hash[64];
	int padding = fixPadding(input, inputSize);
	size_t inputSizeWithPadding = inputSize + padding;
	//hash
	mbedtls_sha512(input, inputSize, hash, 0);

	output = new unsigned char[inputSizeWithPadding + 64];
	memcpy(output, hash, 64);
	mbedtls_aes_setkey_enc(&aesContext, key, 128);

	mbedtls_aes_crypt_cbc(&aesContext, MBEDTLS_AES_ENCRYPT, inputSizeWithPadding, iv, input, output + 64);
	outputSize = inputSizeWithPadding + 64;
	return 0;
}
int cryptFun::decryptAndVerify(unsigned char* input, size_t inputSize, unsigned char*& output, size_t &outputSize) {
	unsigned char hash[64];
	memcpy(hash, input, 64); //fetch hash from beg of file
	outputSize = inputSize - 64;
	output = new unsigned char[outputSize];

	mbedtls_aes_setkey_dec(&aesContext, key, 128);
	mbedtls_aes_crypt_cbc(&aesContext, MBEDTLS_AES_DECRYPT, outputSize, iv, input + 64, output);

	//remove padding
	if (output[outputSize - 1] < 16) {
		outputSize = outputSize - output[outputSize - 1];
	}

	//compare hash
	unsigned char decryptedHash[64];
	mbedtls_sha512(output, outputSize, decryptedHash, 0);
	if (memcmp(hash, decryptedHash, 64)) {
		return 1;
	}

	return 0;
}