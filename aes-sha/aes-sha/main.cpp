#include <iostream>
#include <fstream>
#include <vector>
#include "mbedtls/aes.h"
#include "mbedtls/sha512.h"
using namespace std;

#define MODE_ENCRYPT 0
#define MODE_DECRYPT 1

int main(int argc, char *argv[]) {

	if (argc != 3) {
		cerr << "Invalid number of arguments. Usage: mode inputFile" << endl;
		cerr << "mode: 0 enc, 1 dec" << endl;
		return 1;
	}
	int mode;

	mode = argv[1][0] - '0';
	if (mode < 0 || mode > 1) {
		cerr << "Invalid mode" << endl;
		cerr << endl << "mode: 0 enc, 1 dec" << endl;
		return 1;
	}

	string fileName = argv[2];
	size_t fileSize;
	size_t roundSize;
	unsigned char key[16] = { 0x09, 0x0F, 0x05, 0x0C, 0x0A, 0x0B, 0x0B, 0x0C, 0x0D, 0x0D, 0x0E, 0x03, 0x04, 0x05, 0x07, 0x0D };
	unsigned char iv[16] = { 0x0F, 0x02, 0x08, 0x04, 0x03, 0x08, 0x06, 0x0F, 0x0E, 0x07, 0x05, 0x07, 0x0D, 0x05, 0x07, 0x0D };
	unsigned char *in;
	unsigned char *out;
	unsigned char hash[64];
	string encSuffix = ".enc";
	string decSuffix = ".dec";
	mbedtls_aes_context aesContext;
	mbedtls_sha512_context shaContext;

	//reading input file
	ifstream inputFile(fileName, ios_base::binary);

	if (!inputFile.is_open()) {
		cerr << "Unable to open input file." << endl;
		return 1;
	}

	inputFile.seekg(0, ios::end);
	fileSize = (size_t)inputFile.tellg();
	inputFile.seekg(0, ios::beg);

	roundSize = fileSize;
	if ((roundSize % 16) != 0) roundSize = fileSize + 16 - (fileSize % 16);

	vector<char> bytes(fileSize);
	inputFile.read(&bytes[0], fileSize);

	in = new unsigned char[roundSize];
	out = new unsigned char[roundSize];

	in = (unsigned char*)bytes.data();
	
	

	mbedtls_aes_init(&aesContext);
	mbedtls_sha512_init(&shaContext);
	
	//encrypt

	if (mode == MODE_ENCRYPT) {
		//padding
		size_t diff = roundSize - fileSize;
		memset(in + fileSize, diff, diff);
		//hash
		mbedtls_sha512(in, fileSize, hash, 0);
		
		mbedtls_aes_setkey_enc(&aesContext, key, 128);

		mbedtls_aes_crypt_cbc(&aesContext, MBEDTLS_AES_ENCRYPT, roundSize, iv, in, out);

		//output
		ofstream output(fileName + encSuffix, ios::binary);
		output.write((char*)hash, 64); //hash is added at begining of file
		output.write((char*)out, roundSize);
		output.close();
	}

	//decrypt

	if (mode == MODE_DECRYPT) {
		memcpy(hash, in, 64); //fetch hash from beg of file
		size_t outputSize = roundSize - 64;
		mbedtls_aes_setkey_dec(&aesContext, key, 128);
		mbedtls_aes_crypt_cbc(&aesContext, MBEDTLS_AES_DECRYPT, outputSize, iv, in + 64, out);

		//remove padding
		if (out[outputSize - 1] < 16) {
			outputSize = outputSize - out[outputSize - 1];
		}

		//compare hash
		unsigned char decryptedHash[64];
		mbedtls_sha512(out, outputSize, decryptedHash, 0);
		if (memcmp(hash, decryptedHash, 64)) {
			cerr << "Hashes are not equal, file was corrupted.";
		}

		//output
		ofstream output(fileName + decSuffix, ios::binary);
		output.write((char*)out, outputSize);
		output.close();
	}

	//clean

	memset(in, 0, roundSize);
	memset(key, 0, 16);
	memset(iv, 0, 16);
	
	return 0;
}
