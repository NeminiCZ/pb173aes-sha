#include <iostream>
#include <fstream>
#include <vector>
#include "mbedtls/aes.h"

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
	string encSuffix = ".enc";
	string decSuffix = ".dec";
	mbedtls_aes_context context;

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
	
	

	mbedtls_aes_init(&context);

	
	//encrypt

	if (mode == MODE_ENCRYPT) {
		//padding
		size_t diff = roundSize - fileSize;
		memset(in + fileSize, diff, diff);
		
		mbedtls_aes_setkey_enc(&context, key, 128);

		mbedtls_aes_crypt_cbc(&context, MBEDTLS_AES_ENCRYPT, roundSize, iv, in, out);

		//output
		ofstream output(fileName + encSuffix, ios::binary);
		output.write((char*)out, roundSize);
		output.close();
	}

	if (mode == MODE_DECRYPT) {
		mbedtls_aes_setkey_dec(&context, key, 128);
		mbedtls_aes_crypt_cbc(&context, MBEDTLS_AES_DECRYPT, roundSize, iv, in, out);

		size_t outputSize;
		//remove padding
		//doesnt work if last two chars are same
		if (out[roundSize - 1] == 1) {
			outputSize = roundSize - 1;
		}
		else if (out[roundSize - 1] == out[roundSize - 2]) {
			outputSize = roundSize - out[roundSize - 1];
		}

		//output
		ofstream output(fileName + decSuffix, ios::binary);
		output.write((char*)out, outputSize);
		output.close();
	}
	return 0;
}
