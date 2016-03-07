#include "cryptFun.h"

// Tell CATCH to define its main function here
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

TEST_CASE("ReadFile test") {
	unsigned char key[16] = { 0x09, 0x0F, 0x05, 0x0C, 0x0A, 0x0B, 0x0B, 0x0C, 0x0D, 0x0D, 0x0E, 0x03, 0x04, 0x05, 0x07, 0x0D };
	unsigned char iv[16] = { 0x0F, 0x02, 0x08, 0x04, 0x03, 0x08, 0x06, 0x0F, 0x0E, 0x07, 0x05, 0x07, 0x0D, 0x05, 0x07, 0x0D };
	cryptFun crypto(key, iv);
	unsigned char* contents = NULL;
	unsigned char realFileContent[5] = { "test" };
	size_t fileSize;
	CHECK(crypto.readFile("testRead.txt", contents, fileSize) == 0);
	CHECK(memcmp(contents,realFileContent, 4) == 0);
	CHECK(fileSize == 4);
	CHECK(crypto.readFile("nonexistendFile.txt", contents, fileSize) == 1);
}

TEST_CASE("Encryption -> Decryption test") {
	unsigned char key[16] = { 0x09, 0x0F, 0x05, 0x0C, 0x0A, 0x0B, 0x0B, 0x0C, 0x0D, 0x0D, 0x0E, 0x03, 0x04, 0x05, 0x07, 0x0D };
	unsigned char key2[16] = { 0x09, 0x0F, 0x05, 0x0C, 0x0A, 0x0B, 0x0B, 0x0C, 0x0D, 0x0D, 0x0E, 0x03, 0x04, 0x05, 0x08, 0x0D };
	unsigned char iv[16] = { 0x0F, 0x02, 0x08, 0x04, 0x03, 0x08, 0x06, 0x0F, 0x0E, 0x07, 0x05, 0x07, 0x0D, 0x05, 0x07, 0x0D };
	cryptFun crypto(key, iv);
	cryptFun crypto1(key, iv);
	cryptFun crypto2(key, iv);
	cryptFun cryptoDifKey(key2, iv);
	unsigned char* vanillaFileContents = NULL;
	unsigned char* encFileContents = NULL;
	unsigned char* encryptOutput = NULL;
	unsigned char* decryptOutput = NULL;
	size_t vanillaFileSize;
	size_t encryptOutputSize;
	size_t decryptOutputSize;
	crypto.readFile("testRead.txt", vanillaFileContents, vanillaFileSize);
	SECTION("readFile -> enc -> dec") {
		CHECK(crypto.encryptAndHash(vanillaFileContents, vanillaFileSize, encryptOutput, encryptOutputSize) == 0);
		CHECK(crypto1.decryptAndVerify(encryptOutput, encryptOutputSize, decryptOutput, decryptOutputSize) == 0);
	}
	crypto.readFile("testRead.txt", vanillaFileContents, vanillaFileSize);
	SECTION("dec with wrong key") {
		CHECK(crypto2.encryptAndHash(vanillaFileContents, vanillaFileSize, encryptOutput, encryptOutputSize) == 0);
		CHECK(cryptoDifKey.decryptAndVerify(encryptOutput, encryptOutputSize, decryptOutput, decryptOutputSize) == 1);
	}
	delete[] vanillaFileContents;
	delete[] encFileContents;
	delete[] encryptOutput;
	delete[] decryptOutput;
}

TEST_CASE("Encryption vector") {
	unsigned char key[16] = { 0x09, 0x0F, 0x05, 0x0C, 0x0A, 0x0B, 0x0B, 0x0C, 0x0D, 0x0D, 0x0E, 0x03, 0x04, 0x05, 0x07, 0x0D };
	unsigned char key2[16] = { 0x09, 0x0F, 0x05, 0x0C, 0x0A, 0x0B, 0x0B, 0x0C, 0x0D, 0x0D, 0x0E, 0x03, 0x04, 0x05, 0x08, 0x0D };
	unsigned char iv[16] = { 0x0F, 0x02, 0x08, 0x04, 0x03, 0x08, 0x06, 0x0F, 0x0E, 0x07, 0x05, 0x07, 0x0D, 0x05, 0x07, 0x0D };
	cryptFun crypto(key, iv);
	cryptFun crypto1(key, iv);
	cryptFun crypto2(key, iv);
	cryptFun cryptoDifKey(key2, iv);
	unsigned char* vanillaFileContents = NULL;
	unsigned char* encryptOutput = NULL;
	unsigned char* encLoadedFileContents = NULL;
	unsigned char* corruptedFileContents = NULL;
	size_t vanillaFileSize;
	size_t encryptOutputSize;
	size_t corruptedFileSize;
	size_t encLoadedFileSize;
	crypto.readFile("test.txt", vanillaFileContents, vanillaFileSize);
	crypto.readFile("test.enc.txt", encLoadedFileContents, encLoadedFileSize);
	crypto.readFile("corrupted.enc.txt", corruptedFileContents, corruptedFileSize);
	SECTION("readFile  -> enc") {
		CHECK(crypto.encryptAndHash(vanillaFileContents, vanillaFileSize, encryptOutput, encryptOutputSize) == 0);
		CHECK(encLoadedFileSize == encryptOutputSize);
		CHECK(memcmp(encryptOutput, encLoadedFileContents, encryptOutputSize) == 0);
		CHECK(memcmp(encryptOutput, corruptedFileContents, encryptOutputSize) != 0);
	}
	delete[] vanillaFileContents;
	delete[] encryptOutput;
	delete[] encLoadedFileContents;
	delete[] corruptedFileContents;
}
