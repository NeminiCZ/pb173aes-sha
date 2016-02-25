#include <iostream>
#include "mbedtls/aes.h"
using namespace std;

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

	return 0;
}
