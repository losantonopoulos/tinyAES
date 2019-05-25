#include "AES256.h"
#include <iostream>
#include <stdio.h>
#include <cstdint>
#include <cstring>
#include <cinttypes>

using namespace std;

int main(int argc, char **argv){

	uint8_t* output  = new uint8_t[BLOCK_128_SIZE];
	uint8_t* output2 = new uint8_t[BLOCK_128_SIZE];
	uint8_t* src	 = new uint8_t[BLOCK_128_SIZE]{
		0x32,0x88,0x31,0xe0,
		0x43,0x5a,0x31,0x37,
		0xf6,0x30,0x98,0x07,
		0xa8,0x8d,0xa2,0x34};

	uint8_t* my_key = new uint8_t[KEY_128_SIZE]{
		0x2b,0x28,0xab,0x09,
		0x7e,0xae,0xf7,0xcf,
		0x15,0xd2,0x15,0x4f,
		0x16,0xa6,0x88,0x3c};


	//char userKey[17] = "819B7A526D";

	if (argc < 2 ) {
		cerr << "Error: Key was not supplied..." << endl;
		return -1;
	}else if(argc > 2){
		cerr << "Error: Invalid number of arguments..." << endl;
		return -2;
	}

	AES256 myAES;
	myAES.setKey(my_key);
	if(!myAES.setUserKey(argv[1])) return -1;

	//return 0;

	cout << "\033[1;32m\nINPUT:\033[0m" << endl;
	myAES.printData(src);

	myAES.encrypt(src, src, 16);
	myAES.decrypt(src, src, 16);

	cout << "\033[1;32m\nDECRYPTED:\033[0m" << endl;
	myAES.printData(src);
	
	char msg[1025] = "Hello abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz";
	
	int nbytes = strlen(msg)+1;
	cout << "Bytes encrypted: " << myAES.encrypt((uint8_t*)msg, (uint8_t*)msg, nbytes) << endl;
	cout << "Bytes decrypted: " << myAES.decrypt((uint8_t*)msg, (uint8_t*)msg, nbytes) << endl;
	cout << msg << endl;

	delete [] output2;
	delete [] output;
	delete [] src;
	delete [] my_key;

	return 0;	
}

