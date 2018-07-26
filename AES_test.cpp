#include "AES.h"
#include <iostream>
#include <stdio.h>
#include <cstdint>
#include <cstring>
#include <cinttypes>

using namespace std;
typedef uint8_t byte;

int main(){

	byte* output  = new byte[BLOCK_128_SIZE];
	byte* output2 = new byte[BLOCK_128_SIZE];
	byte* src	  = new byte[BLOCK_128_SIZE]{
		0x32,0x88,0x31,0xe0,
		0x43,0x5a,0x31,0x37,
		0xf6,0x30,0x98,0x07,
		0xa8,0x8d,0xa2,0x34};

	byte* my_key = new byte[KEY_128_SIZE]{
		0x2b,0x28,0xab,0x09,
		0x7e,0xae,0xf7,0xcf,
		0x15,0xd2,0x15,0x4f,
		0x16,0xa6,0x88,0x3c};

	AES myAES;
	myAES.setKey(my_key);

	cout << "\033[1;32m\nINPUT:\033[0m" << endl;
	myAES.printData(src);

	myAES.encrypt(src,output);
	myAES.decrypt(output,output2);

	cout << "\033[1;32m\nDECRYPTED:\033[0m" << endl;
	myAES.printData(output2);
	
	delete [] output2;
	delete [] output;
	delete [] src;
	delete [] my_key;

	return 0;	
}

