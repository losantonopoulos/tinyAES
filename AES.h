#ifndef __AES_H__
#define __AES_H__

#include <cstdint>
#include <cinttypes>

// IN #BYTES
#define BLOCK_128_SIZE 	   16		
#define KEY_128_SIZE       16
#define KEY_128_ROUNDS     10
#define AES_128_ROWS			4
#define AES_128_COLUMNS		4

typedef uint8_t byte;

class AES {
	public:
			
		/*
			Arguments:
				key		- An 128bit key for encryption
				src		- Byte Array[BLOCK_128_SIZE] containing input data
				dst		- Byte Array[BLOCK_128_SIZE] containing output data

			This is the function which is used for encryption of data.
			In order for this function to work you must specify a key. 
			If you are not about to change the key all the time, you can use
			the setKey(key) function and then call the encrypt(src,dst) function.
		*/
		void encrypt(const byte *temp_key,const byte *src,byte *output);

		/*
			Arguments:
				key		- An 128bit key for encryption
				src		- Byte Array[BLOCK_128_SIZE] containing input data
				dst		- Byte Array[BLOCK_128_SIZE] containing output data

			This is the function which is used for decryption of data.
			In order for this function to work you must specify a key. 
			If you are not about to change the key all the time, you can use
			the setKey(key) function and then call the decrypt(src,dst) function.   
		*/
		void decrypt(const byte *temp_key,const byte *src,byte *output);

		/*
			Arguments:
				src		- Byte Array[BLOCK_128_SIZE] containing input data
				dst		- Byte Array[BLOCK_128_SIZE] containing output data

			This is the function which is used for encryption of data 
			by using the key set with the setkey(key) function.  
		*/
		void encrypt(const byte *src,byte *output);

		/*
			Arguments:
				src		- Byte Array[BLOCK_128_SIZE] containing input data
				dst		- Byte Array[BLOCK_128_SIZE] containing output data

			This is the function which is used for encryption of data 
			by using the key set with the setkey(key) function.  
		*/
		void decrypt(const byte *src,byte *output);
		
		/*
			Arguments:
				key		- An 128bit key for encryption
				
			This is the function which sets up the class in such a way that 
			you don't need to insert the key every time you want to encrypt
			or decrypt data. Simply after you set up the key correctly 
			you can use	encrypt(src,dst) or decrypt(src,dst) function.  
		*/
		bool setKey(const byte *key);
		
		/**/
		void printData(byte *key);
		
		/**/
		AES();

	private:
		// PRIVATE VARIABLES
		byte **expanded_128_key;
		byte *original_128_key;
		bool initialized = false;
		bool key_set	  = false;

		// LUTs
		static const byte rCon[10];
		static const byte sBox[256];
		static const byte invSbox[256];

		// MULTIPLICATION LUTs
		static const byte multiply_2[256];
		static const byte multiply_3[256];
		static const byte multiply_9[256];
		static const byte multiply_11[256];
		static const byte multiply_13[256];
		static const byte multiply_14[256];

		
		// GENERIC OPERATIONS
		void expandKey(const byte *original_key,byte **expanded_key);
		void convertToState(const byte *src,byte **dst);
		void addKey(const byte *key,byte **dst);
		void viewKey(byte *key);
		void view(byte **dst);
		
		// ROUND OPERATIONS
		void substitute(byte **dst);
		void mixColumns(byte **dst);
		void shiftRows(byte **dst);

		void invSubstitute(byte **dst);
		void invMixColumns(byte **dst);
		void invShiftRows(byte **dst);		
};

#endif
