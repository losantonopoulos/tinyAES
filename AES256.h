#ifndef __AES256_H__
#define __AES256_H__

#include <cstdint>
#include <cinttypes>

// IN #BYTES
#define BLOCK_256_SIZE		32
#define SMALL_KEY_256_SIZE	10		
#define KEY_256_SIZE 		32
#define KEY_256_ROUNDS 		14
#define AES_256_COLUMNS		8
#define AES_256_ROWS		4

class AES256 {
	public:
			
		/*
			Arguments:
				key		- An 256bit key for encryption
				src		- Byte Array[BLOCK_256_SIZE] containing input data
				dst		- Byte Array[BLOCK_256_SIZE] containing output data

			This is the function which is used for encryption of data.
			In order for this function to work you must specify a key. 
			If you are not about to change the key all the time, you can use
			the setKey(key) function and then call the encrypt(src,dst) function.
		*/
		unsigned int encrypt(const uint8_t *temp_key,const uint8_t *src,uint8_t *output, unsigned int n_bytes);

		/*
			Arguments:
				key		- An 256bit key for encryption
				src		- Byte Array[BLOCK_256_SIZE] containing input data
				dst		- Byte Array[BLOCK_256_SIZE] containing output data

			This is the function which is used for decryption of data.
			In order for this function to work you must specify a key. 
			If you are not about to change the key all the time, you can use
			the setKey(key) function and then call the decrypt(src,dst) function.   
		*/
		unsigned int decrypt(const uint8_t *temp_key,const uint8_t *src,uint8_t *output, unsigned int n_bytes);

		/*
			Arguments:
				src		- Byte Array[BLOCK_256_SIZE] containing input data
				dst		- Byte Array[BLOCK_256_SIZE] containing output data

			This is the function which is used for encryption of data 
			by using the key set with the setkey(key) function.  
		*/
		unsigned int encrypt(const uint8_t *src,uint8_t *output, unsigned int n_bytes);

		/*
			Arguments:
				src		- Byte Array[BLOCK_256_SIZE] containing input data
				dst		- Byte Array[BLOCK_256_SIZE] containing output data

			This is the function which is used for encryption of data 
			by using the key set with the setkey(key) function.  
		*/
		unsigned int decrypt(const uint8_t *src,uint8_t *output, unsigned int n_bytes);
		
		/*
			Arguments:
				key		- An 128bit key for encryption
				
			This is the function which sets up the class in such a way that 
			you don't need to insert the key every time you want to encrypt
			or decrypt data. Simply after you set up the key correctly 
			you can use	encrypt(src,dst) or decrypt(src,dst) function.  
		*/
		bool setKey(uint8_t *key);

		bool setUserKey(char *key);
		
		/**/
		void printData(uint8_t *key);
		
		/**/
		AES256();

	private:
		// PRIVATE VARIABLES
		uint8_t **expanded_256_key;
		uint8_t *original_256_key;
		bool initialized = false;
		bool key_set	  = false;

		// LUTs
		static const uint8_t rCon[10];
		static const uint8_t sBox[256];
		static const uint8_t invSbox[256];

		// MULTIPLICATION LUTs
		static const uint8_t multiply_2[256];
		static const uint8_t multiply_3[256];
		static const uint8_t multiply_9[256];
		static const uint8_t multiply_11[256];
		static const uint8_t multiply_13[256];
		static const uint8_t multiply_14[256];

		
		// GENERIC OPERATIONS
		void expandKey(const uint8_t *original_key,uint8_t **expanded_key);
		void convertToState(const uint8_t *src,uint8_t **dst);
		void addKey(const uint8_t *key,uint8_t **dst);
		void viewKey(uint8_t *key);
		void view(uint8_t **dst);
		
		// ROUND OPERATIONS
		void substitute(uint8_t **dst);
		void mixColumns(uint8_t **dst);
		void shiftRows(uint8_t **dst);

		void invSubstitute(uint8_t **dst);
		void invMixColumns(uint8_t **dst);
		void invShiftRows(uint8_t **dst);

		void encryptBlock(uint8_t **tmp, const uint8_t *src, uint8_t *dst);
		void encryptBlock(uint8_t *key,  uint8_t **expandedKey, uint8_t **tmp, const uint8_t *src,uint8_t *dst);
		void decryptBlock(uint8_t **tmp, const uint8_t *src, uint8_t *dst);
		void decryptBlock(uint8_t *key,  uint8_t **expandedKey, uint8_t **tmp, const uint8_t *src,uint8_t *dst);
};

#endif
