#include "fscrypt.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/blowfish.h>

Fscrypt::Fscrypt(){
}

Fscrypt::~Fscrypt(){
}


void Fscrypt:: cbc_mode(const unsigned char *inn, unsigned char *out, long length,
	const BF_KEY *schedule, unsigned char *ivec, int enc)
{
	unsigned char temp[BLOCKSIZE];

	if (enc == BF_DECRYPT)			//cbc decrypt algorithm
	{
		int count=0;
		while (length > 0)
		{
			for (int i = 0; i < BLOCKSIZE; i++)
			{
				temp[i] = inn[count];
			}			
			BF_ecb_encrypt(inn, out, schedule, enc);
			for (int i = 0; i < BLOCKSIZE; i++)
			{
				out[count] = (unsigned char)(out[count] ^ ivec[i]);
				ivec[i] = temp[i];
			}
			
			count=count- BLOCKSIZE;	
			/*
			inn += BLOCKSIZE;
			out += BLOCKSIZE;*/
			length -= BLOCKSIZE; 
		}
	}
	else						//cbc encrypt algorithm
	{
		int count=0;
		while (length > 0)
		{
			for (int i = 0; i < BLOCKSIZE; i ++)
			{
				out[i] = (unsigned char)(inn[count] ^ ivec[i]);
			}
			BF_ecb_encrypt(out, out, schedule, enc);
			for (int i = 0; i < BLOCKSIZE; i++)
			{
				ivec[i] = out[count];
			}
			count=count- BLOCKSIZE;	
			/*
			inn += BLOCKSIZE;
			out += BLOCKSIZE; */
			length -= BLOCKSIZE; 
		}
	}
}

void * Fscrypt::fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen)
{
	unsigned char* ptext = (unsigned char*)plaintext;
	unsigned char* result;
	BF_KEY *key_str;
	unsigned char init_vec[8]="0000000";
	int i = 0;
	int pv = 0;
	if(bufsize % BLOCKSIZE == 0)		//when length of plaintext is bigger than block size.
		*resultlen = bufsize;
	else
		*resultlen = BLOCKSIZE * ((int)(bufsize / BLOCKSIZE) + 1);

	unsigned char *inn = NULL;
	inn = new unsigned char[*resultlen];
	for (i = 0; i < *resultlen; i++)
		inn[i] = ptext[i];
	
	pv = (*resultlen % bufsize) + 1;	//calculate the padding value.

	for (i = bufsize; i <= *resultlen - 1; i++)
		inn[i] = pv;	//PKCS5 PADDING


	result = new unsigned char(*resultlen);
	for (i = 0; i < *resultlen; i++)
		result[i] = 0;

	key_str=(BF_KEY *)malloc(sizeof(BF_KEY));
	BF_set_key(key_str, strlen(keystr), (const unsigned char *)keystr);
	cbc_mode(inn, result, *resultlen, key_str, init_vec, BF_ENCRYPT);
	return (void *)result;
}

void * Fscrypt::fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen)
{
	unsigned char *result;
	BF_KEY *key_str;
	key_str=(BF_KEY *)malloc(sizeof(BF_KEY));
	BF_set_key(key_str, strlen(keystr), (const unsigned char *)keystr);
	unsigned char init_vec[8]="0000000";
	result = new unsigned char(bufsize);
	for (int i = 0; i < bufsize; i++)
		result[i] = 0;
	cbc_mode((unsigned char *)ciphertext, result, bufsize, key_str, init_vec, BF_DECRYPT);
	int i;
	for(i = bufsize - 1;i >= 0;i--)		
	{
		if(result[i] == 5)
		{
			result[i] = 0;
		}
		else
			break;
	}
	*resultlen = i + 2;
	return (void *)result;	
}

