#ifndef E_FSCRYPT
#define E_FSCRYPT
#include "openssl/blowfish.h"

class Fscrypt{
	
public:
	
	Fscrypt();
	~Fscrypt();
	void cbc_mode(const unsigned char *, unsigned char *, long , const BF_KEY *, unsigned char *, int );
	const int BLOCKSIZE = 8;
	void *fs_encrypt(void *, int , char *, int *);
	void *fs_decrypt(void *, int , char *, int *);
	
	
};
#endif

