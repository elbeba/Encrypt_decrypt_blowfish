#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "fscrypt.h"
#include "openssl/blowfish.h"

int main()
{
  char s[] = "hello world";
  char *outbuf, *recvbuf;
  char pass[] = "top secret";
  int len = 0;
  int recvlen = 0;

  outbuf = (char *) fs_encrypt((void *) s, strlen(s)+1, pass, &len);
 
  int i = 0;
  printf("ciphertext = ");
  for (i = 0; i < len; i++)
      printf("%02x", outbuf[i]);
  printf("\n");

  recvbuf  = (char *) fs_decrypt((void *) outbuf, len, pass, &recvlen);
  printf("plaintext = %s\n", recvbuf);
}

