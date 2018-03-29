#ifndef MD5_H_
#define MD5_H_

typedef struct
{
    unsigned int state[4]; /* state (ABCD) */
    unsigned int count[2]; /* number of bits, modulo 2^64 (lsb first) */
    unsigned char buffer[64]; /* input buffer */
} MD5_CTX, *PMD5_CTX;

void MD5Init(MD5_CTX *context);
void MD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputLen);
void MD5Final(unsigned char* digest, MD5_CTX *context);
int MD5Encode(unsigned char *szEncoded, const unsigned char *szData,
    int nSize, unsigned char *szKey, int nKeyLen);
int chap_auth(char *hash, char id, char *pwd, int pwd_size, char *chal, int chal_size);

int md5_packages_string(char *desc_str, char *src_str);
char *md5_file (char *path, int md5_len);

#endif /* MD5_H_ */

