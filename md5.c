/******************************************************************************
 * ģ������: MD5-MD5����ģ��
 * �޸ļ�¼: 2009-03-13 V1.0.0
 *****************************************************************************/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "md5.h"

static unsigned char PADDING[64] =
{
    (char)0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* Constants for MD5Transform routine. */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

/* F, G, H and I are basic MD5 functions. */
#define F(x, y, z)          (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z)          (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z)          ((x) ^ (y) ^ (z))
#define I(x, y, z)          ((y) ^ ((x) | (~z)))
/* ROTATE_LEFT rotates x left n bits. */
#define ROTATE_LEFT(x, n)   (((x) << (n)) | ((x) >> (32-(n))))
/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation. */
#define FF(a, b, c, d, x, s, ac) { (a) += F ((b), (c), (d)) + (x) + (unsigned int)(ac);  (a) = ROTATE_LEFT ((a), (s)); (a) += (b);  }
#define GG(a, b, c, d, x, s, ac) { (a) += G ((b), (c), (d)) + (x) + (unsigned int)(ac);  (a) = ROTATE_LEFT ((a), (s)); (a) += (b);  }
#define HH(a, b, c, d, x, s, ac) { (a) += H ((b), (c), (d)) + (x) + (unsigned int)(ac);  (a) = ROTATE_LEFT ((a), (s)); (a) += (b);  }
#define II(a, b, c, d, x, s, ac) { (a) += I ((b), (c), (d)) + (x) + (unsigned int)(ac);  (a) = ROTATE_LEFT ((a), (s)); (a) += (b);  }

/* Encodes input (UINT4) into output (unsigned char). Assumes len is a multiple of 4. */
#define Encode(to, from, size) memcpy(to, from, size)

/* Decodes input (unsigned char) into output (UINT4). Assumes len is a multiple of 4. */
#define Decode(to, from, size) memcpy(to, from, size)

#define MD5_memcpy(to, from, size) memcpy(to, from, size)
#define MD5_memset(buf, val, size) memset(buf, val, size)

/* MD5 basic transformation. Transforms state based on block. */
static void MD5Transform(unsigned int state[4], unsigned char block[64])
{
    unsigned int a = state[0], b = state[1], c = state[2], d = state[3], x[16];

    Decode (x, block, 64);
    /* Round 1 */
    FF(a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
    FF(d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
    FF(c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
    FF(b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
    FF(a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
    FF(d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
    FF(c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
    FF(b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
    FF(a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
    FF(d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
    FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
    FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
    FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
    FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
    FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
    FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */
    /* Round 2 */
    GG(a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
    GG(d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
    GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
    GG(b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
    GG(a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
    GG(d, a, b, c, x[10], S22, 0x2441453); /* 22 */
    GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
    GG(b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
    GG(a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
    GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
    GG(c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
    GG(b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
    GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
    GG(d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
    GG(c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */
    /* Round 3 */
    HH(a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
    HH(d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
    HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
    HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
    HH(a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
    HH(d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
    HH(c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
    HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
    HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
    HH(d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
    HH(c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
    HH(b, c, d, a, x[ 6], S34, 0x4881d05); /* 44 */
    HH(a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
    HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
    HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
    HH(b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */
    /* Round 4 */
    II(a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
    II(d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
    II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
    II(b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
    II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
    II(d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
    II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
    II(b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
    II(a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
    II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
    II(c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
    II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
    II(a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
    II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
    II(c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
    II(b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    /* Zeroize sensitive information.
    */
    MD5_memset(x, 0, sizeof (x));
}

/* MD5 initialization. Begins an MD5 operation, writing a new context. */
void MD5Init(MD5_CTX *context)                                         /* context */
{
    context->count[0] = context->count[1] = 0;
    /* Load magic initialization constants.*/
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

/* MD5 block update operation. Continues an MD5 message-digest
  operation, processing another message block, and updating the  context. */
void MD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputLen)
{
    unsigned int i, index, partLen; /* Compute number of bytes mod 64 */
    MD5_CTX *context_tmp=context;
    index = (context_tmp->count[0] >> 3) & 0x3F;
    /* Update number of bits */
    if ((context_tmp->count[0] += (inputLen << 3)) < (inputLen << 3))
        context_tmp->count[1]++;

    context_tmp->count[1] += (inputLen >> 29);
    partLen = 64 - index;

    /* Transform as many times as possible.*/
    if (inputLen >= partLen) {
        MD5_memcpy(context_tmp->buffer+index, input, partLen);
        MD5Transform(context_tmp->state, context_tmp->buffer);

        for (i = partLen; i + 63 < inputLen; i += 64)
            MD5Transform(context_tmp->state, input+i);
        index = 0;
    }
    else
        i = 0;

    /* Buffer remaining input */
    MD5_memcpy(context_tmp->buffer+index, input+i,  inputLen-i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context. */
void MD5Final(unsigned char* digest, MD5_CTX *context)
{
    unsigned char bits[8];
    unsigned int index, padLen;  /* Save number of bits */

    Encode(bits, context->count, 8);  /* Pad out to 56 mod 64.*/
    index = (context->count[0] >> 3) & 0x3f;
    padLen = (index < 56) ? (56 - index) : (120 - index);
    MD5Update(context, PADDING, padLen);  /* Append length (before padding) */
    MD5Update(context, bits, 8);
    /* Store state in digest */
    Encode(digest, context->state, 16);
    /* Zeroize sensitive information.*/
    MD5_memset(context, 0, sizeof (*context));
}

int MDString(unsigned char *string, int nLen, unsigned char *digest)
{
	MD5_CTX context;

	MD5Init(&context);
	MD5Update(&context, string, nLen);
	MD5Final(digest, &context);

	return 0;
}

#define MAXMD5SOURCESTRINGLEN 128
#define MD5STRINGLEN 16
#define PADLEN 64

int MD5Encode(unsigned char *szEncoded, const unsigned char *szData,
    int nSize, unsigned char *szKey, int nKeyLen)
{
    // See rfc2104
    int i = 0;
    unsigned char firstPad[PADLEN + MAXMD5SOURCESTRINGLEN + 1];
    unsigned char K[PADLEN], midResult[PADLEN + 16];

    memset(firstPad, 0, sizeof(firstPad));
    memset(K, 0, PADLEN);
    memcpy(K, szKey, nKeyLen);

    for (i = 0; i < PADLEN; i++)
    {
        firstPad[i] = 0x36 ^ K[i];
        midResult[i] = 0x5c ^ K[i];
    }

    memcpy(firstPad + PADLEN, szData, nSize);
    firstPad[PADLEN + nSize] = '\0';
    MDString(firstPad, PADLEN + nSize, midResult + PADLEN);
    MDString(midResult, PADLEN + 16, szEncoded);

    return 16;
}

int chap_auth(char *hash, char id, char *pwd, int pwd_size, char *chal, int chal_size)
{
    MD5_CTX context;

  MD5Init (&context);
  MD5Update(&context, (unsigned char *)&id, 1);
  MD5Update(&context, (unsigned char *)pwd, pwd_size);
  MD5Update(&context, (unsigned char *)chal, chal_size);
  MD5Final((unsigned char *)hash, &context);

  return 16;
}

/*input:id--�û���¼��ID�ţ������ͷ���ĵ�5���ֽڣ���ʼPC����DVR�ļ��������ID�ű�֤Ϊ0
  pwd:��Ҫ���ܵ�����
  pwdlen:����ĳ���
output:hash:���ܺ������(Ĭ�ϳ���Ϊ16���ֽ�)
*/

static int MD5_enc(char id, char *pwd, char pwdlen, char *hash)
{
  unsigned char chal[] = {0x50,0xfd,0xfd,0x87,0x1c,0x1b,0xd1,0x44,0x9b,0x67,0xdb,0x0d,0x7e,0xed,0xd9,0x1e};
  return chap_auth(hash, id, pwd, pwdlen,(char *)chal, 16);
}


#define HASHLEN       16
#define HASHHEXLEN    32
typedef unsigned char HASH[HASHLEN];
typedef char          HASHHEX[HASHHEXLEN+1];
static  const char    hex_chars[] = "0123456789abcdef";

static char int2hex(char c)
{
	return hex_chars[(c & 0x0F)];
}

static void CvtHex(HASH Bin, HASHHEX Hex)
{
	unsigned short i;

	for (i = 0; i < HASHLEN; i++) {
		Hex[i*2] = int2hex((Bin[i] >> 4) & 0xf);
		Hex[i*2+1] = int2hex(Bin[i] & 0xf);
	}
	Hex[HASHHEXLEN] = '\0';
}

/****************************************************************
������ :	md5_packages_string
����	  :	[IN] src_str ��Ҫ����MD5ֵ���ַ���
		[IN] desc_str �洢����õ���MD5ֵ
		
����ֵ :  1 �ɹ�
˵��	  :	 ����һ���ַ�����MD5ֵ
******************************************************************/
int md5_packages_string(char *desc_str, char *src_str)
{
	MD5_CTX Md5Ctx;
	HASH HA1;

	MD5Init(&Md5Ctx);	     //��ʼ��
	MD5Update(&Md5Ctx, (unsigned char *)src_str, strlen(src_str)); //md5����
	MD5Final(HA1, &Md5Ctx); //�����ܺ�����ķŵ�HA1
	CvtHex(HA1, desc_str);  //��HA1ת��Ϊ�ַ����洢
    return 1;
}

/****************************************************************
������ :	md5_file
����	  :	[IN] path ��Ҫ����MD5ֵ���ļ�·��
		[IN] md5_len ��Ҫ�����MD5ֵ����,16/32
		
����ֵ :  MD5ֵ�ַ���
˵��	  :	 ����һ�������ļ���MD5ֵ
******************************************************************/
char *md5_file (char *path, int md5_len)
{  
	FILE *fp = fopen (path, "rb");	
	MD5_CTX mdContext;	
	int bytes;	
	unsigned char data[1024];  
	char *file_md5;  
	int i;	
	HASH HA1;

	if (fp == NULL) {  
		fprintf (stderr, "fopen %s failed\n", path);  
		return NULL;  
	}  

	MD5Init (&mdContext);  
	while ((bytes = fread (data, 1, 1024, fp)) != 0)  
	{  
		MD5Update (&mdContext, data, bytes);  
	}  
	MD5Final (HA1, &mdContext);  

	file_md5 = (char *)malloc((md5_len + 1) * sizeof(char));  
	if(file_md5 == NULL)  
	{  
		fprintf(stderr, "malloc failed.\n");  
		return NULL;  
	}  
	memset(file_md5, 0, (md5_len + 1));  

	if(md5_len == 16)  
	{  
		for(i=4; i<12; i++)  
		{  
			sprintf(&file_md5[(i-4)*2], "%02x", HA1[i]);  
		}  
	}  
	else if(md5_len == 32)	
	{  
		for(i=0; i<16; i++)  
		{  
			sprintf(&file_md5[i*2], "%02x", HA1[i]);  
		}  
	}  
	else  
	{  
		fclose(fp);  
		free(file_md5);  
		return NULL;  
	}  

	fclose (fp);  
	return file_md5;  
}
