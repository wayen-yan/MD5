#include <stdio.h>
#include <stdlib.h>
#include "md5.h"


int main(int argc, char *argv[])  
{  
	char *md5;  
	/*ÎÄ¼þÂ·¾¶*/
	char *file_path = "JetPack-L4T-3.1-linux-x64.run";

	md5 = md5_file(file_path, 16);  
	printf("16: %s\n", md5);  
	free(md5);  

	md5 = md5_file(file_path, 32);  
	printf("32: %s\n", md5);  
	free(md5);  

	char *src = "fldjafljdlajfldsjfljdsalkfjlkdsajflkdjfjdksla";
	char dst_md5[64];
	md5_packages_string(dst_md5,src);
	printf("result == %s\n", dst_md5);
	return 0;  
}  
