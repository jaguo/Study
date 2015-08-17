#include <stdio.h>
#include <openssl/aes.h>
#include <string.h>
#include <stdlib.h>
#include <error.h>
#include <unistd.h>
#include <fcntl.h>


#define BUFF_SIZE 1024

static void aes_enc(int in, int out, const char *key);
static void aes_dec(int in, int out, const char *key);

int main(int argc, char *argv[])
{
    int flag = 1;	//flag = 1 enc 	flag = 0 dec
    char in_filename[255];
    char out_filename[255];
    char password[255];
    memset(in_filename, 0, sizeof(in_filename));
    memset(out_filename, 0, sizeof(out_filename));
    memset(password, 0, sizeof(password));

    if(argc != 3)
    {
	fprintf(stderr, "Please check input\n");
	printf("example: ./a.out enc/dec filename\n");
	exit(1);
    }
    if(strcmp(argv[1], "enc") == 0 || strcmp(argv[1], "dec") == 0)
    {
	if(strcmp(argv[1], "enc") == 0)
	    flag = 1;
	else
	    flag = 0;
    }
    else
    {
	fprintf(stderr, "Please check input argument\n");
	exit(1);
    }

    strcpy(in_filename, argv[2]);
    strcpy(out_filename, in_filename);

    if(flag)
	strcat(out_filename, "_enc");
    else
	strcat(out_filename, "_dec");
    printf("Please input password:");
    scanf("%s", password);

    int in, out;
    if((in = open(in_filename, O_RDONLY)) == -1)
    {
	perror("open");
	exit(1);
    }
    struct stat st;
    if(fstat(in, &st) == -1)
	perror("stat");
    //int mode = st.st_mode & 0777;
    if((out = open(out_filename, O_CREAT | O_RDWR | O_APPEND, st.st_mode)) == -1)
    {
	perror("open");
	exit(1);
    }

    if(flag)
	aes_enc(in, out, password);
    else
	aes_dec(in, out, password);

    close(in);
    close(out);
    return 0;
}

static void aes_enc(int in, int out, const char *key)
{
    AES_KEY key_data;
    int i;
    int datalen;
    unsigned char buf[BUFF_SIZE];
    unsigned char encout[BUFF_SIZE];
    int filelen = 0;
    //int dateaes = 0;

    if((filelen = lseek(in, 0, SEEK_END)) < 0)
	fprintf(stderr, "lseek error");
    lseek(in, 0, SEEK_SET);
    write(out, &filelen, sizeof(filelen));

    AES_set_encrypt_key(key, 128, &key_data);
    while(1)
    {
	memset(buf, 0, sizeof(buf));
	memset(encout, 0, sizeof(encout));
	datalen = read(in, buf, BUFF_SIZE);
	if(datalen == 0)
	    break;
	if(datalen % 16 != 0)
	    datalen += 16;
	for(i = 0; i < datalen/16; i++)
	{
	    AES_encrypt(buf + i * 16, encout + i * 16, &key_data);
	}
	write(out, encout, (datalen/16) * 16);
    }
}

static void aes_dec(int in, int out, const char *key)
{
    AES_KEY key_data;
    int i;
    int datalen;
    unsigned char buf[BUFF_SIZE];
    unsigned char decout[BUFF_SIZE];
    int filelen = 0;
    read(in, &filelen, sizeof(filelen));
    int count = 0;

    AES_set_decrypt_key(key, 128, &key_data);
    while(1)
    {
	memset(buf, 0, sizeof(buf));
	memset(decout, 0, sizeof(decout));
	datalen = read(in, buf, BUFF_SIZE);
	if(datalen == 0)
	    break;
	for(i = 0; i < datalen/16; i++)
	{
	    AES_decrypt(buf + i * 16, decout + i * 16, &key_data);
	}
	count += datalen;
	write(out, decout, count > filelen ? (filelen % BUFF_SIZE) : BUFF_SIZE);
    }
}
