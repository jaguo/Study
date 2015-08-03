#include <stdio.h>
#include <openssl/aes.h>
#include <string.h>
#include <stdlib.h>
#include <error.h>


#define BUFF_SIZE 1024

static void aes_enc(FILE *in, FILE *out, const char *key);
static void aes_dec(FILE *in, FILE *out, const char *key);

int main(int argc, char *argv[])
{
	int flag = 1;	//flag = 1 enc 	flag = 0 dec
	char in_filename[255];
	char out_filename[255];
	char password[255];
	memset(in_filename, 0, sizeof(in_filename));
	memset(out_filename, 0, sizeof(out_filename));
	memset(password, 0, sizeof(password));

	if(argc != 7)
	{
		fprintf(stderr, "Please check input\n");
		printf("example: enc filename -o outname -p password\n");
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

	int i = 0;
	for(i = 3; i < argc; i++)
	{
		if(!strcmp(argv[i], "-o"))
		{
			strcpy(out_filename,argv[i + 1]);
			i++;
		}
		else if(!strcmp(argv[i], "-p"))
		{
			strcpy(password, argv[i + 1]);
			i++;
		}
		else
		{
			fprintf(stderr, "Don't find argument: %s\n", argv[i]);
			exit(1);
		}
	}

	FILE *in, *out;
	if((in = fopen(in_filename, "r")) == NULL)
	{
		perror("open");
		exit(1);
	}
	if((out = fopen(out_filename, "w")) == NULL)
	{
		perror("open");
		exit(1);
	}

	if(flag)
		aes_enc(in, out, password);
	else
		aes_dec(in, out, password);

	fclose(in);
	fclose(out);
	return 0;
}

static void aes_enc(FILE *in, FILE *out, const char *key)
{
	AES_KEY key_data;
	int i;
	int datalen;
	unsigned char buf[BUFF_SIZE];
	unsigned char encout[BUFF_SIZE];

	AES_set_encrypt_key(key, 128, &key_data);
	while(1)
	{
		memset(buf, 0, sizeof(buf));
		memset(encout, 0, sizeof(encout));
		datalen = fread(buf, 1, BUFF_SIZE, in);
		if(datalen == 0)
			break;
		if(datalen % 16 != 0)
			datalen += 16;
		for(i = 0; i < datalen/16; i++)
		{
			AES_encrypt(buf + i * 16, encout + i * 16, &key_data);
		}
		fwrite(encout, 1, (datalen/16) * 16, out);
	}
}

static void aes_dec(FILE *in, FILE *out, const char *key)
{
	AES_KEY key_data;
	int i;
	int datalen;
	unsigned char buf[BUFF_SIZE];
	unsigned char decout[BUFF_SIZE];

	AES_set_decrypt_key(key, 128, &key_data);
	while(1)
	{
		memset(buf, 0, sizeof(buf));
		memset(decout, 0, sizeof(decout));
		datalen = fread(buf, 1, BUFF_SIZE, in);
		if(datalen == 0)
			break;
		for(i = 0; i < datalen/16; i++)
		{
			AES_decrypt(buf + i * 16, decout + i * 16, &key_data);
		}
		int count = 0;
		while((decout[count] != '\0') && (count < BUFF_SIZE))
			count++;
		printf("count: %d\n", count);
		fwrite(decout, 1, count, out);
	}
}