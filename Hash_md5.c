#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include "md5.h"

#define READ_DATA_LEN 1024

int checkpath(char *path);
void show_md5(char *path);
void calculate_md5(char *path);

int main(int argc, char const *argv[])
{
	char path[255] = {0};

	//check path and default path "."
	if (argc == 1)
	{
		strcpy(path, ".");
	}
	else if (argc == 2)
	{
		strcpy(path, argv[1]);
	}
	else
	{
		fprintf(stderr,"%s Error\n",argv[0]);
		exit(1);
	}

	show_md5(path);

	return 0;
}

void show_md5(char *path)
{
	DIR *dp;
	struct dirent * dirp;
	
	char filepath[255];
	memset(filepath, 0, sizeof(filepath));
	strcpy(filepath, path);	

	int filestatus = checkpath(filepath);
	if( filestatus == 1)
	{
		calculate_md5(filepath);
	}
	else if(filestatus == 2)
	{
		if((dp = opendir(filepath)) == NULL)
		{
			fprintf(stderr, "can't open %s\n", filepath);
			exit(1);
		}

		while((dirp = readdir(dp)) != NULL)
		{
			if((!strcmp(dirp->d_name, ".")) || (!strcmp(dirp->d_name, "..")))
				continue;
			memset(filepath, 0, sizeof(filepath));
			strcpy(filepath, path);
			strcat(filepath, "/");
			strcat(filepath, dirp->d_name);
			//printf("filePath: %s\n", filepath);
			show_md5(filepath);
		}
		closedir(dp);
	}
}

void calculate_md5(char *path)
{
	FILE *fp;
	int i;
	int filelen;
	fp = fopen(path, "r");
	if(fp == NULL)
	{
		printf("Can't Open this file: %s\n", path);
		exit(1);
	}

	//size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);

	MD5_CTX md5;
	MD5Init(&md5);
	
	unsigned char md5value[16];
	unsigned char data[READ_DATA_LEN];

	while(1)
	{
		filelen = fread(data, 1, READ_DATA_LEN, fp);
		if(filelen == -1)
		{
			printf("File open errro\n");
			exit(1);
		}
		MD5Update(&md5, data, filelen);

		if (filelen < READ_DATA_LEN)
			break;
	}
	MD5Final(&md5,md5value);

	for(i=0;i<16;i++)
	{
		printf("%02x",md5value[i]);
	}
	printf("\t%s\n", path);

	fclose(fp);

}

int checkpath(char *path)
{
	struct stat buf;

	if (stat(path, &buf) == -1) 
	{
		perror("stat");
		return -1;
	}

	if (S_ISREG(buf.st_mode))
	{
		return 1;//it is a file
	}
	else if (S_ISDIR(buf.st_mode))
	{
		return 2;//it is a dir
	}
	else
	{
		return -1;//error
	}
}