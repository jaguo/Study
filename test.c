#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main()
{
    int fd;
    struct stat md;
    fd = open("./a.out", O_RDONLY);
    fstat(fd, &md);
    printf("%lo\n", (unsigned long)md.st_mode);
    return 0;
}
