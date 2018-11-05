#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int8_t read_buf[1024];

int main()
{
	int fd;
	fd = open("/dev/DUKPT_device", O_RDWR);
	if(fd < 0)
	{
		printf("Cannot open device file...\n");
		return 0;
	}

	printf("Data Reading...");
	read(fd, read_buf, 1024);
	printf("Done!\n\n");
	printf("Data = %s\n\n", read_buf);

	close(fd);

	return 0;
}
