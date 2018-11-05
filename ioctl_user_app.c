#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define IOCTL_MAGIC 70

#define LOAD_INITIAL_KEY_IPEK _IOW(IOCTL_MAGIC, 0, char*)
#define LOAD_INITIAL_KEY_KSN _IOW(IOCTL_MAGIC, 1, char*)
#define REQUEST_PIN_ENTRY _IOW(IOCTL_MAGIC, 2, char*)
#define CANCEL_PIN_ENTRY _IO(IOCTL_MAGIC, 3)
#define POWER_ON_RESET _IO(IOCTL_MAGIC, 4)


int main()
{
	int fd;
	char *input_IPEK = "6AC292FAA1315B4D858AB3A3D7D5933A";
	char *input_KSN = "FFFF9876543210E00000";
	char *input_PAN = "0000401234567890";

	fd = open("/dev/DUKPT_device", O_RDWR);
	if(fd < 0)
	{
		printf("Cannot open device file...\n");
		return 0;
	}


	int cmd;
	while(1)
	{
		printf("==================================\n");
		printf("|        DUKPT DEMO App          |\n");
		printf("|      1 for load initial key    |\n");
		printf("|      2 for request pin entry   |\n");
		printf("|      3 for exit                |\n");
		printf("==================================\n");
		printf("Command: ");
		scanf(" %d", &cmd);
		//cmd = getchar();

		if(cmd == 1)
		{
			ioctl(fd, LOAD_INITIAL_KEY_IPEK, input_IPEK);
			ioctl(fd, LOAD_INITIAL_KEY_KSN, input_KSN);
		}
		else if(cmd == 2)
		{
			ioctl(fd, REQUEST_PIN_ENTRY, input_PAN);
		}
		else if(cmd == 3)
		{
			break;
		}
		else
		{
			printf("Invalid command\n");
		}


	}


	
	
	
	close(fd);

	return 0;
}


