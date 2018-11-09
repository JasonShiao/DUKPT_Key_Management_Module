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

#define SAFE_READ_ERROR -1


int main()
{
	int fd_cmd;
	int fd_data;
	char *input_IPEK = "6AC292FAA1315B4D858AB3A3D7D5933A";
	char *input_KSN = "FFFF9876543210E00000";
	char *input_PAN = "0000401234567890";

	char *write_buf = "343031323334353637383930394439383700000000000000";
	char read_buf[500];

	fd_cmd = open("/dev/DUKPT_cmd", O_RDWR);
	if(fd_cmd < 0)
	{
		printf("Cannot open device file...\n");
		return 0;
	}


	int cmd;
	size_t n_read;
	size_t n_write;
	while(1)
	{
		printf("==========================================================\n");
		printf("                DUKPT DEMO App                            \n");
		printf("      1 load initial key:                                 \n");
		printf("            default IPEK: 6AC292FAA1315B4D858AB3A3D7D5933A\n");
		printf("            default KSN: FFFF9876543210E00000             \n");
		printf("      2 write transaction data                            \n");
		printf("            default data: 3430313233343536                \n");
		printf("                          3738393039443938                \n");
		printf("                          3700000000000000                \n");
		printf("      3 write PAN and request pin entry                   \n");
		printf("            default formatted PAN: 000040123456789        \n");
		printf("            default PIN: 1234                             \n");
		printf("      4 read encrypted transaction data                   \n");
		printf("      5 for exit                                          \n");
		printf("==========================================================\n");
		printf("Command: ");
		scanf(" %d", &cmd);

		if(cmd == 1)
		{
			ioctl(fd_cmd, LOAD_INITIAL_KEY_IPEK, input_IPEK);
			ioctl(fd_cmd, LOAD_INITIAL_KEY_KSN, input_KSN);
		}
		else if(cmd == 2)
		{
			fd_data = open("/dev/DUKPT_data", O_RDWR);
			if(fd_cmd < 0)
			{
				printf("Cannot open device file...\n");
				break;
			}

			n_write = write(fd_data, write_buf, strlen(write_buf));
			printf("%zu bytes written\n", n_write);

			close(fd_data);

		}
		else if(cmd == 3)
		{
			ioctl(fd_cmd, REQUEST_PIN_ENTRY, input_PAN);
		}
		else if(cmd == 4)
		{
			fd_data = open("/dev/DUKPT_data", O_RDWR);
			if(fd_cmd < 0)
			{
				printf("Cannot open device file...\n");
				break;
			}

			while(1)
			{
				n_read = read(fd_data, read_buf, 500);
				if(n_read == SAFE_READ_ERROR)
				{
					printf("ERROR\n");
					break;
				}
				if(n_read == 0)
				{
					printf("End of data\n");
					break;
				}
				read_buf[n_read] = '\0';
				printf("Data Read: %s\n", read_buf);
			}

			close(fd_data);

		}
		else if(cmd == 5)
		{
			break;
		}
		else
		{
			printf("Invalid command\n");
		}


	}


	
	
	
	close(fd_cmd);

	return 0;
}


