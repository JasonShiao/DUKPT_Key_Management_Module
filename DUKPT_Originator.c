/********************************************************
 *                                                      *
 *    Implementation of DUKPT PIN Block Encryption      *
 *    based on ANSI_X9.24-1-2009                        *
 *                                                      *
 *    Originater (device) Side                          *
 *                                                      *
 *                            By Jason Shiao, Oct 2018  *
 *                                                      *
*********************************************************/

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>

#include <linux/string.h>
#include <linux/unistd.h>

#include "DES.h"
#include "DUKPT.h"

#define MAX_TRANSACTION_DATA_LEN 400

#define IOCTL_MAGIC 70

#define LOAD_INITIAL_KEY_IPEK _IOW(IOCTL_MAGIC, 0, char*)
#define LOAD_INITIAL_KEY_KSN _IOW(IOCTL_MAGIC, 1, char*)
#define REQUEST_PIN_ENTRY _IOW(IOCTL_MAGIC, 2, char*)
#define CANCEL_PIN_ENTRY _IO(IOCTL_MAGIC, 3)
#define POWER_ON_RESET _IO(IOCTL_MAGIC, 4)

#define SET_CLEAR_DATA _IOW(IOCTL_MAGIC, 5, char*)
#define GET_ENCRYPT_DATA _IOR(IOCTL_MAGIC, 6)


/*   Global Variable   */
dev_t DUKPT_cmd_dev = 0;
dev_t DUKPT_data_dev = 0;
static struct class *dev_class;
static struct cdev DUKPT_cmd_cdev;
static struct cdev DUKPT_data_cdev;


uint8_t *kernel_buffer;
static uint8_t* DUKPT_cmd_buffer;
static uint8_t* DUKPT_data_buffer;


typedef enum {READY, ACTIVE, EXIT}ReadStateType; 
ReadStateType read_state = READY;

static DUKPT_Reg *DUKPT_Instance;

/*   Function Prototype   */

static int __init DUKPT_Originator_init(void);
static void __exit DUKPT_Originator_exit(void);

static int DUKPT_cmd_open(struct inode *inode, struct file *file);
static int DUKPT_cmd_release(struct inode *inode, struct file *file);
static ssize_t DUKPT_cmd_read(struct file *filp, char __user *buf, size_t len, loff_t *off);
static ssize_t DUKPT_cmd_write(struct file *filp, const char __user *buf, size_t len, loff_t *off);
static long DUKPT_cmd_ioctl(struct file* file, unsigned int cmd, unsigned long arg);

static int DUKPT_data_open(struct inode *inode, struct file *file);
static int DUKPT_data_release(struct inode *inode, struct file *file);
static ssize_t DUKPT_data_read(struct file *filp, char __user *buf, size_t len, loff_t *off);
static ssize_t DUKPT_data_write(struct file *filp, const char __user *buf, size_t len, loff_t *off);
static long DUKPT_data_ioctl(struct file* file, unsigned int cmd, unsigned long arg);

static struct file_operations DUKPT_cmd_fops =
{
	.owner			= THIS_MODULE,
	.read			= DUKPT_cmd_read,
	.write			= DUKPT_cmd_write,
	.open			= DUKPT_cmd_open,
	.unlocked_ioctl	= DUKPT_cmd_ioctl, 
	.release		= DUKPT_cmd_release,
};

static int DUKPT_cmd_open(struct inode *inode, struct file *file)
{

	/* Create physical memory */
	if((kernel_buffer = kmalloc(1024, GFP_KERNEL)) == 0)
	{
		printk(KERN_INFO "Cannot allocate memory in kernel\n");
		return -1;
	}
	printk(KERN_INFO "Device File Opened...!!!\n");
	return 0;
}

static int DUKPT_cmd_release(struct inode *inode, struct file *file)
{
	kfree(kernel_buffer);
	printk(KERN_INFO "Device File Closed...!!!\n");
	return 0;
}

static ssize_t DUKPT_cmd_read(struct file *file, char __user *buf, size_t len, loff_t *off)
{
	
	ssize_t bytes_read;

	switch(read_state)
	{
		case READY:

			Request_PIN_Entry_1(DUKPT_Instance);

			/* Return encrypted PIN Block (stored in CryptoReg) to user space */
			snprintf(kernel_buffer, 1024, "%016llX\n", DUKPT_Instance->CryptoReg[0]);
			printk(KERN_INFO "Encrypted PIN Block: %016llX \n", DUKPT_Instance->CryptoReg[0]);
		
			/* New Key */
			NewKey(DUKPT_Instance);

			bytes_read = simple_read_from_buffer(buf, len, off, kernel_buffer, strlen(kernel_buffer));
			
			break;
		case ACTIVE:
			
			bytes_read = simple_read_from_buffer(buf, len, off, kernel_buffer, strlen(kernel_buffer));
			
			break;
		case EXIT:
		default:
			read_state = READY;
			bytes_read = simple_read_from_buffer(buf, len, off, kernel_buffer, strlen(kernel_buffer));
			return bytes_read;
			break;
	}


	if(strlen(kernel_buffer) - *off == 0)
		read_state = EXIT;
	else if(strlen(kernel_buffer) - *off > 0)
	{
		read_state = ACTIVE;
	}

	return bytes_read;

}

static ssize_t DUKPT_cmd_write(struct file *file, const char __user *buf, size_t len, loff_t *off)
{

	size_t i;
	uint64_t PIN_Block = 0x0;

	/* check PIN Block len */
	if(len > (16+1))
	{
		printk(KERN_INFO "Invalid PIN length!\n");
		return -1;
	}


	/* Accept PIN from user space */
	copy_from_user(kernel_buffer, buf, len);


	/* check PIN Block digit value */
	printk(KERN_INFO "user input len: %zu \n", len);
	for(i = 0; i < (len-1); i++)
	{
		if((kernel_buffer[i] < '0' || kernel_buffer[i] > '9') && (kernel_buffer[i] < 'A' || kernel_buffer[i] > 'Z'))
		{
			printk(KERN_INFO "Invalid PIN digit value!\n");
			return -1;
		}
	}

	/* Convert PIN Block from char array to uint64_t */
	for(i = 0; i < (len-1); i++)
	{
		PIN_Block <<= 4;
		if(kernel_buffer[i] >= '0' && kernel_buffer[i] <= '9')
		{
			PIN_Block |= (uint64_t)(kernel_buffer[i] - '0');
		}
		else if(kernel_buffer[i] >= 'A' && kernel_buffer[i] <= 'Z')
		{
			PIN_Block |= (uint64_t)(kernel_buffer[i] - 'A' + 10);
		}
		else
		{
			printk(KERN_INFO "Invalid PIN digit\n");
			return -1;
		}
	}

	/* Store PIN Block into Crypto Register 1 */
	DUKPT_Instance->CryptoReg[0] = PIN_Block;


	printk(KERN_INFO "PIN Block input: Done\n");
	
	return len;
}

static long DUKPT_cmd_ioctl(struct file* file, unsigned int cmd, unsigned long arg)
{
	size_t i;
	uint64_t temp_half_IPEK;
	uint64_t temp_PIN_field;
	int ret;

	switch(cmd)
	{
		case LOAD_INITIAL_KEY_IPEK:

			copy_from_user(DUKPT_cmd_buffer, (char*)arg, 32);
			DUKPT_cmd_buffer[32] = '\0';
			/* Left half */
			temp_half_IPEK = 0;
			for(i = 0; i < 16; i++)
			{
				temp_half_IPEK <<= 4;
				if(DUKPT_cmd_buffer[i] >= '0' && DUKPT_cmd_buffer[i] <= '9')
					temp_half_IPEK |= (DUKPT_cmd_buffer[i] - '0');
				else if(DUKPT_cmd_buffer[i] >= 'a' && DUKPT_cmd_buffer[i] <= 'z')
					temp_half_IPEK |= (DUKPT_cmd_buffer[i] - 'a' + 10);
				else if(DUKPT_cmd_buffer[i] >= 'A' && DUKPT_cmd_buffer[i] <= 'Z')
					temp_half_IPEK |= (DUKPT_cmd_buffer[i] - 'A' + 10);
				else
					return -EINVAL;
			}
			DUKPT_Instance->FKReg[20].LeftHalf = temp_half_IPEK;

			/* Right half */
			temp_half_IPEK = 0;
			for(i = 16; i < 32; i++)
			{
				temp_half_IPEK <<= 4;
				if(DUKPT_cmd_buffer[i] >= '0' && DUKPT_cmd_buffer[i] <= '9')
					temp_half_IPEK |= (DUKPT_cmd_buffer[i] - '0');
				else if(DUKPT_cmd_buffer[i] >= 'a' && DUKPT_cmd_buffer[i] <= 'z')
					temp_half_IPEK |= (DUKPT_cmd_buffer[i] - 'a' + 10);
				else if(DUKPT_cmd_buffer[i] >= 'A' && DUKPT_cmd_buffer[i] <= 'Z')
					temp_half_IPEK |= (DUKPT_cmd_buffer[i] - 'A' + 10);
				else
					return -EINVAL;
			}
			DUKPT_Instance->FKReg[20].RightHalf = temp_half_IPEK;

			printk(KERN_INFO "IPEK = %016llX %016llX loaded ...done\n",
								DUKPT_Instance->FKReg[20].LeftHalf, 
								DUKPT_Instance->FKReg[20].RightHalf);

			GenerateLRC(&(DUKPT_Instance->FKReg[20]));
			DUKPT_Instance->CurrentKeyPtr = &DUKPT_Instance->FKReg[20];

			
			return 0;
			break;
		case LOAD_INITIAL_KEY_KSN:
		
			copy_from_user(DUKPT_cmd_buffer, (char*)arg, 20);
			for(i=0; i<10; i++)
			{
				if(DUKPT_cmd_buffer[2*i] >= '0' && DUKPT_cmd_buffer[2*i] <= '9')
					DUKPT_Instance->KSNReg[i] = (DUKPT_cmd_buffer[2*i] - '0') << 4;
				else if(DUKPT_cmd_buffer[2*i] >= 'a' && DUKPT_cmd_buffer[2*i] <= 'z')
					DUKPT_Instance->KSNReg[i] = (DUKPT_cmd_buffer[2*i] - 'a' + 10) << 4;
				else if(DUKPT_cmd_buffer[2*i] >= 'A' && DUKPT_cmd_buffer[2*i] <= 'Z')
					DUKPT_Instance->KSNReg[i] = (DUKPT_cmd_buffer[2*i] - 'A' + 10) << 4;
				else
					return -EINVAL;
				
				if(DUKPT_cmd_buffer[2*i+1] >= '0' && DUKPT_cmd_buffer[2*i+1] <= '9')
					DUKPT_Instance->KSNReg[i] |= (DUKPT_cmd_buffer[2*i+1] - '0');
				else if(DUKPT_cmd_buffer[2*i+1] >= 'a' && DUKPT_cmd_buffer[2*i+1] <= 'z')
					DUKPT_Instance->KSNReg[i] |= (DUKPT_cmd_buffer[2*i+1] - 'a' + 10);
				else if(DUKPT_cmd_buffer[2*i+1] >= 'A' && DUKPT_cmd_buffer[2*i+1] <= 'Z')
					DUKPT_Instance->KSNReg[i] |= (DUKPT_cmd_buffer[2*i+1] - 'A' + 10);
				else
					return -EINVAL;

			}

			printk(KERN_INFO "KSN = %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X loaded ...done\n",
									DUKPT_Instance->KSNReg[0], DUKPT_Instance->KSNReg[1], 
									DUKPT_Instance->KSNReg[2], DUKPT_Instance->KSNReg[3],
									DUKPT_Instance->KSNReg[4], DUKPT_Instance->KSNReg[5], 
									DUKPT_Instance->KSNReg[6], DUKPT_Instance->KSNReg[7], 
									DUKPT_Instance->KSNReg[8], DUKPT_Instance->KSNReg[9]);

			/* Clear Encryption Counter (right-most 21 bits) */
			DUKPT_Instance->KSNReg[9] = DUKPT_Instance->KSNReg[9] & (uint8_t)0x0;
			DUKPT_Instance->KSNReg[8] = DUKPT_Instance->KSNReg[8] & (uint8_t)0x0;
			DUKPT_Instance->KSNReg[7] = DUKPT_Instance->KSNReg[7] & (uint8_t)0xE0;


			/* Set #1 bit (leftmost bit) of ShiftReg to 1 */
			DUKPT_Instance->ShiftReg = (uint64_t)(0x1) << 20;

			do
			{
				NewKey_3(DUKPT_Instance);
				ret = NewKey_1(DUKPT_Instance);
			}while(ret == 0);

			NewKey_4(DUKPT_Instance);

			ret = NewKey_2(DUKPT_Instance);

			if(ret == 1)
			{
				/* TODO:cease operation */
				DUKPT_Instance->current_state = DUKPT_OVERFLOW;
				return 0;
			}

			//Exit();

			DUKPT_Instance->current_state = DUKPT_ACTIVE;

			return 0;
			break;
		case REQUEST_PIN_ENTRY:

			if(DUKPT_Instance->current_state == DUKPT_OVERFLOW)
			{
				printk(KERN_INFO "DUKPT overflows. Please initialize it with a new key/\n");
				return 0;
			}

			
			copy_from_user(DUKPT_cmd_buffer, (char*)arg, 16);
			/* input: right-most 12 digits(nibbles) of PAN */
			DUKPT_Instance->AccountReg = 0;
			for(i = 0 ; i < 16; i++)
			{
				DUKPT_Instance->AccountReg <<= 4;
				if(DUKPT_cmd_buffer[i] >= '0' && DUKPT_cmd_buffer[i] <= '9')
					DUKPT_Instance->AccountReg |= (DUKPT_cmd_buffer[i] - '0');
				else if(DUKPT_cmd_buffer[i] >= 'a' && DUKPT_cmd_buffer[i] <= 'z')
					DUKPT_Instance->AccountReg |= (DUKPT_cmd_buffer[i] - 'a' + 10);
				else if(DUKPT_cmd_buffer[i] >= 'A' && DUKPT_cmd_buffer[i] <= 'Z')
					DUKPT_Instance->AccountReg |= (DUKPT_cmd_buffer[i] - 'A' + 10);
				else
					return -EINVAL;
			}
			printk(KERN_INFO "Account Reg: %016llX\n", DUKPT_Instance->AccountReg);
			

			/* TODO: Enable a keypad/keyboard for PIN entry */
			temp_PIN_field = 0x041234FFFFFFFFFF; /* Directly assign here for demo/test */


			DUKPT_Instance->CryptoReg[0] = temp_PIN_field ^ DUKPT_Instance->AccountReg;

			printk(KERN_INFO "PIN Block: %016llX\n", DUKPT_Instance->CryptoReg[0]);


			do
			{
				ret = Request_PIN_Entry_1(DUKPT_Instance);
			}while(ret == 0);

			if(ret == 2)
			{
				/* TODO: Cease Operation */
				DUKPT_Instance->current_state = DUKPT_OVERFLOW;
				return 0;
			}

			Request_PIN_Entry_2(DUKPT_Instance);

			ret = NewKey(DUKPT_Instance);

			if(ret == 1)
			{
				ret = NewKey_1(DUKPT_Instance);
				while(ret == 0)
				{
					NewKey_3(DUKPT_Instance);
					ret = NewKey_1(DUKPT_Instance);
				}
				NewKey_4(DUKPT_Instance);
			}
				
			ret = NewKey_2(DUKPT_Instance);

			if(ret == 1)
			{
				/* TODO:Cease operation */
				DUKPT_Instance->current_state = DUKPT_OVERFLOW;
			}

			//Exit();
				
			return 0;
			break;
		case CANCEL_PIN_ENTRY:
			
			/* TODO: Deactivate keypad/keyboard */
			
			//Exit();	
			
			return 0;
			break;
		case POWER_ON_RESET:
		
			return 0;
			break;
		default:
			printk(KERN_DEBUG "%s Unknown command %d\n", __FUNCTION__, cmd);
			return -EINVAL;
			break;
	}

}



static struct file_operations DUKPT_data_fops =
{
	.owner			= THIS_MODULE,
	.read			= DUKPT_data_read,
	.write			= DUKPT_data_write,
	.open			= DUKPT_data_open,
	.unlocked_ioctl	= DUKPT_data_ioctl, 
	.release		= DUKPT_data_release,
};



static int DUKPT_data_open(struct inode *inode, struct file *file){ return 0;}
static int DUKPT_data_release(struct inode *inode, struct file *file){ return 0;}
static ssize_t DUKPT_data_read(struct file *filp, char __user *buf, size_t len, loff_t *off){ return 0;}
static ssize_t DUKPT_data_write(struct file *filp, const char __user *buf, size_t len, loff_t *off){ return 0;}
static long DUKPT_data_ioctl(struct file* file, unsigned int cmd, unsigned long arg){ return 0;}



static int __init DUKPT_Originator_init(void)
{

	/* Assign PIN Block Directly instead of calling Request PIN Entry */
	

	/* DUKPT_cmd: Allocate Major number */
	if((alloc_chrdev_region(&DUKPT_cmd_dev, 0, 1, "DUKPT_cmd_dev")) < 0)
	{
		printk(KERN_INFO "Cannot allocate major number\n");
		return -1;
	}
	printk(KERN_INFO "DUKPT cmd device: Major = %d Minor = %d \n", MAJOR(DUKPT_cmd_dev), MINOR(DUKPT_cmd_dev));

	
	/* DUKPT_data: Allocate Major number */
	if((alloc_chrdev_region(&DUKPT_data_dev, 0, 1, "DUKPT_data_dev")) < 0)
	{
		printk(KERN_INFO "Cannot allocate major number\n");
		return -1;
	}
	printk(KERN_INFO "DUKPT data device: Major = %d Minor = %d \n", MAJOR(DUKPT_data_dev), MINOR(DUKPT_data_dev));
	

	/* Create a cdev structure of cmd device for the driver module */
	cdev_init(&DUKPT_cmd_cdev, &DUKPT_cmd_fops);
	cdev_init(&DUKPT_data_cdev, &DUKPT_data_fops);


	/* Add character device to the system */
	if((cdev_add(&DUKPT_cmd_cdev, DUKPT_cmd_dev, 1)) < 0)
	{
		printk(KERN_INFO "Cannot add the cmd device to the system\n");
		goto r_class;
	}
	if((cdev_add(&DUKPT_data_cdev, DUKPT_data_dev, 1)) < 0)
	{
		printk(KERN_INFO "Cannot add the data device to the system\n");
		goto r_class;
	}


	/* Create struct class (high-level view of devices) */
	if((dev_class = class_create(THIS_MODULE, "DUKPT_class")) == NULL)
	{
		printk(KERN_INFO "Cannot create the struct class\n");
		goto r_class;
	}


	/* Create device */
	if((device_create(dev_class, NULL, DUKPT_cmd_dev, NULL, "DUKPT_cmd")) == NULL)
	{
		printk(KERN_INFO "Cannot create the cmd Device 1\n");
		goto r_device;
	}
	if((device_create(dev_class, NULL, DUKPT_data_dev, NULL, "DUKPT_data")) == NULL)
	{
		printk(KERN_INFO "Cannot create the data Device 1\n");
		goto r_device;
	}


	/* Allocate DUKPT_Reg instance */
	DUKPT_Instance = kmalloc(sizeof(DUKPT_Reg), GFP_KERNEL);
	DUKPT_cmd_buffer = kmalloc(50, GFP_KERNEL);
	DUKPT_data_buffer = kmalloc(MAX_TRANSACTION_DATA_LEN, GFP_KERNEL);

	/* Directly assign in program (for test) */
	//KSN[0] = 0xFF; KSN[1] = 0xFF; KSN[2] = 0x98; KSN[3] = 0x76;
	//KSN[4] = 0x54; KSN[5] = 0x32; KSN[6] = 0x10; KSN[7] = 0xE0;
	//KSN[8] = 0x00; KSN[9] = 0x00;

	//BDK[0] = 0x0123456789ABCDEF;
	//BDK[1] = 0xFEDCBA9876543210;

	//IPEK[0] = 0x6AC292FAA1315B4D;
	//IPEK[1] = 0x858AB3A3D7D5933A;
	// can use CalcIPEK(BDK, KSN, IPEK) to calculate IPEK from BDK and KSN;

	//printk(KERN_INFO "-------------------------------------------------\n");
	//printk(KERN_INFO "KSN = %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", KSN[0], KSN[1], KSN[2], KSN[3], KSN[4], KSN[5], KSN[6], KSN[7], KSN[8], KSN[9]);
	//printk(KERN_INFO "IPEK = %016llx %016llx\n", IPEK[0], IPEK[1]);
	//printk(KERN_INFO "-------------------------------------------------\n");


	
	/* End of sample data assignment */

	/****************     Initialization Start     ******************/

	/* Load Initial Key */
	//DUKPT_Instance->FKReg[20].LeftHalf = IPEK[0];
	//DUKPT_Instance->FKReg[20].RightHalf = IPEK[1];

	//GenerateLRC(&(DUKPT_Instance->FKReg[20]));
	//DUKPT_Instance->CurrentKeyPtr = &DUKPT_Instance->FKReg[20];



	/* Set Key Serial Number Register */
	//for (i = 0; i < 10; i++)
	//	DUKPT_Instance->KSNReg[i] = KSN[i];

	/* Clear Encryption Counter (right-most 21 bits) */
	//DUKPT_Instance->KSNReg[9] = DUKPT_Instance->KSNReg[9] & (uint8_t)0x0;
	//DUKPT_Instance->KSNReg[8] = DUKPT_Instance->KSNReg[8] & (uint8_t)0x0;
	//DUKPT_Instance->KSNReg[7] = DUKPT_Instance->KSNReg[7] & (uint8_t)0xE0;


	/* Set #1 bit (leftmost bit) of ShiftReg to 1 */
	//DUKPT_Instance->ShiftReg = (uint64_t)(0x1) << 20;


	//NewKey_3(DUKPT_Instance);

	/***************      Initialization Finished      ****************/

	printk(KERN_INFO "======================================\n");
	printk(KERN_INFO "DUKPT module is inserted successfully.\n");
	printk(KERN_INFO "======================================\n");

	return 0;

r_device:
	class_destroy(dev_class);
r_class:
	unregister_chrdev_region(DUKPT_cmd_dev, 1);
	unregister_chrdev_region(DUKPT_data_dev, 1);

	kfree(DUKPT_Instance);
	kfree(DUKPT_cmd_buffer);
	kfree(DUKPT_data_buffer);

	return -1;
}

static void __exit DUKPT_Originator_exit(void)
{
	device_destroy(dev_class, DUKPT_cmd_dev);
	device_destroy(dev_class, DUKPT_data_dev);
	
	class_destroy(dev_class);
	
	cdev_del(&DUKPT_cmd_cdev);
	cdev_del(&DUKPT_data_cdev);

	unregister_chrdev_region(DUKPT_cmd_dev, 1);
	unregister_chrdev_region(DUKPT_data_dev, 1);

	kfree(DUKPT_Instance);

	printk(KERN_INFO "======================================\n");
	printk(KERN_INFO "Device Driver Remove...Done!!\n");
	printk(KERN_INFO "======================================\n");
}


module_init(DUKPT_Originator_init);
module_exit(DUKPT_Originator_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jason Shiao");
MODULE_DESCRIPTION("DUKPT Key Management");
MODULE_VERSION("0.0.1");
