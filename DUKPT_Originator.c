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

#include <linux/string.h>
#include <linux/unistd.h>

#include "DES.h"
#include "DUKPT.h"




/*   Global Variable   */
dev_t dev = 0;
static struct class *dev_class;
static struct cdev DUKPT_cdev;
uint8_t *kernel_buffer;


typedef enum {READY, ACTIVE, EXIT}ReadStateType; 
ReadStateType read_state = READY;

static DUKPT_Reg *DUKPT_Instance;
static uint8_t KSN[10]; // Key Serial Number
static uint64_t BDK[2]; // Base Derivation Key
static uint64_t IPEK[2]; // Initial PIN encryption Key


/*   Function Prototype   */

static int __init DUKPT_Originator_init(void);
static void __exit DUKPT_Originator_exit(void);

static int device_open(struct inode *inode, struct file *file);
static int device_release(struct inode *inode, struct file *file);
static ssize_t device_read(struct file *filp, char __user *buf, size_t len, loff_t *off);
static ssize_t device_write(struct file *filp, const char __user *buf, size_t len, loff_t *off);

static struct file_operations fops =
{
	.owner		= THIS_MODULE,
	.read		= device_read,
	.write		= device_write,
	.open		= device_open,
	.release	= device_release,
};

static int device_open(struct inode *inode, struct file *file)
{

	/* Create physical memory */
	if((kernel_buffer = kmalloc(1024, GFP_KERNEL)) ==0)
	{
		printk(KERN_INFO "Cannot allocate memory in kernel\n");
		return -1;
	}
	printk(KERN_INFO "Device File Opened...!!!\n");
	return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
	kfree(kernel_buffer);
	printk(KERN_INFO "Device File Closed...!!!\n");
	return 0;
}

static ssize_t device_read(struct file *file, char __user *buf, size_t len, loff_t *off)
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

	//printk(KERN_INFO "strlen of kernel_buffer = %zu\n", strlen(kernel_buffer));
	//printk(KERN_INFO "off = %lld\n", *off);
	//printk(KERN_INFO "bytes_read = %zu\n", bytes_read);
	//printk(KERN_INFO "strlen of kernel_buffer - off = %lld\n", strlen(kernel_buffer) - *off);

	return bytes_read;

}

static ssize_t device_write(struct file *file, const char __user *buf, size_t len, loff_t *off)
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



static int __init DUKPT_Originator_init(void)
{
	int i;

	/* Assign PIN Block Directly instead of calling Request PIN Entry */
	

	/* Allocate Major number */
	if((alloc_chrdev_region(&dev, 0, 1, "DUKPT_Dev")) < 0)
	{
		printk(KERN_INFO "Cannot allocate major number\n");
		return -1;
	}
	printk(KERN_INFO "Major = %d Minor = %d \n", MAJOR(dev), MINOR(dev));

	/* Create cdev structure for the driver module */
	cdev_init(&DUKPT_cdev, &fops);

	/* Add character device to the system */
	if((cdev_add(&DUKPT_cdev, dev, 1)) < 0)
	{
		printk(KERN_INFO "Cannot add the device to the system\n");
		goto r_class;
	}

	/* Create struct class (high-level view of devices) */
	if((dev_class = class_create(THIS_MODULE, "DUKPT_class")) == NULL)
	{
		printk(KERN_INFO "Cannot create the struct class\n");
		goto r_class;
	}

	/* Create device */
	if((device_create(dev_class, NULL, dev, NULL, "DUKPT_device")) == NULL)
	{
		printk(KERN_INFO "Cannot create the Device 1\n");
		goto r_device;
	}

	/* Allocate DUKPT_Reg instance */
	DUKPT_Instance = kmalloc(sizeof(DUKPT_Reg), GFP_NOWAIT);



	/* Directly assign in program (for test) */
	KSN[0] = 0xFF; KSN[1] = 0xFF; KSN[2] = 0x98; KSN[3] = 0x76;
	KSN[4] = 0x54; KSN[5] = 0x32; KSN[6] = 0x10; KSN[7] = 0xE0;
	KSN[8] = 0x00; KSN[9] = 0x00;

	BDK[0] = 0x0123456789ABCDEF;
	BDK[1] = 0xFEDCBA9876543210;

	IPEK[0] = 0x6AC292FAA1315B4D;
	IPEK[1] = 0x858AB3A3D7D5933A;
	// or use CalcIPEK(BDK, KSN, IPEK) to calculate IPEK from BDK and KSN;

	printk(KERN_INFO "-------------------------------------------------\n");
	printk(KERN_INFO "KSN = %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", KSN[0], KSN[1], KSN[2], KSN[3], KSN[4], KSN[5], KSN[6], KSN[7], KSN[8], KSN[9]);
	printk(KERN_INFO "IPEK = %016llx %016llx\n", IPEK[0], IPEK[1]);
	printk(KERN_INFO "-------------------------------------------------\n");


	
	/* End of sample data assignment */

	/****************     Initialization Start     ******************/

	/* Load Initial Key */
	DUKPT_Instance->FKReg[20].LeftHalf = IPEK[0];
	DUKPT_Instance->FKReg[20].RightHalf = IPEK[1];

	GenerateLRC(&(DUKPT_Instance->FKReg[20]));
	DUKPT_Instance->CurrentKeyPtr = &DUKPT_Instance->FKReg[20];



	/* Set Key Serial Number Register */
	for (i = 0; i < 10; i++)
		DUKPT_Instance->KSNReg[i] = KSN[i];

	/* Clear Encryption Counter (right-most 21 bits) */
	DUKPT_Instance->KSNReg[9] = DUKPT_Instance->KSNReg[9] & (uint8_t)0x0;
	DUKPT_Instance->KSNReg[8] = DUKPT_Instance->KSNReg[8] & (uint8_t)0x0;
	DUKPT_Instance->KSNReg[7] = DUKPT_Instance->KSNReg[7] & (uint8_t)0xE0;


	/* Set #1 bit (leftmost bit) of ShiftReg to 1 */
	DUKPT_Instance->ShiftReg = (uint64_t)(0x1) << 20;


	NewKey_3(DUKPT_Instance);

	/***************      Initialization Finished      ****************/

	printk(KERN_INFO "======================================\n");
	printk(KERN_INFO "DUKPT module is inserted successfully.\n");
	printk(KERN_INFO "======================================\n");

	return 0;

r_device:
	class_destroy(dev_class);
r_class:
	unregister_chrdev_region(dev, 1);

	kfree(DUKPT_Instance);

	return -1;
}

static void __exit DUKPT_Originator_exit(void)
{
	device_destroy(dev_class, dev);
	class_destroy(dev_class);
	cdev_del(&DUKPT_cdev);
	unregister_chrdev_region(dev, 1);

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
