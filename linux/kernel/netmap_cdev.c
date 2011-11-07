/*
 * Stub to build netmap.c on linux as a character driver
 *
 * Courtesy of Luca Deri and ..
 */
/*
 * XXX luigi

the equivalent of selrecord()/selwakeup() is
poll_wait()/wake_up(), see
http://www.xml.com/ldd/chapter/book/ch05.html
and linux-2.6.38.8/sound/core/timer.c

 */
#include <linux/device.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/idr.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/kobject.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <asm/io.h>

static int netmap_major;
static char* netmap_name = "netmap";
static struct class *netmap_class;

/* NETMAP CTRL DEVICE OPERATIONS */

static int
netmap_open(struct inode *inode, struct file *filep)
{
  printk("[netmap] netmap_open\n");
  filep->private_data = NULL; /* Put your data here */

  try_module_get(THIS_MODULE);
  return 0;
}


static int
netmap_release(struct inode *inode, struct file *filep)
{
  printk("[netmap] netmap_release\n");
  module_put(THIS_MODULE);
  return 0;
}


static ssize_t
netmap_read(struct file *filep, char __user *buf, size_t count, loff_t *ppos)
{
  printk("[netmap] netmap_read\n");
  return -EINVAL;
}


static ssize_t
netmap_write(struct file *filep, const char __user *buf, size_t count, loff_t *ppos)
{
  printk("[netmap] netmap_write\n");
  return -EINVAL;
}


static unsigned int
netmap_poll(struct file *filep, poll_table *wait)
{
  printk("[netmap] netmap_poll\n");
  // poll_wait(filep, &idev->wait, wait);

  return POLLIN | POLLRDNORM;
}


static int
netmap_ioctl(struct inode *inode, struct file *filep, unsigned int ioctl_num, unsigned long ioctl_param)
{
  printk("[netmap] netmap_ioctl\n");

  return 0;
}


static const struct file_operations netmap_fops = {
  .owner	= THIS_MODULE,
  //  .open		= netmap_open,
  //  .release	= netmap_release,
  //  .read		= netmap_read,
  //  .write        = netmap_write,
  .poll         = netmap_poll,  
  .ioctl        = netmap_ioctl,  
};


/* NETMAP MODULE REGISTRATION */

static int __init
netmap_init_module(void)
{
  int ret= 0;

  if ((netmap_major = register_chrdev(0, netmap_name, &netmap_fops)) < 0){
    printk("[netmap] Error registering driver\n");
    return(-1);
  }

  netmap_class = class_create(THIS_MODULE, netmap_name);
  if (IS_ERR(netmap_class)){
    ret = -ENOMEM;
  } else  
    device_create(netmap_class,
		  NULL,
		  MKDEV(netmap_major, 0),
		  NULL,
		  netmap_name);
  
  printk("[netmap] Registration succeeded %s [major=%u]\n", netmap_name, netmap_major);
  return ret;
}


static void __exit
netmap_exit_module(void)
{
  device_destroy(netmap_class, MKDEV(netmap_major, 0));
  class_destroy(netmap_class);
  unregister_chrdev(netmap_major, netmap_name);
}

module_init(netmap_init_module);
module_exit(netmap_exit_module);

MODULE_DESCRIPTION("netmap driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Luigi Rizzo");
