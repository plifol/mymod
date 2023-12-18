
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <linux/ioctl.h>
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/jiffies.h>

MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "Nadin" );

#define MYDEV_NAME "my_module"

#define IOC_MAGIC '\x66'

#define IOCTL_VALSET     _IOW(IOC_MAGIC, 0, struct ioctl_arg)
#define IOCTL_VALGET     _IOR(IOC_MAGIC, 1, struct ioctl_arg)
#define IOCTL_VALGET_NUM _IOR(IOC_MAGIC, 2, int)
#define IOCTL_VALSET_NUM _IOW(IOC_MAGIC, 3, int)

#define IOCTL_VAL_MAXNR 3

static dev_t first;
static unsigned int count = 1;
static int my_major = 511;
static const int my_minor = 0;

static struct cdev *my_cdev;

static struct class *my_class;

static struct device *my_device;

static struct kobject *mymodule;

static long msize    = 0;
static long addr     = 0;
static int ioctl_num = 0;

static char readbuf[1024];
static size_t readbuflen;

struct ioctl_arg
{
    unsigned int val;
};

struct test_ioctl_data
{
    unsigned char val;
    rwlock_t lock;
};

static struct proc_dir_entry *mychardev_proc_file;


static ssize_t msize_show( struct kobject *kobj,
                           struct kobj_attribute *attr, char *buf )
{
    return sprintf( buf, "%ld\n", msize );
}

static ssize_t msize_store( struct kobject *kobj,
                            struct kobj_attribute *attr, char *buf,
                            size_t count )
{
    sscanf( buf, "%ldu", &msize );
    return count;
}

static struct kobj_attribute msize_attribute =
    __ATTR( msize, 0660, msize_show, (void *)msize_store );

static ssize_t addr_show( struct kobject *kobj,
                          struct kobj_attribute *attr, char *buf )
{
    return sprintf( buf, "%ld\n", addr );
}

static ssize_t addr_store( struct kobject *kobj,
                           struct kobj_attribute *attr, char *buf,
                           size_t count )
{
    static struct page** pages;
    int res, i;
    unsigned long nr_pages;
    void* virtaddr[ 100 ];

    sscanf( buf, "%ldu", &addr );
    nr_pages = ( msize + PAGE_SIZE-1 )/PAGE_SIZE;

    res = get_user_pages_unlocked( addr, nr_pages, pages, O_RDWR  );
    for( i = 0; i < nr_pages; i++ )
    {
        void* data = page_to_virt( pages[ i ] );
        memset( virtaddr[ i ], (long)data, sizeof( data ));
        printk( KERN_INFO " virtaddr[ %d ] = %p ", i, data );
    }
    printk( KERN_INFO "\n" );

    return count;
}

static struct kobj_attribute addr_attribute =
    __ATTR( addr, 0660, addr_show, (void *)addr_store );


static long mychardev_ioctl( struct file *file, unsigned int cmd,
                             unsigned long arg )
{
    struct test_ioctl_data *ioctl_data = file->private_data;
    int ret = 0;
    unsigned char val;
    struct ioctl_arg data;
    memset( &data, 0, sizeof(data));

    switch (cmd)
    {
        case IOCTL_VALSET:
            if ( copy_from_user( &data, (int __user *)arg, sizeof( data ) ))
            {
                ret = -EFAULT;
                goto done;
            }
            printk( KERN_INFO "IOCTL set val:%x .\n", data.val );

            write_lock( &ioctl_data->lock );
            ioctl_data->val = data.val;
            write_unlock( &ioctl_data->lock );

            break;

        case IOCTL_VALGET:
            read_lock( &ioctl_data->lock );
            val = ioctl_data->val;
            read_unlock( &ioctl_data->lock );

            data.val = val;
            if ( copy_to_user( (int __user *)arg, &data, sizeof(data) ))
            {
                ret = -EFAULT;
                goto done;
            }
            break;

        case IOCTL_VALGET_NUM:
            ret = __put_user( ioctl_num, (int __user *)arg );
            break;

        case IOCTL_VALSET_NUM:
            ioctl_num = arg;
            break;

        default:
            ret = -ENOTTY;
    }
    done:
        return ret;
}

unsigned int poll( struct file *file, struct poll_table_struct *wait )
{
    printk( KERN_INFO "poll\n" );
    // Ядро снова вызывает poll если возвращается ноль
    poll_wait( file, &waitqueue, wait );
    if ( readbuflen && !ret0 )
    {
        printk( KERN_INFO "return POLLIN\n" );
        return POLLIN;
    }
    else
    {
        printk( KERN_INFO "return 0\n" );
        return 0;
    }
}

static int kthread_func( void *data )
{
    while ( !kthread_should_stop() )
    {
        readbuflen = snprintf( readbuf, sizeof( readbuf ), "%llu", ( unsigned long long )jiffies );
        usleep_range( 1000000, 1000001 );
        printk( KERN_INFO "wake_up\n" );
        wake_up( &waitqueue );
    }
    return 0;
}

static ssize_t mychardev_read( struct file *file, char __user *buf,
                                size_t count, loff_t *f_pos)
{
    struct test_ioctl_data *ioctl_data = file->private_data;
    unsigned char val;
    ssize_t ret;

    read_lock( &ioctl_data->lock );
    val = ioctl_data->val;
    read_unlock( &ioctl_data->lock );

    if ( copy_to_user( buf, readbuf, readbuflen ))
    {
        ret = -EFAULT;
    }
    else
    {
        ret = readbuflen;
    }
    readbuflen = 0;
    return ret;
}

static int mychardev_open( struct inode *inode, struct file *file )
{
     struct test_ioctl_data *ioctl_data;

    printk( KERN_INFO "%s call.\n", __func__ );
    ioctl_data = kmalloc( sizeof(struct test_ioctl_data), GFP_KERNEL );

    if ( ioctl_data == NULL )
        return -ENOMEM;

    rwlock_init( &ioctl_data->lock );
    ioctl_data->val = 0xFF;
    file->private_data = ioctl_data;

    return 0;
    printk( KERN_INFO "Opening device %s: module_refcounter = %d \n", MYDEV_NAME, module_refcount( THIS_MODULE ) );
    return 0;
}

static int mychardev_release( struct inode *inode, struct file *file )
{
     if ( file->private_data )
     {
        kfree( file->private_data );
        file->private_data = NULL;
     }

    printk( KERN_INFO "Free kbuf\n" );
    printk( KERN_INFO "Closing device %s \n", MYDEV_NAME );
    return 0;
}

static ssize_t mychardev_write( struct file *file, const char __user *buf, size_t lbuf, loff_t *ppos )
{
    char *kbuf = file->private_data;
    int nbytes = lbuf - copy_from_user( kbuf + *ppos, buf, lbuf );
    printk( KERN_INFO "adr = %p\n",  (kbuf + *ppos ));
    *ppos += nbytes;
    printk( KERN_INFO "Writing device %s: nbytes = %d: ppos = %d \n", MYDEV_NAME, nbytes, (int)*ppos );
    return nbytes; // Возвращает количество записанных байт
}

static const struct file_operations mychardev_fops = {
    .owner          = THIS_MODULE,
    .read           = mychardev_read,
    .write          = mychardev_write,
    .open           = mychardev_open,
    .release        = mychardev_release,
    .unlocked_ioctl = mychardev_ioctl,
    .poll           = poll
};

static int __init mymodule_init(void)
{
    int error = 0;
    printk( "Init chardev!\n" );
    //Объявляем устройство
    first = MKDEV( my_major, my_minor );
    //Выделяем регион возможных устройств
    register_chrdev_region( first, count, MYDEV_NAME );
    //Выделяем память под структуру устройства
    my_cdev = cdev_alloc();
    //Инициализируем устройство
    cdev_init( my_cdev, &mychardev_fops );
    //Добавляем дерево устройств
    cdev_add( my_cdev, first, count );
    // Динамическое создание нода
    my_class = class_create( THIS_MODULE, "my_class" );
    // Создаем /dev/my_module
    my_device = device_create( my_class, NULL, first, "%s", "my_module" );
    //Создаем /sysfs/mymodule/
    mymodule = kobject_create_and_add( "mymodule", kernel_kobj );
    if (!mymodule)
        return -ENOMEM;
    // Создаем файл /sysfs/mymodule/msize
    error = sysfs_create_file( mymodule, &msize_attribute.attr );
    if ( error )
    {
        printk( KERN_INFO "failed to create file in /sys/kernel/mymodule\n" );
    }
    // // Создаем файл /sysfs/mymodule/addr
    error = sysfs_create_file( mymodule, &addr_attribute.attr );
    if ( error )
    {
        printk( KERN_INFO "failed to create file in /sys/kernel/mymodule\n" );
    }
    // Создаем файл procfs
    mychardev_proc_file = proc_create(PROC_ENTRY_FILENAME, 0644, NULL, &mychardev_fops);
    if (mychardev_proc_file == NULL)
    {
        printk( KERN_INFO "Error: Could not initialize /proc/%s\n", PROC_ENTRY_FILENAME );
        return -ENOMEM;
    }
    proc_set_size(mychardev_proc_file, 80);
    proc_set_user(mychardev_proc_file, GLOBAL_ROOT_UID, GLOBAL_ROOT_GID);

    // Инициализация poll
    debugfs_file = debugfs_create_file( "lkmc_poll", S_IRUSR | S_IWUSR, NULL, NULL, &mychardev_fops );
    init_waitqueue_head(&waitqueue);
    kthread = kthread_create( kthread_func, NULL, "mykthread" );
    wake_up_process( kthread );


    return error;
}

static void __exit mymodule_exit( void )
{
    if( my_cdev )
        cdev_del( my_cdev );
    unregister_chrdev_region( first, count );

    device_destroy( my_class, first );
    class_destroy( my_class );

    kobject_put( mymodule );

    kthread_stop(kthread);
    debugfs_remove(debugfs_file);

    printk( KERN_INFO "mymodule: Exit success\n" );
}

module_init( mymodule_init );
module_exit( mymodule_exit );

