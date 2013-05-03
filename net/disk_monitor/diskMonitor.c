#include <linux/module.h>                                               
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>  
#include <asm/uaccess.h>     
#include <linux/fs.h>
#include <linux/hugetlb.h>    
#include <linux/init.h> 
#include <linux/seq_file.h> 
#include <asm/atomic.h>    
#include <linux/pid.h>
#include <linux/sched.h>                               
#include <linux/unistd.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/netlink.h>
#include <net/sock.h>

MODULE_LICENSE("GPL");

#define NETLINK_AD 17
#define LOG_DIR "/sdcard/logRW.csv"
#define PROC_FILENAME "DiskMonitor"

void create_new_proc_entry();
static struct proc_dir_entry *proc_write_entry;

struct timeval timestamp;

int user = -1;

typedef struct message_storage
{
	unsigned int written;
	unsigned int read;
	unsigned long long address;
	unsigned long timeM;	
} message_storage;

typedef struct info_node{
	int PID;
	unsigned long long written;
	unsigned long long read;
	char device[BDEVNAME_SIZE];
	char process[10];
	message_storage messages[2800];	
	int head;
	int count;
	struct info_node* next;
}info_node;

typedef struct info_list
{
		struct info_node *head;
		struct info_node *tail;
		int flag;
}info_list;

extern info_list* message_list;

int write_proc(struct file *file,const char *buf,int count,void *data )
{


	char bufCopy[1001];
	if(copy_from_user(bufCopy,buf, count))
		return -EFAULT;
	sscanf(bufCopy, "%d",&user);

	return count;
}

void clear(){
	info_node* current_node;
	info_node* next_node = message_list->head;

	while(next_node!=NULL){
printk("HOla");
		current_node = next_node;
		next_node = next_node->next;
		
		kfree(current_node);
	}

	kfree(message_list);
	message_list = NULL;
		
}

void write_qwerty(){

	char output[1024];
	int len = 0;
	int i = 0;

	do_gettimeofday(&timestamp);

	char dump_filename[50]; //Set me to something
	sprintf(dump_filename,"/sdcard/logRW-%lu.csv",timestamp.tv_sec);

	struct file *file;
	info_node* current_node = message_list->head;
	info_node* prev_node = current_node;
	loff_t pos = 0;
	mm_segment_t old_fs;

	old_fs = get_fs();  //Save the current FS segment
	set_fs(get_ds());

	file = filp_open(dump_filename, O_WRONLY|O_CREAT, 0644);

	if(file){
		while(current_node!=NULL){
			len = sprintf(output,"%s, %d, %Lu, %Lu\n", current_node->process, current_node->PID, current_node->written, current_node->read);
			vfs_write(file, output, len,&pos);
			while(i<current_node->count){
				len = sprintf(output,"%Lu, %Lu, %u, %u\n", current_node->messages[i].timeM,current_node->messages[i].address, current_node->messages[i].written, current_node->messages[i].read);
				vfs_write(file, output, len,&pos);
				i++;
			}
			i = 0;
			current_node = current_node->next;
		}
		filp_close(file,NULL);
	}
	
	set_fs(old_fs); //Reset to saves FS
}

int read_proc(char *buf,char **start,off_t offset,int count,int *eof,void *data )
{
	write_qwerty();
	clear();
	return 0;
}

static void netlink_create(void){
	//Create the initial socket upon  module_init
	nl_sk = netlink_kernel_create(&init_net,NETLINK_AD,0, nl_data_ready,NULL, THIS_MODULE);
}

static int __init interceptor_start(void) 
{
	create_new_proc_entry();
	netlink_create();
	return 0;
}

void create_new_proc_entry(void)
{

	proc_write_entry = create_proc_entry(PROC_FILENAME,0644,NULL);
	if(!proc_write_entry) {
	    printk(KERN_INFO "Error creating proc entry");
	    return -ENOMEM;
	}
	proc_write_entry->read_proc = read_proc;
	proc_write_entry->write_proc = write_proc;
	printk(KERN_INFO "proc initialized\n");

}

static void __exit interceptor_end(void) 
{
	printk(KERN_INFO " Inside cleanup_module\n");
	remove_proc_entry(PROC_FILENAME,NULL);
}

static void nl_data_ready(struct sk_buff *skb){
	struct nlmsghdr *nlh = NULL;
	int pid;
	struct sk_buff *skb_out;
	int msg_size;
	int *msg = &message_list->flag;
	int res;
	
	//sk_buff is a linked list of buffers. In our case we only have 1 buffer.
	if(skb == NULL){
		printk("sk buffer is NULL \n");
		return ;
	}
	//Retrieve head pointer to our data which is contained in a message header.
	nlh = (struct nlmsghdr *)skb->data;
	printk(KERN_INFO "%s: received netlink message payload: %s\n", __FUNCTION__, (char *)NLMSG_DATA(nlh));
	
	
	msg_size=sizeof(int);
	pid = nlh->nlmsg_pid; /*pid of sending process */
	skb_out = nlmsg_new(msg_size,0);
	if(!skb_out){
		printk(KERN_ERR "Failed to allocate new skb\n");
		return;
	} 
	nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,msg_size,0);  
	NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
	memcpy(nlmsg_data(nlh),msg,msg_size);
	printk(KERN_INFO "What's the Opcode?:%s",msg->opcode);

	res=nlmsg_unicast(nl_sk,skb_out,pid);

	if(res!=0){
		printk(KERN_INFO "Error while sending back to user\n");
	}
}

module_init(interceptor_start);
module_exit(interceptor_end);

