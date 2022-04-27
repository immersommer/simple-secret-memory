#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/uio.h>

#define __NR_memfd_secret 447
#define PATTERN	0x55
off_t length = 2048;

static int memfd_secret(unsigned int flags){
	return syscall(__NR_memfd_secret, flags);
}


static void test_process_vm_read(int fd, int pipefd[2]){
    struct iovec liov, riov;
	char buf[64];
	char *ptr;
    pid_t ppid = getppid();
    long ret;

	if (read(pipefd[0], &ptr, sizeof(ptr)) < 0) {
		printf("pipe write: %s\n", strerror(errno));
		exit(-1);
	}
    printf("pipe write success(readv)\n");

	//Number of bytes to transfer 
    liov.iov_len = riov.iov_len = sizeof(buf); 
    //Starting address 
	liov.iov_base = buf; 
	riov.iov_base = ptr;
	if (process_vm_readv(getppid(), &liov, 1, &riov, 1, 0) < 0) {
        printf("tracer can't read data from memfd_secret region, test pass\n");
		exit(0);
	}
    printf("tracer can read data from memfd_secret region, test fail\n");
	exit(-1);
}

static void tracer(int fd, int pipefd[2]){
    pid_t ppid = getppid();
    char *ptr;
    long ret;
    int status;

    if(read(pipefd[0], &ptr, sizeof(ptr)) < 0) {
        perror("pipe write");
        exit(-1);
    }
    printf("pipe write success(tracer)\n");

    ret = ptrace(PTRACE_ATTACH, ppid, 0, 0);
    if(ret) {
        perror("ptrace_attach");
        exit(-1);
    }
    printf("ptrace_attach success\n");

    ret = waitpid(ppid, &status, WUNTRACED);
    if ((ret != ppid) || !(WIFSTOPPED(status))) {
        printf("weird waitppid result %ld stat %x\n", ret, status);
		exit(-1);
	}
    printf("parent proc. status change\n");

    //check read data
	if (ptrace(PTRACE_PEEKDATA, ppid, ptr, 0)) {
        printf("tracer can't get data from memfd_secret region, test pass\n");
		exit(0);
    }

    printf("tracer get data from memfd_secret region, test fail, data: %c\n", *ptr);
    exit(-1);
}

static void check_child_status(pid_t pid){
	int status;
	long n = waitpid(pid, &status, 0);
    printf("waitpid(): %ld\n", n);

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		printf("child (trecer) can't read data in parrent's secret region (trecee)\n");
		return;
	}

	printf("unexpected memory access\n");
}


static void ptrace_create(int fd, void (*tra)(int fd, int pipefd[2])) {
    int pipefd[2];
    pid_t pid;
    char *ptr;
   
    struct stat st;

    if (pipe(pipefd)) {
		printf("pipe failed: %s\n", strerror(errno));
		return;
	}

    pid = fork();
	if (pid < 0) {
		printf("fork failed: %s\n", strerror(errno));
		return;
    }
    //child process wait for parent process to write data
	if (pid == 0) {
		tra(fd, pipefd);
        return;
	}

    //parent process maping the secret region to it's adress space
    ptr = mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if(ptr == MAP_FAILED){
        printf("Mapping Failed: %s\n", strerror(errno));
    } else {
        printf("mmap() success! %p\n", ptr);
    }

    int ft = ftruncate(fd, length);
    if(ft != 0 ){
        printf("ftruncate() error: %s\n", strerror(errno));
    } else {
        fstat(fd, &st);
        printf("the file has %ld bytes\n", (long) st.st_size);
    }

    memset(ptr, PATTERN, length);
     // let child process start execution
	if (write(pipefd[1], &ptr, sizeof(ptr)) < 0) {
		printf("pipe write: %s\n", strerror(errno));
		return;
	}
    
    check_child_status(pid);
   

}

int main(int argc, char *argv[]) {
    int fd;
    int pipefd[2];
   
    fd = memfd_secret(0);
    if(fd < 0){
        printf("error!\n");
    } else{
        printf("success!fd: %d\n", fd);
    }
    
    ptrace_create(fd, test_process_vm_read);
    ptrace_create(fd, tracer);

    close(fd);
}
