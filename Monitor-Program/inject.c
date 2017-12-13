#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>//__lxstat
#include <unistd.h>//__lxstat
#include <dirent.h>//readdir
#include <string.h>
#include <stdarg.h>
//#include <fcntl.h>//error: conflicting types for ‘open’


//0 VAR
static uid_t (*old_getuid)(void) = NULL;
static int (*old_rand)(void) = NULL;
static pid_t (*old_fork)(void) = NULL;
static FILE* (*old_tmpfile)(void) = NULL;
static gid_t (*old_getegid)(void) = NULL;
static uid_t (*old_geteuid)(void) = NULL;
static gid_t (*old_getgid)(void) = NULL;


//1 VAR
static char* (*old_getenv)(const char *name) = NULL;//
static struct dirent* (*old_readdir)(DIR *dirp) = NULL;
static int (*old_closedir)(DIR *dirp) = NULL;
static DIR* (*old_opendir)(const char *name) = NULL;
static DIR* (*old_fdopendir)(int fd) = NULL;
static unsigned int (*old_sleep)(unsigned int seconds) = NULL;
static int (*old_close)(int fd) = NULL;
static int (*old_pipe)(int pipefd[2]) = NULL;
static int (*old_fclose)(FILE *fp) = NULL;//
static int (*old_remove)(const char *pathname) = NULL;
static char* (*old_mkdtemp)(char *template) = NULL;
static int (*old_putenv)(char *string) = NULL;
static int (*old_rand_r)(unsigned int *seedp) = NULL;
static int (*old_system)(const char *command) = NULL;
static int (*old_chdir)(const char *path) = NULL;
static int (*old_unlink)(const char *pathname) = NULL;
static int (*old_fflush)(FILE *stream) = NULL;
static long (*old_telldir)(DIR *dirp) = NULL;
static char* (*old_tmpnam)(char *s) = NULL;
static int (*old_mkstemp)(char *template) = NULL;
static int (*old_dup)(int oldfd) = NULL;
static int (*old_fchdir)(int fd) = NULL;
static int (*old_fsync)(int fd) = NULL;
static int (*old_rmdir)(const char *pathname) = NULL;
static int (*old_setegid)(gid_t egid) = NULL;
static int (*old_seteuid)(uid_t euid) = NULL;
static int (*old_setgid)(gid_t gid) = NULL;
static int (*old_setuid)(uid_t uid) = NULL;
static mode_t (*old_umask)(mode_t mask) = NULL;
//static void* (*old_malloc)(size_t size) = NULL;//Segmentation Fault


//2 VAR
static FILE* (*old_fopen)(const char *path, const char *mode) = NULL;//
static void* (*old_realloc)(void *ptr, size_t size) = NULL;
static int (*old_dup2)(int oldfd, int newfd) = NULL;
static int (*old_open)(const char *pathname, int flags) = NULL;
static int (*old_creat)(const char *pathname, mode_t mode) = NULL;
static char* (*old_tempnam)(const char *dir, const char *pfx) = NULL;
static int (*old_stat)(const char *path, struct stat *buf) = NULL;//not shown
static int (*old_fstat)(int fd, struct stat *buf) = NULL;
static int (*old_lstat)(const char *path, struct stat *buf) = NULL;
static int (*old_chmod)(const char *path, mode_t mode) = NULL;
static int (*old_mkdir)(const char *pathname, mode_t mode) = NULL;
static int (*old_rename)(const char *oldpath, const char *newpath) = NULL;
static int (*old_ftruncate)(int fd, off_t length) = NULL;
static char* (*old_getcwd)(char *buf, size_t size) = NULL;
static int (*old_link)(const char *oldpath, const char *newpath) = NULL;
static int (*old_symlink)(const char *oldpath, const char *newpath) = NULL;
static int (*old_fchmod)(int fd, mode_t mode) = NULL;
static int (*old_mkfifo)(const char *pathname, mode_t mode) = NULL;
static int (*old_fputs_unlocked)(const char *s, FILE *stream) = NULL;
static int (*old_ungetc)(int c, FILE *stream) = NULL;
static char* (*old_setlocale)(int category, const char *locale) = NULL;


//3 VAR
static int (*old___lxstat)(int ver, const char *path, struct stat *stat_buf) = NULL;
static int (*old_readdir_r)(DIR *dirp, struct dirent *entry, struct dirent **result) = NULL;
static int (*old_setenv)(const char *name, const char *value, int overwrite) = NULL;
static int (*old_chown)(const char *path, uid_t owner, gid_t group) = NULL;
static int (*old_fchown)(int fd, uid_t owner, gid_t group) = NULL;
static ssize_t (*old_read)(int fd, void *buf, size_t count) = NULL;
static ssize_t (*old_readlink)(const char *path, char *buf, size_t bufsiz) = NULL;
static ssize_t (*old_write)(int fd, const void *buf, size_t count) = NULL;


//4 VAR
static ssize_t (*old_pread)(int fd, void *buf, size_t count, off_t offset) = NULL;//not valid
static ssize_t (*old_pwrite)(int fd, const void *buf, size_t count, off_t offset) = NULL;//not valid
static int (*old_setvbuf)(FILE *stream, char *buf, int mode, size_t size) = NULL;


//embedded
char* mygetenv(const char* name);
FILE* myfopen(const char *path, const char *mode);
int myfclose(FILE *fp);
int myfflush(FILE *stream);


//return void
static void (*old_exit)(int status) __attribute__((noreturn)) = NULL;
static void (*old__exit)(int status) __attribute__((noreturn)) = NULL;
static void (*old_srand)(unsigned int seed) = NULL;
static void (*old_perror)(const char *s) = NULL;
static void (*old_rewinddir)(DIR *dirp) = NULL;
static void (*old_seekdir)(DIR *dirp, long loc) = NULL;
static void (*old_setbuf)(FILE *stream, char *buf) = NULL;


//exec
static int (*old_execv)(const char *path, char *const argv[]) = NULL;
static int (*old_execvp)(const char *file, char *const argv[]) = NULL;
static int (*old_execve)(const char *filename, char *const argv[], char *const envp[]) = NULL;
static int (*old_execvpe)(const char *file, char *const argv[], char *const envp[]) = NULL;


/*embedded functions*/
char* mygetenv(const char* name){
    if(old_getenv == NULL){
            void *handle = dlopen("libc.so.6",RTLD_LAZY);
            if(handle != NULL){
                    old_getenv = dlsym(handle,"getenv");
            }
    }
    char* returns;//NULL now
    if(old_getenv != NULL){
            returns = old_getenv(name);
    }
        return returns;
}

FILE* myfopen(const char *path, const char *mode){
        if(old_fopen == NULL){
                void *handle = dlopen("libc.so.6",RTLD_LAZY);
                if(handle != NULL){
                        old_fopen = dlsym(handle,"fopen");
                }
        }
        FILE* returns;
        if(old_fopen != NULL){
                returns = old_fopen(path,mode);
        }
        return returns;
}

int myfclose(FILE *fp){
        if(old_fclose == NULL){
                void *handle = dlopen("libc.so.6",RTLD_LAZY);
                if(handle != NULL){
                        old_fclose = dlsym(handle,"fclose");
                }
        }
        int returns;
        if(old_fclose != NULL){
                returns = old_fclose(fp);
        }
        return returns;
}

int myfflush(FILE *stream){
    if(old_fflush == NULL){
        void *handle = dlopen("libc.so.6",RTLD_LAZY);
        if(handle != NULL){
            old_fflush = dlsym(handle,"fflush");
        }
    }
    int returns;
    if(old_fflush != NULL){
        returns = old_fflush(stream);
    }
    return returns;
}


/*0 para*/
#define GENERIC_DECLARE_0_VAR(name,returnFmt,returnType)\
returnType name(void){								\
	if(old_##name == NULL){							\
		void *handle = dlopen("libc.so.6",RTLD_LAZY);\
		if(handle!=NULL){							\
			old_##name = dlsym(handle,#name);		\
		}											\
	}												\
	returnType returns;								\
	if(old_##name != NULL){							\
		returns = old_##name();						\
		char *tmp = mygetenv("MONITOR_OUT");		\
		if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){\
			fprintf(stderr,"[monitor] "#name"() = "returnFmt"\n",returns);\
		}else{										\
			FILE* fFile = myfopen(tmp,"a");			\
            if(fFile!=NULL){						\
	            fprintf(fFile,"[moniter] "#name"() = "returnFmt"\n",returns);\
            }										\
            myfclose(fFile);						\
		}											\
	}												\
	return returns;									\
}
GENERIC_DECLARE_0_VAR(getuid,"%d",uid_t)
GENERIC_DECLARE_0_VAR(rand,"%d",int)
GENERIC_DECLARE_0_VAR(fork,"%d",pid_t)
GENERIC_DECLARE_0_VAR(tmpfile,"%p",FILE*)//not valid
GENERIC_DECLARE_0_VAR(getegid,"%d",gid_t)//not valid
GENERIC_DECLARE_0_VAR(geteuid,"%d",uid_t)//not valid
GENERIC_DECLARE_0_VAR(getgid,"%d",gid_t)//not valid


/*1 para*/
#define GENERIC_DECLARE_1_VAR(name,returnFmt,returnType,para1Fmt,para1,...)\
returnType name(__VA_ARGS__){						\
	if(old_##name == NULL){							\
		void *handle = dlopen("libc.so.6",RTLD_LAZY);\
		if(handle!=NULL){							\
			old_##name = dlsym(handle,#name);		\
		}											\
	}												\
	returnType returns;								\
	if(old_##name != NULL){							\
		returns = old_##name(para1);				\
		char *tmp = mygetenv("MONITOR_OUT");		\
		if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){\
			fprintf(stderr,"[monitor] "#name"("para1Fmt") = "returnFmt"\n",para1,returns);\
		}else{										\
			FILE* fFile = myfopen(tmp,"a");			\
            if(fFile!=NULL){						\
	            fprintf(fFile,"[moniter] "#name"("para1Fmt") = "returnFmt"\n",para1,returns);\
            }										\
            myfclose(fFile);  						\
		}											\
	}												\
	return returns;									\
}
GENERIC_DECLARE_1_VAR(getenv,"\'%s\'",char*,"\'%s\'",name,const char* name)
GENERIC_DECLARE_1_VAR(readdir,"%p",struct dirent*,"%p",dirp,DIR *dirp)
GENERIC_DECLARE_1_VAR(closedir,"%d",int,"%p",dirp,DIR *dirp)
GENERIC_DECLARE_1_VAR(opendir,"%p",DIR*,"\'%s\'",name,const char *name)
GENERIC_DECLARE_1_VAR(fdopendir,"%p",DIR*,"%d",fd,int fd)
GENERIC_DECLARE_1_VAR(sleep,"%u",unsigned int,"%u",seconds,unsigned int seconds)
GENERIC_DECLARE_1_VAR(close,"%d",int,"%d",fd,int fd)
GENERIC_DECLARE_1_VAR(pipe,"%d",int,"%p",pipefd,int pipefd[2])//print array %p
GENERIC_DECLARE_1_VAR(fclose,"%d",int,"%p",fp,FILE *fp)
//GENERIC_DECLARE_1_VAR(malloc,"%p",void*,"%zu",size,size_t size)//fail
GENERIC_DECLARE_1_VAR(remove,"%d",int,"\'%s\'",pathname,const char *pathname)
GENERIC_DECLARE_1_VAR(mkdtemp,"%p",char*,"\'%s\'",template,char *template)//not sure
GENERIC_DECLARE_1_VAR(putenv,"%d",int,"\'%s\'",string,char *string)
GENERIC_DECLARE_1_VAR(rand_r,"%d",int,"%p",seedp,unsigned int *seedp)
GENERIC_DECLARE_1_VAR(system,"%d",int,"%s",command,const char *command)
GENERIC_DECLARE_1_VAR(chdir,"%d",int,"%s",path,const char *path)//not sure
GENERIC_DECLARE_1_VAR(unlink,"%d",int,"%s",pathname,const char *pathname)
GENERIC_DECLARE_1_VAR(fflush,"%d",int,"%p",stream,FILE *stream)
GENERIC_DECLARE_1_VAR(telldir,"%ld",long,"%p",dirp,DIR *dirp)//not valid
GENERIC_DECLARE_1_VAR(tmpnam,"%s",char*,"%p",s,char *s)//not valid
GENERIC_DECLARE_1_VAR(mkstemp,"%d",int,"%s",template,char *template)//not valid
GENERIC_DECLARE_1_VAR(dup,"%d",int,"%d",oldfd,int oldfd)//not valid
GENERIC_DECLARE_1_VAR(fchdir,"%d",int,"%d",fd,int fd)//not valid
GENERIC_DECLARE_1_VAR(fsync,"%d",int,"%d",fd,int fd)//not valid
GENERIC_DECLARE_1_VAR(rmdir,"%d",int,"%s",pathname,const char *pathname)//not valid
GENERIC_DECLARE_1_VAR(setegid,"%d",int,"%d",egid,gid_t egid)//not valid
GENERIC_DECLARE_1_VAR(seteuid,"%d",int,"%d",euid,uid_t euid)//not valid
GENERIC_DECLARE_1_VAR(setgid,"%d",int,"%d",gid,gid_t gid)//not valid
GENERIC_DECLARE_1_VAR(setuid,"%d",int,"%d",uid,uid_t uid)//not valid
GENERIC_DECLARE_1_VAR(umask,"%u",mode_t,"%u",mask,mode_t mask)//not valid


/*2 para*/
#define GENERIC_DECLARE_2_VAR(name,returnFmt,returnType,para1Fmt,para1,para2Fmt,para2,...)\
returnType name(__VA_ARGS__){						\
	if(old_##name == NULL){							\
		void *handle = dlopen("libc.so.6",RTLD_LAZY);\
		if(handle!=NULL){							\
			old_##name = dlsym(handle,#name);		\
		}											\
	}												\
	returnType returns;								\
	if(old_##name != NULL){							\
		returns = old_##name(para1,para2);				\
		char *tmp = mygetenv("MONITOR_OUT");		\
		if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){\
			fprintf(stderr,"[monitor] "#name"("para1Fmt","para2Fmt") = "returnFmt"\n",para1,para2,returns);\
		}else{										\
			FILE* fFile = myfopen(tmp,"a");			\
            if(fFile!=NULL){						\
	            fprintf(fFile,"[moniter] "#name"("para1Fmt","para2Fmt") = "returnFmt"\n",para1,para2,returns);\
            }										\
            myfclose(fFile);						\
		}											\
	}												\
	return returns;									\
}
GENERIC_DECLARE_2_VAR(realloc,"%p",void*,"%p",ptr,"%zu",size,void *ptr, size_t size)
GENERIC_DECLARE_2_VAR(fopen,"%p",FILE*,"\'%s\'",path,"\'%s\'",mode,const char *path, const char *mode)
GENERIC_DECLARE_2_VAR(dup2,"%d",int,"%d",oldfd,"%d",newfd,int oldfd, int newfd)
GENERIC_DECLARE_2_VAR(open,"%d",int,"%s",pathname,"%d",flags,const char *pathname, int flags)
GENERIC_DECLARE_2_VAR(creat,"%d",int,"%s",pathname,"%u",mode,const char *pathname, mode_t mode)
GENERIC_DECLARE_2_VAR(tempnam,"%p",char*,"%p",dir,"%p",pfx,const char *dir, const char *pfx)
GENERIC_DECLARE_2_VAR(stat,"%d",int,"\'%s\'",path,"%p",buf,const char *path, struct stat *buf)//is it normal can not hijack?
GENERIC_DECLARE_2_VAR(fstat,"%d",int,"%d",fd,"%p",buf,int fd, struct stat *buf)//not valid
GENERIC_DECLARE_2_VAR(lstat,"%d",int,"%s",path,"%p",buf,const char *path, struct stat *buf)//not valid
GENERIC_DECLARE_2_VAR(chmod,"%d",int,"%s",path,"%u",mode,const char *path, mode_t mode)
GENERIC_DECLARE_2_VAR(mkdir,"%d",int,"%s",pathname,"%u",mode,const char *pathname, mode_t mode)//not valid
GENERIC_DECLARE_2_VAR(rename,"%d",int,"%s", oldpath,"%s", newpath,const char *oldpath, const char *newpath)//not valid
GENERIC_DECLARE_2_VAR(ftruncate,"%d",int,"%d", fd,"%jd", length,int fd, off_t length)//not valid
GENERIC_DECLARE_2_VAR(getcwd,"%s",char*,"%p", buf,"%zu", size,char *buf, size_t size)//not valid
GENERIC_DECLARE_2_VAR(link,"%d",int,"%s", oldpath,"%s", newpath,const char *oldpath, const char *newpath)//not valid
GENERIC_DECLARE_2_VAR(symlink,"%d",int,"%s", oldpath,"%s", newpath,const char *oldpath, const char *newpath)//not valid
GENERIC_DECLARE_2_VAR(fchmod,"%d",int,"%d", fd,"%u", mode,int fd, mode_t mode)//not valid
GENERIC_DECLARE_2_VAR(mkfifo,"%d",int,"%s", pathname,"%u", mode,const char *pathname, mode_t mode)//not valid
GENERIC_DECLARE_2_VAR(fputs_unlocked,"%d",int,"%p", s,"%p", stream, const char *s, FILE *stream)//not valid
GENERIC_DECLARE_2_VAR(ungetc,"%d",int,"%d", c,"%p", stream, int c, FILE *stream)//not valid
GENERIC_DECLARE_2_VAR(setlocale,"%p",char*,"%d", category,"%s", locale, int category, const char *locale)//not valid


/*3 para*/
#define GENERIC_DECLARE_3_VAR(name,returnFmt,returnType,para1Fmt,para1,para2Fmt,para2,para3Fmt,para3,...)\
returnType name(__VA_ARGS__){						\
	if(old_##name == NULL){							\
		void *handle = dlopen("libc.so.6",RTLD_LAZY);\
		if(handle!=NULL){							\
			old_##name = dlsym(handle,#name);		\
		}											\
	}												\
	returnType returns;								\
	if(old_##name != NULL){							\
		returns = old_##name(para1,para2,para3);	\
		char *tmp = mygetenv("MONITOR_OUT");		\
		if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){\
			fprintf(stderr,"[monitor] "#name"("para1Fmt","para2Fmt","para3Fmt") = "returnFmt"\n",para1,para2,para3,returns);\
		}else{										\
			FILE* fFile = myfopen(tmp,"a");			\
            if(fFile!=NULL){						\
	            fprintf(fFile,"[moniter] "#name"("para1Fmt","para2Fmt","para3Fmt") = "returnFmt"\n",para1,para2,para3,returns);\
            }										\
            myfclose(fFile);   						\
		}											\
	}												\
	return returns;									\
}
GENERIC_DECLARE_3_VAR(__lxstat,"%d",int,"%d",ver,"%s",path,"%p",stat_buf,int ver, const char *path, struct stat *stat_buf)
GENERIC_DECLARE_3_VAR(readdir_r,"%d",int,"%p",dirp,"%p",entry,"%p",result,DIR *dirp, struct dirent *entry, struct dirent **result)
GENERIC_DECLARE_3_VAR(setenv,"%d",int,"\'%s\'",name,"%s",value,"%d",overwrite,const char *name, const char *value, int overwrite)
GENERIC_DECLARE_3_VAR(chown,"%d",int,"\'%s\'",path,"%d",owner,"%d",group,const char *path, uid_t owner, gid_t group)
GENERIC_DECLARE_3_VAR(fchown,"%d",int,"%d",fd,"%d",owner,"%d",group,int fd, uid_t owner, gid_t group)
GENERIC_DECLARE_3_VAR(read,"%zd",ssize_t,"%d",fd,"%p",buf,"%zu",count,int fd, void *buf, size_t count)
GENERIC_DECLARE_3_VAR(readlink,"%zd",ssize_t,"%s",path,"%p",buf,"%zu",bufsiz,const char *path, char *buf, size_t bufsiz)
GENERIC_DECLARE_3_VAR(write,"%zd",ssize_t,"%d",fd,"%p",buf,"%zu",count,int fd, const void *buf, size_t count)


/*4 para*/
#define GENERIC_DECLARE_4_VAR(name,returnFmt,returnType,para1Fmt,para1,para2Fmt,para2,para3Fmt,para3,para4Fmt,para4,...)\
returnType name(__VA_ARGS__){						\
	if(old_##name == NULL){							\
		void *handle = dlopen("libc.so.6",RTLD_LAZY);\
		if(handle!=NULL){							\
			old_##name = dlsym(handle,#name);		\
		}											\
	}												\
	returnType returns;								\
	if(old_##name != NULL){							\
		returns = old_##name(para1,para2,para3,para4);\
		char *tmp = mygetenv("MONITOR_OUT");		\
		if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){\
			fprintf(stderr,"[monitor] "#name"("para1Fmt","para2Fmt","para3Fmt","para4Fmt") = "returnFmt"\n",para1,para2,para3,para4,returns);\
		}else{										\
			FILE* fFile = myfopen(tmp,"a");			\
            if(fFile!=NULL){						\
	            fprintf(fFile,"[moniter] "#name"("para1Fmt","para2Fmt","para3Fmt","para4Fmt") = "returnFmt"\n",para1,para2,para3,para4,returns);\
            }										\
            myfclose(fFile); 		     			\
		}											\
	}												\
	return returns;									\
}
GENERIC_DECLARE_4_VAR(pread,"%zd",ssize_t,"%d",fd,"%p",buf,"%zu",count,"%jd",offset,int fd, void *buf, size_t count, off_t offset)//not valid
GENERIC_DECLARE_4_VAR(pwrite,"%zd",ssize_t,"%d",fd,"%p",buf,"%zu",count,"%jd",offset,int fd, const void *buf, size_t count, off_t offset)//not valid
GENERIC_DECLARE_4_VAR(setvbuf,"%d",int,"%p",stream,"%p",buf,"%d",mode,"%zu",size,FILE *stream, char *buf, int mode, size_t size)//not valid


/*const para*/
//ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset){
//        if(old_pwrite == NULL){
//                void *handle = dlopen("libc.so.6",RTLD_LAZY);
//                if(handle != NULL){
//                        old_pwrite= dlsym(handle,"pwrite");
//                }
//        }
//        ssize_t returns;
//        void* bbuf = malloc(sizeof(size_t)*count);
//        memcpy(bbuf,buf,sizeof(size_t)*count);
//        if(old_pwrite != NULL){
//                returns = old_pwrite(fd,bbuf,count,offset);//warning: passing argument 2 of ‘old_write’ discards ‘const’ qualifier
//                char *tmp = mygetenv("MONITOR_OUT");
//                if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){
//                        fprintf(stderr,"[monitor] pwrite(%d,%p,%zu,%jd) = %zd\n",fd,buf,count,offset,returns);//‘%zd’ expects argument of type ‘signed size_t’, but argument 7 has type ‘unsigned int’
//                }else{
//                        FILE* fFile = myfopen(tmp,"a");
//                        if(fFile!=NULL){
//                                fprintf(fFile,"[monitor] pwrite(%d,%p,%zu,%jd) = %zd\n",fd,buf,count,offset,returns);
//                        }
//                        fclose(fFile);
//                }
//        }
//        return returns;
//}


/*return void*/
void exit(int status) {
        if(old_exit == NULL){
                void *handle = dlopen("libc.so.6",RTLD_LAZY);
                if(handle != NULL){
                        old_exit= dlsym(handle,"exit");
                }
        }
        if(old_exit != NULL){
                char *tmp = mygetenv("MONITOR_OUT");
                if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){
                    fprintf(stderr,"[monitor] exit(%d)\n",status);
                }else{
                    FILE* fFile = myfopen(tmp,"a");
                    if(fFile!=NULL){
                        fprintf(fFile,"[monitor] exit(%d)\n",status);
                    }
                    myfclose(fFile);
                }
        }
        old_exit(status);
}

void _exit(int status){
        if(old__exit == NULL){
                void *handle = dlopen("libc.so.6",RTLD_LAZY);
                if(handle != NULL){
                        old__exit= dlsym(handle,"_exit");
                }
        }
        if(old__exit != NULL){
                char *tmp = mygetenv("MONITOR_OUT");
                if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){
                    fprintf(stderr,"[monitor] _exit(%d)\n",status);
                }else{
                    FILE* fFile = myfopen(tmp,"a");
                    if(fFile!=NULL){
                        fprintf(fFile,"[monitor] _exit(%d)\n",status);
                    }
                    myfclose(fFile);
                }
        }
        old__exit(0);
}

void srand(unsigned int seed){
        if(old_srand == NULL){
                void *handle = dlopen("libc.so.6",RTLD_LAZY);
                if(handle != NULL){
                        old_srand= dlsym(handle,"srand");
                }
        }
        if(old_srand != NULL){
                char *tmp = mygetenv("MONITOR_OUT");
                if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){
                    fprintf(stderr,"[monitor] srand(%d)\n",seed);
                }else{
                    FILE* fFile = myfopen(tmp,"a");
                    if(fFile!=NULL){
                        fprintf(fFile,"[monitor] srand(%d)\n",seed);
                    }
                    myfclose(fFile);
                }
        }
        old_srand(seed);
}

void perror(const char *s){
        if(old_perror == NULL){
                void *handle = dlopen("libc.so.6",RTLD_LAZY);
                if(handle != NULL){
                        old_perror= dlsym(handle,"perror");
                }
        }
        if(old_perror != NULL){
                char *tmp = mygetenv("MONITOR_OUT");
                if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){
                    fprintf(stderr,"[monitor] perror(%s)\n",s);
                }else{
                    FILE* fFile = myfopen(tmp,"a");
                    if(fFile!=NULL){
                        fprintf(fFile,"[monitor] perror(%s)\n",s);
                    }
                    myfclose(fFile);
                }
        }
        old_perror(s);
}

void rewinddir(DIR *dirp){
        if(old_rewinddir == NULL){
                void *handle = dlopen("libc.so.6",RTLD_LAZY);
                if(handle != NULL){
                        old_rewinddir= dlsym(handle,"rewinddir");
                }
        }
        if(old_rewinddir != NULL){
                char *tmp = mygetenv("MONITOR_OUT");
                if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){
                    fprintf(stderr,"[monitor] rewinddir(%p)\n",dirp);
                }else{
                    FILE* fFile = myfopen(tmp,"a");
                    if(fFile!=NULL){
                        fprintf(fFile,"[monitor] rewinddir(%p)\n",dirp);
                    }
                    myfclose(fFile);
                }
        }
        old_rewinddir(dirp);
}

void seekdir(DIR *dirp, long loc){
        if(old_seekdir == NULL){
                void *handle = dlopen("libc.so.6",RTLD_LAZY);
                if(handle != NULL){
                        old_seekdir= dlsym(handle,"seekdir");
                }
        }
        if(old_seekdir != NULL){
                char *tmp = mygetenv("MONITOR_OUT");
                if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){
                    fprintf(stderr,"[monitor] seekdir(%p,%ld)\n",dirp,loc);
                }else{
                    FILE* fFile = myfopen(tmp,"a");
                    if(fFile!=NULL){
                        fprintf(fFile,"[monitor] seekdir(%p,%ld)\n",dirp,loc);
                    }
                    myfclose(fFile);
                }
        }
        old_seekdir(dirp,loc);
}

void setbuf(FILE *stream, char *buf){
        if(old_setbuf == NULL){
                void *handle = dlopen("libc.so.6",RTLD_LAZY);
                if(handle != NULL){
                        old_setbuf = dlsym(handle,"setbuf");
                }
        }
        if(old_setbuf != NULL){
                char *tmp = mygetenv("MONITOR_OUT");
                if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){
                    fprintf(stderr,"[monitor] setbuf(%p,%p)\n",stream,buf);
                }else{
                    FILE* fFile = myfopen(tmp,"a");
                    if(fFile!=NULL){
                        fprintf(fFile,"[monitor] setbuf(%p,%p)\n",stream,buf);
                    }
                    myfclose(fFile);
                }
        }
        old_setbuf(stream,buf);
}

/*exec*/
//int execv(const char *path, char *const argv[]);//ref
int execl(const char *path, const char *arg, ...){
        if(old_execv == NULL){
                void *handle = dlopen("libc.so.6",RTLD_LAZY);
                if(handle != NULL){
                        old_execv= dlsym(handle,"execv");
                }
        }
        int returns;
        if(old_execv != NULL){
                char * argv[20];//error: array size missing in ‘argv’
                va_list ap;
                va_start(ap,arg);
                const char *tmpp = va_arg(ap,const char*);
                int i = 0;
                while(tmpp!=NULL){
                argv[i] = malloc(strlen(tmpp)+1);//allocate in place
                strncpy(argv[i],tmpp,strlen(tmpp)+1);
                tmpp = va_arg(ap,const char*);
                i++;
                }
                argv[i] = NULL;
                va_end(ap);

                char *tmp = mygetenv("MONITOR_OUT");
                if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){
                        fprintf(stderr,"[monitor] execl(%s,",path);//
                        va_list ap;
                        va_start(ap,arg);
                        const char *tmpp = va_arg(ap,const char*);
                        fprintf(stderr,"%s",tmpp);

                        tmpp = va_arg(ap,const char*);
                        while(tmpp!=NULL){
                            fprintf(stderr,",%s",tmpp);
                        }
                        fprintf(stderr,")\n");
                        if(returns = old_execv(path,argv)<0){//
                            fprintf(stderr," = %d\n",returns);
                        }
                }else{
                        FILE* fFile = myfopen(tmp,"a");
                        if(fFile!=NULL){
                                fprintf(fFile,"[monitor] execl(%s,",path);//
                                va_list ap;
                                va_start(ap,arg);
                                const char *tmpp = va_arg(ap,const char*);
                                fprintf(fFile,"%s",tmpp);

                                tmpp = va_arg(ap,const char*);
                                while(tmpp!=NULL){
                                        fprintf(fFile,",%s",tmpp);
                                }
                                fprintf(fFile,")\n");

                                myfflush(fFile);
                                if(returns = old_execv(path,argv)<0){//
                                        fprintf(fFile," = %d\n",returns);
                                }
                        }
                        myfclose(fFile);
                }
        }
        return returns;

}

//int execvp(const char *file, char *const argv[]);//ref
int execlp(const char *file, const char *arg, ...){
        if(old_execvp == NULL){
                void *handle = dlopen("libc.so.6",RTLD_LAZY);
                if(handle != NULL){
                        old_execvp= dlsym(handle,"execvp");
                }
        }
        int returns;
        if(old_execvp != NULL){
                char * argv[20];//error: array size missing in ‘argv’
                va_list ap;
                va_start(ap,arg);
                const char *tmpp = va_arg(ap,const char*);
                int i = 0;
                while(tmpp!=NULL){
                argv[i] = malloc(strlen(tmpp)+1);//allocate in place
                strncpy(argv[i],tmpp,strlen(tmpp)+1);
                tmpp = va_arg(ap,const char*);
                i++;
                }
                argv[i] = NULL;
                va_end(ap);

                char *tmp = mygetenv("MONITOR_OUT");
                if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){
                        fprintf(stderr,"[monitor] execlp(%s,",file);//
                        va_list ap;
                        va_start(ap,arg);
                        const char *tmpp = va_arg(ap,const char*);
                        fprintf(stderr,"%s",tmpp);

                        tmpp = va_arg(ap,const char*);
                        while(tmpp!=NULL){
                            fprintf(stderr,",%s",tmpp);
                        }
                        fprintf(stderr,")\n");
                        if(returns = old_execvp(file,argv)<0){//
                            fprintf(stderr," = %d\n",returns);
                        }
                }else{
                        FILE* fFile = myfopen(tmp,"a");
                        if(fFile!=NULL){
                                fprintf(fFile,"[monitor] execlp(%s,",file);//
                                va_list ap;
                                va_start(ap,arg);
                                const char *tmpp = va_arg(ap,const char*);
                                fprintf(fFile,"%s",tmpp);

                                tmpp = va_arg(ap,const char*);
                                while(tmpp!=NULL){
                                        fprintf(fFile,",%s",tmpp);
                                }
                                fprintf(fFile,")\n");

                                myfflush(fFile);
                                if(returns = old_execvp(file,argv)<0){//
                                        fprintf(fFile," = %d\n",returns);
                                }
                        }
                        myfclose(fFile);
                }
        }
        return returns;
}

int execv(const char *path, char *const argv[]){
        if(old_execv == NULL){
                void *handle = dlopen("libc.so.6",RTLD_LAZY);
                if(handle != NULL){
                        old_execv= dlsym(handle,"execv");
                }
        }
        int returns;
        if(old_execv != NULL){
                char *tmp = mygetenv("MONITOR_OUT");
                if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){
                        fprintf(stderr,"[monitor] execv(%s,%p)\n",path,argv);//
                        if(returns = old_execv(path,argv)<0){//
                            fprintf(stderr," = %d\n",returns);
                        }
                }else{
                        FILE* fFile = myfopen(tmp,"a");
                        if(fFile!=NULL){
                                fprintf(fFile,"[monitor] execv(%s,%p)\n",path,argv);//
                                myfflush(fFile);
                                if(returns = old_execv(path,argv)<0){//
                                        fprintf(fFile," = %d\n",returns);
                                }
                        }
                        myfclose(fFile);
                }
        }
        return returns;
}

int execvp(const char *file, char *const argv[]){
        if(old_execvp == NULL){
                void *handle = dlopen("libc.so.6",RTLD_LAZY);
                if(handle != NULL){
                        old_execvp= dlsym(handle,"execvp");
                }
        }
        int returns;
        if(old_execvp != NULL){
                char *tmp = mygetenv("MONITOR_OUT");
                if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){
                        fprintf(stderr,"[monitor] execvp(%s,%p)\n",file,argv);//
                        if(returns = old_execvp(file,argv)<0){//
                            fprintf(stderr," = %d\n",returns);
                        }
                }else{
                        FILE* fFile = myfopen(tmp,"a");
                        if(fFile!=NULL){
                                fprintf(fFile,"[monitor] execvp(%s,%p)\n",file,argv);//
                                myfflush(fFile);
                                if(returns = old_execvp(file,argv)<0){//
                                        fprintf(fFile," = %d\n",returns);
                                }
                        }
                        myfclose(fFile);
                }
        }
        return returns;
}

int execve(const char *filename, char *const argv[], char *const envp[]){
        if(old_execve == NULL){
                void *handle = dlopen("libc.so.6",RTLD_LAZY);
                if(handle != NULL){
                        old_execve= dlsym(handle,"execve");
                }
        }
        int returns;
        if(old_execve != NULL){
                char *tmp = mygetenv("MONITOR_OUT");
                if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){
                        fprintf(stderr,"[monitor] execve(%s,%p,%p)\n",filename,argv,envp);//
                        if(returns = old_execve(filename,argv,envp)<0){//
                            fprintf(stderr," = %d\n",returns);
                        }
                }else{
                        FILE* fFile = myfopen(tmp,"a");
                        if(fFile!=NULL){
                                fprintf(fFile,"[monitor] execve(%s,%p,%p)\n",filename,argv,envp);//
                                myfflush(fFile);
                                if(returns = old_execve(filename,argv,envp)<0){//
                                        fprintf(fFile," = %d\n",returns);
                                }
                        }
                        myfclose(fFile);
                }
        }
        return returns;
}
int execvpe(const char *file, char *const argv[], char *const envp[]){
        if(old_execvpe == NULL){
                void *handle = dlopen("libc.so.6",RTLD_LAZY);
                if(handle != NULL){
                        old_execvpe= dlsym(handle,"execvpe");
                }
        }
        int returns;
        if(old_execvpe != NULL){
                char *tmp = mygetenv("MONITOR_OUT");
                if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){
                        fprintf(stderr,"[monitor] execvpe(%s,%p,%p)\n",file,argv,envp);//
                        if(returns = old_execvpe(file,argv,envp)<0){//
                            fprintf(stderr," = %d\n",returns);
                        }
                }else{
                        FILE* fFile = myfopen(tmp,"a");
                        if(fFile!=NULL){
                                fprintf(fFile,"[monitor] execvpe(%s,%p,%p)\n",file,argv,envp);//
                                myfflush(fFile);
                                if(returns = old_execvpe(file,argv,envp)<0){//
                                        fprintf(fFile," = %d\n",returns);
                                }
                        }
                        myfclose(fFile);
                }
        }
        return returns;
}
