# Monitor-Program

## Requirement
We are going to practice library injection and API hijacking. 
- Please implement a **"library call monitor" (LCM)** program that is able to show the activities of an arbitrary binary running on a Linux operating system.

>*library call monitor ex: `ltrace` - trace all library call*

- You have to implement your LCM as a shared library and inject the shared library into a process using `LD_PRELOAD`. 
- You have to dump the library calls as well as a summary of passed parameters. 
- Please monitor at least the functions listed in the section "Minimum Requirements" below. 
- The result should be stored into a filename specified by an environment variable "`MONITOR_OUTPUT`".
- If the value of MONITOR_OUTPUT is `stderr`, output the messages to standart error instead of a file.

### Minimum Requirements
Here is the minimum list of monitored library calls.

<img src="https://i.imgur.com/1qFgaAp.png" width="675">


## Demo
Let's monitor `ls` program as example.

We can set the value of `MONITOR_OUTPUT` to be a specified filename, ex: *monitor.out*.

As you can see, `ls` can still function normally under our monitoring.

`$ MONITOR_OUT=monitor.out LD_PRELOAD=./inject.so /bin/ls -la`

<img src="https://i.imgur.com/oPEoy1a.png" width="510">

The *monitor.out* contains monitor information.

`$ vim monitor.out`

<img src="https://i.imgur.com/O70Y9f5.png" width="510">


If we set the value of `MONITOR_OUTPUT` to be `stderr`, the monitor information will directly show up in the standard output.

`MONITOR_OUT=stderr LD_PRELOAD=./inject.so /bin/ls -la`

<img src="https://i.imgur.com/pCpfCrN.png" width="504">

## Lazy Loading
In order to monitor program in runtime, we modified the function (in the minimum requirements list) definition (so as to dump the passed parameter) and compiled it to shared library.

When executing the monitored program, using the `LD_PRELOAD` to set our shared libary to the highest precedence, the monitoring effect will show up.

## Data Structures and Functions
- `LD_PRELOAD`: To give shared library precedence in our own. 
- Dynamically loaded (DL) libraries
    - `dlopen()`: Open (or get the handle of) a specified shared library.
    - `dlsym()`: Search for the value of a symbol in the given library.
    - `dlclose()`: The converse of *dlopen*, which closes a shared library.

- MACRO
Here is a sample macro implementation.
    ```
    /*0 para*/
    #define GENERIC_DECLARE_0_VAR(name,returnFmt,returnType)                     \
    returnType name(void){                                                       \
        if(old_##name == NULL){                                                  \
            void *handle = dlopen("libc.so.6",RTLD_LAZY);                        \
            if(handle!=NULL){                                                    \
                old_##name = dlsym(handle,#name);                                \
            }                                                                    \
        }                                                                        \
        returnType returns;                                                      \
        if(old_##name != NULL){                                                  \
            returns = old_##name();                                              \
            char *tmp = mygetenv("MONITOR_OUT");                                 \
            if(tmp==NULL||strlen(tmp)==0||*tmp==' '||strcmp(tmp,"stderr")==0){   \
                fprintf(stderr,"[monitor] "#name"() = "returnFmt"\n",returns);   \
            }else{                                                               \
                FILE* fFile = myfopen(tmp,"a");                                  \
                if(fFile!=NULL){                                                 \
                    fprintf(fFile,"[moniter] "#name"() = "returnFmt"\n",returns);\
                }                                                                \
                myfclose(fFile);                                                 \
            }                                                                    \
        }                                                                        \
        return returns;                                                          \
    }
    ```
    Since there are a lot of functions we need to monitor, I group the function into different categories by their number of parameters. 

    For each category, implement a macro for it.

    In the remaining part, I provide some special cases, which can't use macro.
    
- Variable-length functions `<strarg.h>`
    - For functions which accept argument list, ex: `execlp`, `execl`, `execle`, 
use macros in `<stdarg.h>` to access their arguments.
      - va_list, va_start, va_arg, va_end
    -  We can then convert them to their corresponding functions which accept array as argument, ie., `execvp`, `execv`, `execve`.
    
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<img src="https://i.imgur.com/JzBB9cX.png" width="585">
    
- GNU C syntax, `__attribute__` 
    - For dealing with "no return" function, ex: `exit`, `_exit`.
    
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`static void (*old__exit)(int status) __attribute__((noreturn)) = NULL;`
