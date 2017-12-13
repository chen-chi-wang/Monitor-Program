# A 'netstat -nap'-like Program
## Requirement
Implement a 'netstat -nap' tool by yourself. You have to list all the existing TCP and UDP connections. For each identified connection (socket descriptor), find the corresponding process name and its command lines that creates the connection (socket descriptor). **You have to implement all the features by yourself and cannot make calls to the system built-in netstat program nor parse output from 'netstat -nap'.**

To provide more flexibilities, your program have to accept several predefined options, including

- -t or --tcp: list only TCP connections.
- -u or --udp: list only UDP connections.

When no argument is passed, your program should output all identified connections. You may test your program with a root account so that your program would be able to access `/proc` files owned by other users.

## Demo
### Run the command without any argument
```
$ sudo ./netstat_like
```

<img src="https://i.imgur.com/XnOKQdQ.png" width="700">

### Run the command with --tcp
```
$ sudo ./netstat_like --tcp
```
<img src="https://i.imgur.com/pgjFUxf.png" width="700">


### Run the command with --ucp
```
sudo ./netstat_like --udp
```

<img src="https://i.imgur.com/SzZGbAX.png" width="700">

## Principle
- Look at the two files `/proc/network/tcp` and `/proc/network/udp`
- Read files in `/proc/[pid]/fd`
- Traverse all `/proc/[pid]/fd` directories and identify socket descriptors. The socket descriptors are actually symbolic links point to **`socket:[inode]`**, where inode is the corresponding inode number used in `/proc/network/tcp` and `/proc/network/udp`.
