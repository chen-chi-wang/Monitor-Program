/* Implement a 'netstat -nap'-like program.
*  Example:
*  	sudo ./netstat_like -t    #list tcp connections
*  	sudo ./netstat_like --tcp #list tcp connections
* 	sudo ./netstat_like       #list tcp and udp connections
*/

#include <stdio.h>
#include <stdlib.h>//free, NULL
#include <getopt.h>
#include <sys/types.h>//OPENDIR(3)
#include <dirent.h>//OPENDIR(3)
#include <string.h>//strcpy
#include <unistd.h>//READLINK(2)
#include <arpa/inet.h>//inet_pton(3) text to binary form
#include <inttypes.h>
#include <netinet/in.h>
#define MAX_RECORD 200 //tcp+tcp6 or udp+udp6
#define MSG_LEN 600 //one line charactors :9+22+22=53 53+CMD_LEN
#define CMD_LEN 400//debug passed:udp udp6 tcp tcp6

char* concat(char *str1, char *str2);
void produce_records_stage_1(char tcpRecords[MAX_RECORD][MSG_LEN],int TCP_FLAG);
void produce_records_stage_2(char tcpRecords[MAX_RECORD][MSG_LEN],int TCP_FLAG);
void print_usage(); 
char* convertAddr(int V6_FLAG,char* lineTokArr);
char (*pe)[MSG_LEN];//pointer end
int i;

int main(int argc,char* argv[]){
		int opt= 0;
		int tcp = -1, udp = -1;

		//Specifying the expected options
		//The two options t and u don't expect any argument
		static struct option long_options[] = {
				{"tcp", no_argument,       0,  't' },
				{"udp", no_argument,       0,  'u' },
				{0    ,           0,       0,   0  }
		};

		int long_index =0;
		while ((opt = getopt_long(argc, argv,"tu",
										long_options, &long_index )) != -1) {
				switch (opt) {
						case 't' : tcp = 0;
								   break;
						case 'u' : udp = 0;
								   break;
						default: print_usage();
								 exit(EXIT_FAILURE);
				}
		}

		int TCP_FLAG;
		char tcpRecords[MAX_RECORD][MSG_LEN];
		char udpRecords[MAX_RECORD][MSG_LEN];

		// List the tcp connections
		if (tcp == 0) {
				TCP_FLAG = 1;
				produce_records_stage_1(tcpRecords,TCP_FLAG);
		}

		// List the ucp connections
		if (udp == 0) {
				TCP_FLAG = 0;
				produce_records_stage_1(udpRecords,TCP_FLAG);
		}

		// List all connections
		if((tcp==-1)&&(udp==-1)){

				TCP_FLAG = 1;
				produce_records_stage_1(tcpRecords,TCP_FLAG);

				TCP_FLAG = 0;
				produce_records_stage_1(udpRecords,TCP_FLAG);
		}

		return 0;
}

void produce_records_stage_1(char tcpRecords[MAX_RECORD][MSG_LEN],int TCP_FLAG){
		ssize_t read;
		size_t len = 0;
		char str_col2[7];//char_tmp_col2 :7 60
		char str_col3[23];//140.114.177.174:38130 :3*4+3+1+5=21 + 1 space = 22 + 1 null = 23
		char str_col4[23];
		char str_col1[10];//41637028_ :9 + 1 null = 10 60
		int V6_FLAG = 0;
		int change_flag=0;
		int line_cnt=0;	
		int j=0;
		char char_tmp_col2[7];//Proto_ :6 + 1 null = 7

		while(j<2){//v4 in first round, v6 in second round	

				FILE *fPtr;
				char *line = NULL;

				//v4: tcp or udp
				if(j==0){
						if(TCP_FLAG){
								V6_FLAG = 0;
								fPtr = fopen("/proc/net/tcp","rb");
								snprintf(char_tmp_col2,sizeof(char_tmp_col2),"%-6s","tcp");

						}else{
								fPtr = fopen("/proc/net/udp","rb");
								snprintf(char_tmp_col2,sizeof(char_tmp_col2),"%-6s","udp");
						}
				}
				//v6: tcp6 or udp6
				if(j==1){
						V6_FLAG = 1;
						change_flag=1;
						if(TCP_FLAG){
								fPtr = fopen("/proc/net/tcp6","rb");
								snprintf(char_tmp_col2,sizeof(char_tmp_col2),"%-6s","tcp6");
						}else{
								fPtr = fopen("/proc/net/udp6","rb");
								snprintf(char_tmp_col2,sizeof(char_tmp_col2),"%-6s","udp6");
						}
				}

				if(fPtr){
						while((read=getline(&line,&len,fPtr))!=-1){

								if(line_cnt==0){
										line_cnt++;continue;
								}else{//for reading second file purpose
										if(change_flag){
												change_flag=0;
												continue;//skip first line of v6 file
										}
								}

								char *lineTokArr = strtok(line," ");
								int i=1;
								while(lineTokArr!=NULL){		
										if(i==2||i==3||i==10){
												if(i==2){//e.g. lineTokArr=494D728C:BE44
														char tok_tmp[50];
														char *rest_of_str = NULL;
														strncpy(tok_tmp,lineTokArr,sizeof(tok_tmp)-1);
														tok_tmp[sizeof(tok_tmp)-1]='\0';

														char char_tmp_col3[50];
														char *tmpTokArr = strtok_r(tok_tmp,":",&rest_of_str);
														strncpy(char_tmp_col3,convertAddr(V6_FLAG,tmpTokArr),sizeof(char_tmp_col3)-1);
														char_tmp_col3[sizeof(char_tmp_col3)-1]='\0';
														tmpTokArr = strtok_r(NULL,":",&rest_of_str);
														int port = (int)strtol(tmpTokArr,NULL,16);
														char port_str[6];//33540 :5 + 1 null = 6 
														snprintf(port_str,sizeof(port_str),"%d",port);
														strncat(char_tmp_col3,":",sizeof(char_tmp_col3)-strlen(char_tmp_col3)-1);
														strncat(char_tmp_col3,port_str,sizeof(char_tmp_col3)-strlen(char_tmp_col3)-1);//str_col3=140.114.77.73:48708
														snprintf(str_col3,sizeof(str_col3),"%-22s",char_tmp_col3);//3*4+3+1+5=21 21+1(space)=22

												}
												if(i==3){//97EB718C:0016
														char tok_tmp[50];
														char *rest_of_str = NULL;
														strncpy(tok_tmp,lineTokArr,sizeof(tok_tmp)-1);
														tok_tmp[sizeof(tok_tmp)-1]='\0';

														char char_tmp_col4[50];
														char *tmpTokArr = strtok_r(tok_tmp,":",&rest_of_str);
														strncpy(char_tmp_col4,convertAddr(V6_FLAG,tmpTokArr),sizeof(char_tmp_col4)-1);
														char_tmp_col4[sizeof(char_tmp_col4)-1]='\0';
														tmpTokArr = strtok_r(NULL,":",&rest_of_str);
														int port = (int)strtol(tmpTokArr,NULL,16);
														char port_str[6];
														snprintf(port_str,sizeof(port_str),"%d",port);
														strncat(char_tmp_col4,":",sizeof(char_tmp_col4)-strlen(char_tmp_col4)-1);
														strncat(char_tmp_col4,port_str,sizeof(char_tmp_col4)-strlen(char_tmp_col4)-1);//140.113.235.151:22
														snprintf(str_col4,sizeof(str_col4),"%-22s",char_tmp_col4);
												}

												if(i==10){//41637028
														char char_tmp_col10[10];
														snprintf(char_tmp_col10,sizeof(char_tmp_col10),"%-9s",lineTokArr);//41637028
														strncpy(str_col1,char_tmp_col10,sizeof(str_col1)-1);
														str_col1[sizeof(str_col1)-1]='\0';
												}
										}
										lineTokArr = strtok(NULL," ");
										i++;

								}

								strncpy(str_col2,char_tmp_col2,sizeof(str_col2)-1);
								str_col2[sizeof(str_col2)-1]='\0';
								char buffer[100];

								char *free_ind = concat(str_col3,str_col4);//22+22+1=44+1
								strncpy(buffer,free_ind,sizeof(buffer)-1);
								buffer[sizeof(buffer)-1]='\0';
								free(free_ind);
	
								free_ind = concat(str_col2,buffer);
								strncpy(buffer,free_ind,sizeof(buffer)-1);
								buffer[sizeof(buffer)-1]='\0';
								free(free_ind);
			
								free_ind = concat(str_col1,buffer);
								strncpy(buffer,free_ind,sizeof(buffer)-1);
								buffer[sizeof(buffer)-1]='\0';


								strncpy(tcpRecords[line_cnt],free_ind,MSG_LEN-1);
								tcpRecords[line_cnt][MSG_LEN-1]='\0';
								free(free_ind);
//								strcpy(tcpRecords[line_cnt],strcat(str_col1,strcat(str_col2,strcat(str_col3,str_col4))));
								line_cnt++;
						}			


				}else{
						puts("open fail");//break;
				}		
				fclose(fPtr);
				if(line){//error:double free or corruption (out)//if free is not in the loop, and declare also outside the loop, then no double free problem
						free(line);								//otherwise, declare twice will solve the problem.
				}
				j++;
		}//end 2 loop
		//		if(line){//error:double free or corruption (out)//option2: take free outside the loop
		//				free(line);
		//		}

		//be careful pe is public, pe should be passed!!
		//puts("*********produce_records_stage_1 debug*********");
		for(pe=tcpRecords+1;pe<tcpRecords+MAX_RECORD;pe++){//notice that tcpRecords[0] is not used, skip it! pe will point to the end, so not commented out this line!
				if((*pe)[0]=='\0'){//==0 is equivalent
						break;
				}

//				printf("%s\n",pe);
		}
		//printf("have %ld records\n",pe-(tcpRecords+1));//Exclude title line

		//puts("**********************END**********************");
		produce_records_stage_2(tcpRecords,TCP_FLAG);
}
char* concat(char *str1, char *str2){
	char *result = malloc(strlen(str1)+strlen(str2)+1);
	strcpy(result,str1);
	strcat(result,str2);
	return result;
}
void produce_records_stage_2(char tcpRecords[MAX_RECORD][MSG_LEN],int TCP_FLAG){
		//I think only pe and tcpRecords are global variables should be passed.
		//If we don't want tcpRecords to be passed, maybe declare it outside main is a choice.
		//And be careful where pe starts from in the two-rounds test.

		DIR *dir, *dir2;// "/proc" "/proc/PID/fd" 
		char path_1[]="/proc";
		char path_2[20];//path_2=/proc/PID/fd
		char path_3[30];//path_3=/proc/PID/fd/symbolic
		char path_4[30];//path_4=/proc/PID/cmdline
		struct dirent *ptr, *ptr2;
		int i;
		dir = opendir(path_1);//path_1=/proc

		while((ptr=readdir(dir))!=NULL){

				int pid = atoi(ptr->d_name);

				//PID start!!!
				if(pid!=0){//exclude none process

						strncpy(path_2,"/proc/",sizeof(path_2)-1);
						path_2[sizeof(path_2)]='\0';
						strncat(path_2,ptr->d_name,sizeof(path_2)-strlen(path_2)-1);
						strncat(path_2,"/fd",sizeof(path_2)-strlen(path_2)-1);
						int symbolic;
						dir2 = opendir(path_2);//path_2=/proc/PID/fd
						while((ptr2=readdir(dir2))!=NULL){

								symbolic = atoi(ptr2->d_name);//0 1 2 3 symbolic
								if(symbolic>=3){

										strncpy(path_3,"/proc/",sizeof(path_3)-1);
										path_3[sizeof(path_3)]='\0';
										strncat(path_3,ptr->d_name,sizeof(path_3)-strlen(path_3)-1);
										strncat(path_3,"/fd/",sizeof(path_3)-strlen(path_3)-1);
										strncat(path_3,ptr2->d_name,sizeof(path_3)-strlen(path_3)-1);

										//convert symbolic
										char target_path[256];
										int len = readlink(path_3,target_path,sizeof(target_path));//path_3=/proc/PID/fd/symbolic

										if(len!=-1){

												target_path[len]='\0';//valid string
												char target_head[10];

												snprintf(target_head,sizeof(target_head),"%.6s",target_path);	 
												if(strcmp("socket",target_head)==0){

														char *rest_of_str = NULL;
														char *tmpTokArr = strtok_r(target_path,"]",&rest_of_str);
														tmpTokArr = strtok_r(tmpTokArr,"[",&rest_of_str);
														tmpTokArr = strtok_r(NULL,"[",&rest_of_str);//this is inode!
														//printf("%s\n",tmpTokArr);//11854 <-- this is inode!

														//traverse tcpRecords	
														char (*pc)[MSG_LEN]=tcpRecords[1];
														while(pc<pe){

																char tok_tmp[100];
																char *rest_of_str2 = NULL;
																strncpy(tok_tmp,*pc,sizeof(tok_tmp)-1);
																tok_tmp[sizeof(tok_tmp)-1]='\0';
																char *tmpTokArr2 = strtok_r(tok_tmp," ",&rest_of_str2);


																//need to traverse all the possible record head
																if(strcmp(tmpTokArr,tmpTokArr2)==0){
																		//printf("\nfind PID %s \n",ptr->d_name);//PID																
																		//printf("%s\n",tmpTokArr);//11854 <-- this is inode!
																		strncpy(path_4,"/proc/",sizeof(path_4)-1);
																		strncat(path_4,ptr->d_name,sizeof(path_4)-strlen(path_4)-1);
																		strncat(path_4,"/cmdline",sizeof(path_4)-strlen(path_4)-1);//path_4=/proc/PID/cmdline

																		FILE *fPtr_cmd = fopen(path_4,"rb");
																		char ch;
																		char cmd_buf[CMD_LEN];//fetch raw data first
																		char cmd[CMD_LEN];//replace null character
																		char *p = cmd_buf;
																		if(fPtr_cmd){
																				while((ch=fgetc(fPtr_cmd))!=EOF){
																						*p++ = ch;
																				}
																		}
																		fclose(fPtr_cmd);

																		i=0;
																		for(i;i<p-cmd_buf;i++){
																				if(cmd_buf[i]!=0){
																						cmd[i] = cmd_buf[i];	
																				}else{
																						cmd[i] = ' ';
																				}
																		}
																		cmd[p-cmd_buf] = '\0';
																		//printf("factory:%s\n",cmd);//ssh linux1.cs.nctu.edu.tw 
																		strncat(tcpRecords[(pc-(tcpRecords+1)+1)],ptr->d_name,sizeof(tcpRecords[(pc-(tcpRecords+1)+1)])-strlen(tcpRecords[(pc-(tcpRecords+1)+1)])-1);
																		strncat(tcpRecords[(pc-(tcpRecords+1)+1)],"/",sizeof(tcpRecords[(pc-(tcpRecords+1)+1)])-strlen(tcpRecords[(pc-(tcpRecords+1)+1)])-1);
																		strncat(tcpRecords[(pc-(tcpRecords+1)+1)],cmd,sizeof(tcpRecords[(pc-(tcpRecords+1)+1)])-strlen(tcpRecords[(pc-(tcpRecords+1)+1)])-1);
																		//printf("complete:%s\n",tcpRecords[(pc-(tcpRecords+1)+1)]);//complete
																		//printf("strlen:%d\n",strlen(tcpRecords[(pc-(tcpRecords+1)+1)]));//bug catched!


																		//truncate inode for debug purpose
																		char tok_tmp2[MSG_LEN];
																		char *rest_of_str3 = NULL;
																		strncpy(tok_tmp2,tcpRecords[(pc-(tcpRecords+1)+1)],sizeof(tok_tmp2)-1);
																		tok_tmp2[sizeof(tok_tmp2)-1]='\0';
																		char *tmpTokArr3 = strtok_r(tok_tmp2," ",&rest_of_str3);
																		char buffer[MSG_LEN];
																		i=0;
																		while(tmpTokArr3!=NULL){
																				//printf("i=%d\n",i);
																				//printf("%s\n",tmpTokArr3);
																				//printf("%s\n",rest_of_str3);
																				//printf("%s\n",buffer);

																				char char_tmp_col[100];
																				switch(i){
																						case 0:
																								break;
																						case 1:
																								snprintf(char_tmp_col,sizeof(char_tmp_col),"%-6s",tmpTokArr3);
																								strncpy(buffer,char_tmp_col,sizeof(buffer)-1);
																								buffer[sizeof(buffer)-1]='\0';
																								break;
																						case 2:
																						case 3:
																								snprintf(char_tmp_col,sizeof(char_tmp_col),"%-22s",tmpTokArr3);
																								strncat(buffer,char_tmp_col,sizeof(buffer)-strlen(buffer)-1);
																								break;
																						case 4:
																						default:
																								
																								strncpy(char_tmp_col,tmpTokArr3,sizeof(char_tmp_col)-1);
																								char_tmp_col[sizeof(char_tmp_col)-1]='\0';
																								strncat(char_tmp_col," ",sizeof(char_tmp_col)-strlen(char_tmp_col)-1);
																								strncat(buffer,char_tmp_col,sizeof(buffer)-strlen(buffer)-1);
																								//strcat(buffer,strcat(strcpy(char_tmp_col,tmpTokArr3)," "));
																								break;
																				}

																				i++;
																				tmpTokArr3 = strtok_r(NULL," ",&rest_of_str3);//1,2,3
																		}//end while
																		//printf("%s\n",buffer);//debug product

																}//strcmp with records	
																pc++;
														}//end pc while
												}//socket head	
										}//len!=-1
								}//symbolic>=3
						}//end dir2
						closedir(dir2);
				}//end if pid
		}//end dir 
		closedir(dir);


		//product print
		if(TCP_FLAG){
				puts("List of TCP connections:");
		}else{
				puts("List of UDP connections:");
		}
		printf("Proto Local Address         Foreign Address       PID/Program name and arguments\n");
		for(pe=tcpRecords+1;pe<tcpRecords+MAX_RECORD;pe++){//notice that tcpRecords[0] is not used, skip it!
				if((*pe)[0]=='\0'){//==0 is equivalent
						break;
				}
				char tok_tmp[MSG_LEN];
				char *rest_of_str3 = NULL;
				strncpy(tok_tmp,tcpRecords[(pe-(tcpRecords+1)+1)],sizeof(tok_tmp)-1);
				tok_tmp[sizeof(tok_tmp)-1]='\0';

				char buffer[MSG_LEN];
				char *tmpTokArr3 = strtok_r(tok_tmp," ",&rest_of_str3);
				if(tmpTokArr3!=NULL){//inode
						tmpTokArr3 = strtok_r(NULL," ",&rest_of_str3);//and the rest
				}
				strncpy(buffer,tmpTokArr3,sizeof(buffer)-1);
				buffer[sizeof(buffer)-1]='\0';
				strncat(buffer," ",sizeof(buffer)-strlen(buffer)-1);
				strncat(buffer,rest_of_str3,sizeof(buffer)-strlen(buffer)-1);
				printf("%s\n",buffer);
		}
		puts("");
}
void print_usage() {/*without definition:undefined reference to `print_usage'
collect2: error: ld returned 1 exit status*/
		printf("Usage: -t -u\n");
}
char str_ipv4[INET_ADDRSTRLEN+1];
char str_ipv6[INET6_ADDRSTRLEN+1];
char* convertAddr(int V6_FLAG,char* lineTokArr){
		if(!V6_FLAG){
				struct sockaddr_in sa4;
				//char str_ipv4[INET_ADDRSTRLEN+1];//warning: function returns address of local variable. But malloc will run out of memory (even not return NULL!!) So, I move out local arr and the problem was solved.
				//char *str_ipv4 = malloc (sizeof(char)*INET_ADDRSTRLEN);

				char c0[10],c1[10],c2[10],c3[10],c4[10],c5[10],c6[10],c7[10];
				sprintf(c0,"%c",lineTokArr[0]);
				sprintf(c1,"%c",lineTokArr[1]);
				sprintf(c2,"%c",lineTokArr[2]);
				sprintf(c3,"%c",lineTokArr[3]);
				sprintf(c4,"%c",lineTokArr[4]);
				sprintf(c5,"%c",lineTokArr[5]);
				sprintf(c6,"%c",lineTokArr[6]);
				sprintf(c7,"%c",lineTokArr[7]);
				sa4.sin_addr.s_addr = ((int)strtol(c0,NULL,16)) << 28 |
						((int)strtol(c1,NULL,16)) << 24 |
						((int)strtol(c2,NULL,16)) << 20 |
						((int)strtol(c3,NULL,16)) << 16 |
						((int)strtol(c4,NULL,16)) << 12 |
						((int)strtol(c5,NULL,16)) << 8 |
						((int)strtol(c6,NULL,16)) << 4 |
						((int)strtol(c7,NULL,16)); 
				inet_ntop(AF_INET,&(sa4.sin_addr),str_ipv4,INET_ADDRSTRLEN);
				//printf("ipv4 text: %s\n",str_ipv4);

				return str_ipv4;	
		}else{//ipv6
				struct sockaddr_in6 sa6;

				//char str_ipv6[INET6_ADDRSTRLEN+1];

				//char *str_ipv6 = malloc (sizeof(char)*INET6_ADDRSTRLEN);
				//if((str_ipv6 = malloc (sizeof(char)*INET6_ADDRSTRLEN))==NULL){//useless
				//	puts("allocation failed");
				//}

				unsigned char tmp[32];
				tmp[6] = lineTokArr[0];	
				tmp[7] = lineTokArr[1];	
				tmp[4] = lineTokArr[2];	
				tmp[5] = lineTokArr[3];	
				tmp[2] = lineTokArr[4];	
				tmp[3] = lineTokArr[5];	
				tmp[0] = lineTokArr[6];	
				tmp[1] = lineTokArr[7];	
				tmp[14] = lineTokArr[8];	
				tmp[15] = lineTokArr[9];	
				tmp[12] = lineTokArr[10];	
				tmp[13] = lineTokArr[11];	
				tmp[10] = lineTokArr[12];	
				tmp[11] = lineTokArr[13];	
				tmp[8] = lineTokArr[14];	
				tmp[9] = lineTokArr[15];	
				tmp[22] = lineTokArr[16];	
				tmp[23] = lineTokArr[17];	
				tmp[20] = lineTokArr[18];	
				tmp[21] = lineTokArr[19];	
				tmp[18] = lineTokArr[20];	
				tmp[19] = lineTokArr[21];	
				tmp[16] = lineTokArr[22];	
				tmp[17] = lineTokArr[23];	
				tmp[30] = lineTokArr[24];	
				tmp[31] = lineTokArr[25];	
				tmp[28] = lineTokArr[26];	
				tmp[29] = lineTokArr[27];	
				tmp[26] = lineTokArr[28];	
				tmp[27] = lineTokArr[29];	
				tmp[24] = lineTokArr[30];	
				tmp[25] = lineTokArr[31];	
				char aa[10],ee[10];
				sprintf(aa,"%c",tmp[6]);sprintf(ee,"%c",tmp[7]);
				sa6.sin6_addr.s6_addr[3] = ((int)strtol(aa,NULL,16)) << 4 | (((int)strtol(ee,NULL,16)) & 0xFF);
				sprintf(aa,"%c",tmp[4]);sprintf(ee,"%c",tmp[5]);
				sa6.sin6_addr.s6_addr[2] = ((int)strtol(aa,NULL,16)) << 4 | (((int)strtol(ee,NULL,16)) & 0xFF);
				sprintf(aa,"%c",tmp[2]);sprintf(ee,"%c",tmp[3]);
				sa6.sin6_addr.s6_addr[1] = ((int)strtol(aa,NULL,16)) << 4 | (((int)strtol(ee,NULL,16)) & 0xFF);
				sprintf(aa,"%c",tmp[0]);sprintf(ee,"%c",tmp[1]);
				sa6.sin6_addr.s6_addr[0] = ((int)strtol(aa,NULL,16)) << 4 | (((int)strtol(ee,NULL,16)) & 0xFF);
				sprintf(aa,"%c",tmp[14]);sprintf(ee,"%c",tmp[15]);
				sa6.sin6_addr.s6_addr[7] = ((int)strtol(aa,NULL,16)) << 4 | (((int)strtol(ee,NULL,16)) & 0xFF);
				sprintf(aa,"%c",tmp[12]);sprintf(ee,"%c",tmp[13]);
				sa6.sin6_addr.s6_addr[6] = ((int)strtol(aa,NULL,16)) << 4 | (((int)strtol(ee,NULL,16)) & 0xFF);
				sprintf(aa,"%c",tmp[10]);sprintf(ee,"%c",tmp[11]);
				sa6.sin6_addr.s6_addr[5] = ((int)strtol(aa,NULL,16)) << 4 | (((int)strtol(ee,NULL,16)) & 0xFF);
				sprintf(aa,"%c",tmp[8]);sprintf(ee,"%c",tmp[9]);
				sa6.sin6_addr.s6_addr[4] = ((int)strtol(aa,NULL,16)) << 4 | (((int)strtol(ee,NULL,16)) & 0xFF);
				sprintf(aa,"%c",tmp[22]);sprintf(ee,"%c",tmp[23]);
				sa6.sin6_addr.s6_addr[11] = ((int)strtol(aa,NULL,16)) << 4 | (((int)strtol(ee,NULL,16)) & 0xFF);
				sprintf(aa,"%c",tmp[20]);sprintf(ee,"%c",tmp[21]);
				sa6.sin6_addr.s6_addr[10] = ((int)strtol(aa,NULL,16)) << 4 | (((int)strtol(ee,NULL,16)) & 0xFF);
				sprintf(aa,"%c",tmp[18]);sprintf(ee,"%c",tmp[19]);
				sa6.sin6_addr.s6_addr[9] = ((int)strtol(aa,NULL,16)) << 4 | (((int)strtol(ee,NULL,16)) & 0xFF);
				sprintf(aa,"%c",tmp[16]);sprintf(ee,"%c",tmp[17]);
				sa6.sin6_addr.s6_addr[8] = ((int)strtol(aa,NULL,16)) << 4 | (((int)strtol(ee,NULL,16)) & 0xFF);
				sprintf(aa,"%c",tmp[30]);sprintf(ee,"%c",tmp[31]);
				sa6.sin6_addr.s6_addr[15] = ((int)strtol(aa,NULL,16)) << 4 | (((int)strtol(ee,NULL,16)) & 0xFF);
				sprintf(aa,"%c",tmp[28]);sprintf(ee,"%c",tmp[29]);
				sa6.sin6_addr.s6_addr[14] = ((int)strtol(aa,NULL,16)) << 4 | (((int)strtol(ee,NULL,16)) & 0xFF);
				sprintf(aa,"%c",tmp[26]);sprintf(ee,"%c",tmp[27]);
				sa6.sin6_addr.s6_addr[13] = ((int)strtol(aa,NULL,16)) << 4 | (((int)strtol(ee,NULL,16)) & 0xFF);
				sprintf(aa,"%c",tmp[24]);sprintf(ee,"%c",tmp[25]);
				sa6.sin6_addr.s6_addr[12] = ((int)strtol(aa,NULL,16)) << 4 | (((int)strtol(ee,NULL,16)) & 0xFF);
				inet_ntop(AF_INET6,&(sa6.sin6_addr),str_ipv6,INET6_ADDRSTRLEN);
				//printf("ipv6 text: %s\n",str_ipv6);

				return str_ipv6;	
		}	
}

