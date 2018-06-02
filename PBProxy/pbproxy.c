#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <openssl/aes.h>
#include<openssl/hmac.h>
#include<openssl/buffer.h>
#include<openssl/rand.h>
#include<openssl/opensslconf.h>
#define BLOCK_SIZE 4096

// ATMIKA SHARMA
//111464371


struct ctr_state
{
unsigned char IVec[16];
unsigned int num;
unsigned char ecount[16];
};//structure declaration ends

char * key_val(const char * filename)
{
FILE *file = fopen(filename,"r");
long int size=0;

if(!file)
	{
	fprintf(stderr,"kuch to err hai key ka");
	return NULL;
	}
fseek(file,0,SEEK_END);
size=ftell(file);
rewind (file);

char * result=(char*) malloc(size);
if(!result)
	{
	fprintf(stderr,"memory err\n");
	return NULL;
	}

if(fread(result,1,size,file)!=size)
	{
	fprintf(stderr,"read err\n");
	return NULL;	
	}

fclose(file);
return result;
}

void pclient (int destination_port, struct hostent * destination_hostname, char * key)
{
AES_KEY  activation_key;
int cfd =-1;
int reading=0;
struct sockaddr_in server,server2;
char buf[BLOCK_SIZE];
cfd=socket(AF_INET, SOCK_STREAM,0);


bzero((char *) &server,sizeof(server));
server.sin_family=AF_INET;
server.sin_port=htons(destination_port);
server.sin_addr.s_addr=((struct in_addr *)(destination_hostname->h_addr))->s_addr;


if(-1 == connect(cfd,(struct sockaddr *)&server,sizeof(server)))
	{
	fprintf(stderr,"connection failed,check if dest port open");
	return;
	}// if condition ends
	printf("connection successful");
	
	fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
	fcntl(cfd, F_SETFL, O_NONBLOCK);
	
if(AES_set_encrypt_key(key,128,&activation_key)<0)
	{
	fprintf(stderr,"encryption key err");
	return;
	}

	while(1)
		{
		while((reading=read(STDIN_FILENO,buf,BLOCK_SIZE))>=0)
			{
			if(reading==0)
				{
				fprintf(stderr,"client exiting");
				return;
				}//reading =0 if
			if(reading>0)
				{
				struct ctr_state state;
				unsigned char IV[8];
				unsigned char encr[reading];
				if(!RAND_bytes(IV,8))
					{
					fprintf(stderr,"err generating random bytes");						
					
					}// random bytes if ends here
				
				char * temp = (char*) malloc(reading +8);
				memcpy(temp,IV,8);
				
				//initializing state values now
				state.num=0;
				memset(state.IVec +8,0,8);	
				memcpy(state.IVec,IV,8);
				memset(state.ecount,0,16);
				AES_ctr128_encrypt(buf, encr, reading, &activation_key, state.IVec, state.ecount, &state.num);
				
				memcpy(temp+8,encr,reading);
				write(cfd,temp,reading+8);
				free(temp);				
			
	
				}//reading>condition

			if(reading<BLOCK_SIZE)
				{
				break;
				}//reading<blocksize condition					
					
			}//reading while ends here

		while((reading=read(cfd,buf,BLOCK_SIZE))>=0)
			{
			if(reading==0)
				{
				fprintf(stderr,"client exiting");
				return;
				}//reading =0 if
			if(reading>0)
				{
				struct ctr_state state;
				unsigned char IV[8];
				unsigned char decr[reading-8];
				memcpy(IV,buf,8);
				
				//initializing state values now
				state.num=0;
				memset(state.IVec +8,0,8);	
				memcpy(state.IVec,IV,8);
				memset(state.ecount,0,16);
				AES_ctr128_encrypt(buf+8, decr, reading-8, &activation_key, state.IVec, state.ecount, &state.num);
				
				write(STDOUT_FILENO,decr,reading-8);
					
			
	
				}//reading>condition

			if(reading<BLOCK_SIZE)
				{
				break;
				}//reading<blocksize condition					
					

			}// 2nd reading while ends

		
		}// while true ends

}// pclient declaration ends


void pserver( int listening_port, int destination_port, struct hostent * destination_hostname, char * key)
{

struct sockaddr_in server, server2;
int asfd =-1;
int reading =0;
char buf[BLOCK_SIZE];
AES_KEY aes_key;
int flags;

int sfd=socket(AF_INET, SOCK_STREAM, 0);
asfd=socket(AF_INET, SOCK_STREAM,0);
server2.sin_family=AF_INET;
server2.sin_addr.s_addr=((struct in_addr *)(destination_hostname->h_addr))->s_addr;
server2.sin_port=htons(destination_port);

bzero((char*)&server,sizeof(server));
server.sin_family=AF_INET;
server.sin_addr.s_addr=INADDR_ANY;
server.sin_port=htons(listening_port);

if(0>bind(sfd,(struct sockaddr *)&server,sizeof(server)))
	{
	fprintf(stderr,"bind err");
	return;
	}// bind if ends

if(0>listen(sfd,10))
	{
	fprintf(stderr,"listen err");
	return;
	}//listen if ends

while(1)
	{
	struct sockaddr_in dest_addr;
	socklen_t len;
	int accepted_fd=-1;

	len=sizeof(dest_addr);
	accepted_fd=accept(sfd, (struct sockaddr *)&dest_addr,&len);
	fcntl(accepted_fd,F_SETFL,flags | O_NONBLOCK);
	
	if(-1==connect(asfd,(struct sockaddr *) &server2, sizeof(server2)))
		{
		fprintf(stderr,"accepted session connect failed");
		return;
		}//connect failed if ends

	else
		{
		printf("connection established");
		}// else ends	
	
	fcntl(asfd,F_SETFL,flags | O_NONBLOCK);
	memset(buf,0,sizeof(buf));
	
	if(AES_set_encrypt_key(key,128,&aes_key)<0)
		{
		fprintf(stderr,"encr key err");	
		}

	while(1)
		{
			
		while((reading=read(accepted_fd,buf,BLOCK_SIZE))>=0)
			{
			if(reading==0)
				{
				close(accepted_fd);
				close(asfd);
				fprintf(stderr,"EXIT");	
				}// reading=0 if

			if(reading>0)
				{	
				struct ctr_state state;
				
				unsigned char IV[8];
				unsigned char decr[reading-8];
				memcpy(IV,buf,8);
				
				//initializing state
				state.num=0;
				memset(state.IVec+8,0,8);
				memcpy(state.IVec,IV,8);
				memset(state.ecount,0,16);
				AES_ctr128_encrypt(buf+8,decr,reading-8,&aes_key,state.IVec,state.ecount,&state.num);
				write(asfd,decr,reading-8);
							
				
				}//reading >0 if
			
			if(reading < BLOCK_SIZE)
				{
				break;
				}// reading <block_size
		
			}// first reading while  ends


		while((reading=read(asfd,buf,BLOCK_SIZE))>=0)
			{
				
				if(reading==0)
				{
				close(accepted_fd);
				close(asfd);
				fprintf(stderr,"EXIT");	
				}// reading=0 if

			if(reading>0)
				{	
				struct ctr_state state;
				
				unsigned char IV[8];
				unsigned char encr[reading];
				if(!RAND_bytes(IV,8))
					{
					fprintf(stderr,"random gen err");
					}// random if
			
				char *temp=(char *)malloc(reading+8);
				
				memcpy(temp,IV,8);
				
				//initializing state
				state.num=0;
				memset(state.IVec+8,0,8);
				memcpy(state.IVec,IV,8);
				memset(state.ecount,0,16);

				AES_ctr128_encrypt(buf,encr,reading,&aes_key,state.IVec,state.ecount,&state.num);
				memcpy(temp + 8, encr, reading);
				write(accepted_fd,temp,reading+8);
				free(temp);
							
				
				}//reading >0 if
			
			if(reading < BLOCK_SIZE)
				{
				break;
				}// reading <block_size


			


			}// second while ends		
	

		}//while (1) ends
	

	}// while true ends


}// pserver definition ends


int main(int argc, char * argv[])
{
int option=0;
int listening_port=-1;
int proxy_mode = 0;
char key_file[BLOCK_SIZE];
int destination_port =-1;
char destination_hostname[BLOCK_SIZE];
while((option=getopt(argc,argv,"l:k:")) != -1)
	{
	switch(option)
		{
		case 'l': listening_port=atoi(optarg);
				proxy_mode=1;
				break;
		case 'k': strcpy(key_file,optarg);
			break;
		case '?': printf("unknown option \n");
			break;
		default:
			printf("exiting");
			return 0;
				
		}//switch ends
	}//getopt while ends
strcpy(destination_hostname,argv[optind]);
destination_port=atoi(argv[optind+1]);
char *key=key_val(key_file);

if(!key)
	{
	fprintf(stderr,"key not found");
	return 0;
	}// key not found if

struct hostent *dest_host = NULL;
dest_host=gethostbyname(destination_hostname);
if(!dest_host)
	{
	fprintf(stderr,"host addr err");	
	return 0;	
	}// dest hostname err if ends	
if(proxy_mode)
	{
	pserver(listening_port,destination_port,dest_host,key);
	}// proxy mode if
	
else
	{
	pclient(destination_port,dest_host,key);	
	}
return 0;
}// int main ends

























































































































































