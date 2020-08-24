// Tencent is pleased to support the open source community by making HaboMalHunter available.
// Copyright (C) 2017 THL A29 Limited, a Tencent company. All rights reserved.
// Licensed under the MIT License (the "License"); you may not use this file except in 
// compliance with the License. You may obtain a copy of the License at
// 
// http://opensource.org/licenses/MIT
// 
// Unless required by applicable law or agreed to in writing, software distributed under the 
// License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
// either express or implied. See the License for the specific language governing permissions 
// and limitations under the License.

/*
Author: 
Date:	August 18, 2016
Description: Linux Malware Analysis System Target Loader
1. print pid
2. pause and waiting for signal
3. execve to load the target
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

void print_pid(){
	pid_t current_pid = getpid();
	printf("%d\n",current_pid);
	fflush(stdout);
	return;
}
void sig_handler(int signum){
	//printf("Received signal %d\n",signum);
}
void sig_manager(){
	signal(SIGCONT,sig_handler);
}
void target_loader(char* target, char** para_list, char** envp){
	int ret = execve(target,para_list,envp);
	if (-1==ret){
		printf("execve error:%s for loading the target:%s\n", strerror(errno),target);
		exit(2);
	}
}
void usage(){
	printf("usage: target_loader target_path target_params\n");
}
// Support for run with params
void get_para_list(int argc, char** argv, char** para_list){
    for(int i=0;i<argc;i++){
        if(i==argc-1){
            para_list[i]=NULL;
            continue;
        }
        para_list[i]=argv[i+1];
    }
}
int main(int argc, char** argv, char** envp){
	char* target=NULL;
	//TODO LD_PRELOAD, LD_DEBUG
	if (2>argc){
		usage();
		exit(1);
	}else{
		target = argv[1];
	}
	print_pid();
	sig_manager();
	pause();

    char* para_list[argc];
    get_para_list(argc, argv, para_list);
	target_loader(target,para_list,envp);
	return 0;
}
