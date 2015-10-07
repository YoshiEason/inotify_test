#include <stdio.h>
#include <iostream>
#include <linux/syno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <linux/limits.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <string>
#include <map>
#include <sys/inotify.h>

#define INOTIFY_BUFFER_SIZE 131072
#define INOTIFY_ALL_EVENTS (IN_ACCESS|IN_ATTRIB|IN_CLOSE_WRITE|IN_CLOSE_NOWRITE|IN_CREATE|IN_DELETE|IN_DELETE_SELF|IN_MODIFY|IN_MOVE_SELF|IN_MOVED_FROM|IN_MOVED_TO|IN_OPEN|IN_Q_OVERFLOW|IN_ISDIR)

static volatile int run = 1;

static void signal_handler(int sig)
{
	run = 0;
}

static void ParseInotifyEvent(struct inotify_event *i)
{
  printf("wd = %d\n", i->wd);
  if (i->cookie > 0)
          printf("cookie =%4d; ", i->cookie);
  if (i->len > 0)
          printf("file =%s; ", i->name);
  printf("mask = ");
  if (i->mask & IN_ACCESS) printf("INOTIFY_ACCESS ");
  if (i->mask & IN_ATTRIB) printf("INOTIFY_ATTRIB ");
  if (i->mask & IN_CLOSE_WRITE) printf("INOTIFY_CLOSE_NOWRITE ");
  if (i->mask & IN_CLOSE_NOWRITE) printf("INOTIFY_CLOSE_WRITE ");
  if (i->mask & IN_CREATE) printf("INOTIFY_CREATE ");
  if (i->mask & IN_DELETE) printf("INOTIFY_DELETE ");
  if (i->mask & IN_DELETE_SELF) printf("INOTIFY_DELETE_SELF ");
  if (i->mask & IN_MODIFY) printf("INOTIFY_MODIFY ");
  if (i->mask & IN_MOVE_SELF) printf("INOTIFY_SELF ");
  if (i->mask & IN_MOVED_FROM) printf("INOTIFY_MOVED_FROM");
  if (i->mask & IN_MOVED_TO) printf("INOTIFY_MOVED_TO ");
  if (i->mask & IN_OPEN) printf("SYNOTIFY_OPEN ");
  if (i->mask & IN_Q_OVERFLOW) printf("INOTIFY_Q_OVERFLOW ");
  if (i->mask & IN_ISDIR) printf("INOTIFY_IS_DIR ");
  printf("\n");
}

static void print_usage() {
	std::cout << " Usage: synotify_test [OPTION]... " << std::endl;
	std::cout << " OPTION:" << std::endl;
	std::cout << " 	--add_watch [PATH]... - specify the monitored path" << std::endl;
	std::cout << " 	--delay [SECONDS] - delayed seconds until read events" << std::endl;
	std::cout << " 	--silent - do not output event to stdout" << std::endl;
}

int main(int argc, char **argv) {
	
	std::map<std::string, int> watch_list;
	int iarg = 0;
	int delay_sec = 0;
	int option_index = 0;
	bool is_silent = false;
	
	static struct option long_opts[] = {
		{"add_watch", 1, 0 , 'a'},
		{"delay", 1, 0 , 'd'},
		{"silent", 0, 0 , 's'},
		{"help", 0, 0 , 'h'},
		{0, 0, 0, 0}
	};

	while (1) {
		iarg = getopt_long(argc, argv, "", long_opts, &option_index);

		if (iarg == -1)
			break;
		
		switch(iarg) {
			case 'a':
				watch_list[optarg] = 0;
				break;
			case 'd':
				delay_sec = atoi(optarg);
				break;
			case 's':
				is_silent = true;
				break;
			case 'h':
			case '?':
			default:
				print_usage();
				return 0;
		};
	}

	for (int i = optind; i < argc; i++) {
		watch_list[argv[i]] = 0;
	}
	
	std::map<std::string, int>::iterator iter;
	std::cout << std::endl << "Add watch path: " << std::endl;
	for (iter = watch_list.begin(); iter != watch_list.end(); iter++) {
		std::cout << "	- "<< iter->first.c_str() << std::endl;
	}
	std::cout << std::endl << "Delay seconds: " << delay_sec << std::endl;

	signal(SIGHUP, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGQUIT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGPIPE, SIG_IGN);
	
	char *buffer = new char [INOTIFY_BUFFER_SIZE];
	int ret = 0;
	int wd = 0;
	int inotify_fd = inotify_init();

	if (inotify_fd < 0){
		if(errno == ENOSYS || errno == ENOTSUP){
			printf("inotify not supported\n");
			return -1;
		}
		printf("inotify_init error: %s,%d\n", strerror(errno), errno);
		return 1;
	}

	for (iter = watch_list.begin(); iter != watch_list.end(); iter++) {
		wd = inotify_add_watch(inotify_fd, iter->first.c_str(), INOTIFY_ALL_EVENTS);
		if (wd < 0)
			std::cout << "Add watch on '" << iter->first << "' failed: [" << strerror(errno) << "]" << std::endl;
		else {
			std::cout << "Watching " << iter->first << " done" << std::endl;
			iter->second = wd;
		}
	}

	if (delay_sec != 0)
		sleep(delay_sec);

	printf("Start to read events\n");

	while(run){
		
		fd_set read_set;
		struct timeval interval;
		interval.tv_sec = 1;
		interval.tv_usec = 0;
		FD_ZERO(&read_set);
		FD_SET(inotify_fd, &read_set);
		
		int rc = select(inotify_fd + 1, &read_set, NULL, NULL, &interval);
		
		if (rc < 0) {
			printf("select: %s (%d)\n", strerror(errno), errno);
			continue;
		}
		
		if (rc == 0) {
			continue;
		}
		
		if (!FD_ISSET(inotify_fd, &read_set)) {
			printf("select: fd is not set\n");
			continue;
		}
		
		size_t read_bytes = read (inotify_fd, buffer, INOTIFY_BUFFER_SIZE);

		if (read_bytes <= 0){
			printf("read error: %s\n", strerror(errno));
			goto ERR;
		} else {
			struct inotify_event *event;
			size_t parse_len = 0;
			char *p;
			for (p = buffer; p < buffer + read_bytes; ) {
				event = (struct inotify_event *) p;
				if (!is_silent)
					ParseInotifyEvent(event);
				p += sizeof(struct inotify_event) + event->len;
			}
        }
	}
ERR:
	if (inotify_fd > 0) {
		for (iter = watch_list.begin(); iter != watch_list.end(); iter++) {
			ret = inotify_rm_watch (inotify_fd, iter->second);
			if(ret < 0){
				printf("remove watch %s failed:%s\n", iter->first.c_str(),strerror(errno));
			}else
				printf("remove %s done\n", iter->first.c_str());
		}		
	}
	close(inotify_fd);
	delete [] buffer;
	return 0;
}

