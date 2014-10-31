/*
 * kinetic_heartbeat.c
 *
 *  Created on: Oct 14, 2014
 *      Author: mshafiq
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#define  KINETIC_HEARTBEAT_PORT 8123
#define  KINETIC_UUID_LENGTH	19
#define  KINETIC_TIMEOUT		60000
#define  KINETIC_RETRY_INTERVAL	100
#define  KINETIC_HEARTBEAT_SIZE 1024
#define  KINETIC_IPV4_TAG "ipv4_addr"
#define  KINETIC_IPV6_TAG "ipv6_addr"
#define  KINETIC_IP_PORT 	"port"
#define  KINETIC_UUID_TAG "world_wide_name"

typedef struct uuid_entry {
		char	uuid[KINETIC_UUID_LENGTH];
		char	ip[INET6_ADDRSTRLEN ];
		uint16_t port;
}uuid_entry_t;

int kinetic_ipaddress2uuid(uuid_entry_t *entry);
static char  *get_tag_value(char *buf, const char *tag, char *val, int val_len)
{
	char *start = buf;
	int i;
	if((start = strcasestr(buf, tag)) != NULL) {
	while ( (*start != '"' || *start != ':' ) && (*start != '\0')) start++;
	if (*start == '\0')  return NULL;

	while ( (*start == '"' || *start == ':' ) && (*start != '\0')) start++;
	if (*start == '\0')   return NULL;

	memset(val, 0x00, val_len);
	i = 0;
	while(*start != '"' || *start != '\0') {
		if (i >= val_len) break;
			*val++ = *start++;
		}
		return start;
	}
	return NULL;
}
static bool uuid_matched(char *buf, uuid_entry_t *entry)
{
	char  uuid[KINETIC_UUID_LENGTH];
	/* get UUID */
	memset(uuid, 0x00, sizeof(uuid));
	if (get_tag_value(buf, KINETIC_UUID_TAG, uuid, sizeof(uuid)) == NULL)
		return false;
	if (strncasecmp(uuid, entry->uuid, sizeof(uuid)))
		return false;
	memset(entry->ip, 0x00, sizeof(entry->ip));
	 if (get_tag_value(buf, KINETIC_IPV4_TAG, entry->ip, sizeof(entry->ip)) != NULL)
		 return true;
	 if (get_tag_value(buf, KINETIC_IPV6_TAG, entry->ip, sizeof(entry->ip)) != NULL)
	 		 return true;
	 return false;
}

int kinetic_ipaddress2uuid(uuid_entry_t *entry)
{
	struct sockaddr_in addr;
	struct sockaddr from;
	int opt = 1;
	socklen_t from_len = (socklen_t)sizeof(from);
	int sock, wait = 0;
	char	buf[KINETIC_HEARTBEAT_SIZE];

	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		return -1;
	}
	memset(&addr, 0x00,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(KINETIC_HEARTBEAT_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if ((bind(sock, &addr, sizeof(addr)) < 0) ||
			(setsockopt(sock, SOL_SOCKET, SOCK_NONBLOCK,
			(char *)&opt, sizeof(opt)) < 0)) {
		return -1;
	}
	while (wait < KINETIC_TIMEOUT) {
		if (recvfrom(sock, buf, sizeof(buf), 0, &from, &from_len) < 0) {
			if (errno != EINTR && errno != EAGAIN)
				return -1;
		}
		else {
			 if(uuid_matched(buf, entry))
				 return 0;
		}
		usleep(KINETIC_RETRY_INTERVAL * 1000);
		wait += KINETIC_RETRY_INTERVAL;
	}
	return 0;
}


