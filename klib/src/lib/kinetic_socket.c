/*
* kinetic-c
* Copyright (C) 2014 Seagate Technology.
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
*
*/
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif // _BSD_SOURCE
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif // _BSD_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "kinetic_socket.h"
#include "kinetic_logger.h"
#include "kinetic_types_internal.h"
#include "kinetic_proto.h"
#include "protobuf-c/protobuf-c.h"
#include "kinetic_pdu.h"


#define KINETIC_SEND_RETRY				(10 * 1000)
#define KINETIC_RCV_RETRY				(10 * 1000)
#define  KINETIC_HEARTBEAT_PORT 			8123
#define  KINETIC_UUID_LENGTH				19
#define  KINETIC_TIMEOUT				60000
#define  KINETIC_RETRY_INTERVAL				100
#define  KINETIC_HEARTBEAT_SIZE 			1024
#define  KINETIC_PORT_TAG 				"port"
#define  KINETIC_IPV4_TAG 				"ipv4_addr"
#define  KINETIC_IPV6_TAG 				"ipv6_addr"
#define  KINETIC_UUID_TAG 				"world_wide_name"
#define  KINETIC_DRIVE_TIMEOUT				60
#define  KINETIC_MULTICAST_GROUP			"239.1.2.3"

uint8_t										discard_buf[1024 * 1024];
ByteBuffer discard = {.array.data = discard_buf, .array.len = sizeof(discard_buf) };


int KineticSocket_Connect(const char* host, int port, bool nonBlocking)
{
	struct sockaddr_in addr;
	int rc, buf_size = (4096 *4096),
			fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0 ) {
		 LOGF("Error connecting to %s:%d error%s", host, port, strerror(errno));
		 return fd;
	}
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port	= INADDR_ANY;
	if ((rc = bind(fd, (const struct sockaddr *)&addr, sizeof(addr))) < 0){
		LOGF("Local Bind error for %s:%d error%s", host, port, strerror(errno));
		return rc;
	}

	addr.sin_port = htons(port);
	inet_aton(host, &(addr.sin_addr));
	if ((rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr))) < 0 ) {
		LOGF("Connect failed for %s:%d error%s", host, port, strerror(errno));
		return rc;
	}
	// ignore errors
	setsockopt(fd,SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
	setsockopt(fd,SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
	/*
	if (nonBlocking)
		if ((rc = fcntl(fd, F_SETFL, O_NONBLOCK)) < 0) {
		LOGF("non-blocking mode for %s:%d error%s", host, port, strerror(errno));
		close(fd);
			return rc;
	}
	*/
	return fd;
}

void KineticSocket_Close(int socket)
{
	close(socket);
}


static KineticStatus __KineticSocket_Read(int socket, ByteBuffer* dest, size_t len)
{
#ifdef DEBUG
    LOGF("Reading %zd bytes into buffer @ 0x%zX from fd=%d",
         len, (size_t)dest->array.data, socket);
#endif
    size_t bytesToReadIntoBuffer = len;
    if (dest->array.len < len) {
        bytesToReadIntoBuffer = dest->array.len;
    }
    while (dest->bytesUsed < bytesToReadIntoBuffer) {
    	int opStatus = read(socket, &dest->array.data[dest->bytesUsed],
                          dest->array.len - dest->bytesUsed);
            if (opStatus == -1 && ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK) )){
            	usleep(KINETIC_RCV_RETRY);
                continue;
            }
            else if (opStatus <= 0) {
#				ifdef DEBUG
                LOGF("Failed to read from socket! status=%d, errno=%d, desc='%s'",
                     opStatus, errno, strerror(errno));
#				endif
                return KINETIC_STATUS_SOCKET_ERROR;
            }
            else {
                dest->bytesUsed += opStatus;
#				ifdef DEBUG
                LOGF("Received %d bytes (%zd of %zd)", opStatus, dest->bytesUsed, len);
#				endif
            }
    }

#ifdef DEBUG
    LOGF("Received %zd of %zd bytes requested", dest->bytesUsed, len);
#endif
    return KINETIC_STATUS_SUCCESS;
}
KineticStatus KineticSocket_Read(int socket, ByteBuffer* dest, size_t len)
{
	KineticStatus status = __KineticSocket_Read(socket,  dest, len);
	// Flush any remaining data, in case of a truncated read w/short dest buffer
	 if (status == KINETIC_STATUS_SUCCESS && dest->bytesUsed < len) {
		 size_t remaining = len - dest->bytesUsed;
		 assert(remaining <= sizeof(discard_buf));
		 discard.bytesUsed = 0;
		 if ((status = __KineticSocket_Read(socket,  &discard, remaining)) ==
				 KINETIC_STATUS_SUCCESS)
			 status = KINETIC_STATUS_BUFFER_OVERRUN;
	 }
	 return status;
}

KineticStatus KineticSocket_ReadProtobuf(int socket, KineticPDU* pdu)
{
    size_t bytesToRead = pdu->header.protobufLength;
#ifdef DEBUG
    LOGF("Reading %zd bytes of protobuf", bytesToRead);
#endif
    ByteBuffer recvBuffer = ByteBuffer_Create(pdu->protobufRaw, bytesToRead);
    KineticStatus status = KineticSocket_Read(socket, &recvBuffer, bytesToRead);

    if (status != KINETIC_STATUS_SUCCESS) {
        LOG("Protobuf read failed!");
        return status;
    }
#ifdef DEBUG
    LOG("Read packed protobuf successfully!");
#endif
    pdu->proto =
        KineticProto__unpack(NULL, recvBuffer.bytesUsed, recvBuffer.array.data);
    if (pdu->proto == NULL) {
        pdu->protobufDynamicallyExtracted = false;
        LOG("Error unpacking incoming Kinetic protobuf message!");
        return KINETIC_STATUS_DATA_ERROR;
    }
    else {
        pdu->protobufDynamicallyExtracted = true;
#ifdef DEBUG
        LOG("Protobuf unpacked successfully!");
#endif
        return KINETIC_STATUS_SUCCESS;
    }
}

KineticStatus KineticSocket_Write(int socket, ByteBuffer* src)
{
#ifdef DEBUG
    LOGF("Writing %zu bytes to socket...", src->bytesUsed);
#endif
    for (unsigned int bytesSent = 0; bytesSent < src->bytesUsed;) {
        int bytesRemaining = src->bytesUsed - bytesSent;
        int status = write(socket, &src->array.data[bytesSent], bytesRemaining);
        if (status == -1 &&
            ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))) {
            LOG("Write interrupted. retrying...");
            usleep(KINETIC_SEND_RETRY);
            continue;
        }
        else if (status <= 0) {
            LOGF("Failed to write to socket! status=%d, errno=%s\n", status, strerror(errno));
            return KINETIC_STATUS_SOCKET_ERROR;
        }
        else {
            bytesSent += status;
#ifdef DEBUG
            LOGF("Wrote %d bytes (%d of %zu sent)", status, bytesSent, src->bytesUsed);
#endif
        }
    }
#ifdef DEBUG
    LOG("Socket write completed successfully");
#endif
    return KINETIC_STATUS_SUCCESS;
}

KineticStatus KineticSocket_WriteProtobuf(int socket, KineticPDU* pdu)
{
    assert(pdu != NULL);
#ifdef DEBUG
    LOGF("Writing protobuf (%zd bytes)...", pdu->header.protobufLength);
#endif
    size_t len = KineticProto__pack(&pdu->protoData.message.proto,
                                    pdu->protobufRaw);
    assert(len == pdu->header.protobufLength);

    ByteBuffer buffer = ByteBuffer_Create(pdu->protobufRaw, len);
    buffer.bytesUsed = len;

    return KineticSocket_Write(socket, &buffer);
}
int 	Kinetic_MaskSignals()
{
	sigset_t set;
	sigemptyset(&set);
	//sigaddset(&set, SIGUSR1);
	sigfillset(&set);
	return pthread_sigmask(SIG_BLOCK, &set, NULL);
}
void * rcv_thread(void *arg)
{
	KineticConnection *connection = arg;
	struct epoll_event events;
	int count;
	Kinetic_MaskSignals();
	for (;;) { 
		if ((count = epoll_wait(connection->rcv_epoll, &events, 1, -1)) <= 0) {
#ifdef DEBUG
				LOGF("rcv thread wakeup with no event %d %s", count, strerror(errno));
#endif
				continue;
		}
		KineticPDU_Receive(connection);
	}
}
void * send_thread(void *arg)
{
	KineticConnection *connection = arg;
	struct epoll_event events[EPOLL_EVENT_MAX];
	KineticOperation *op;
	uint64_t val;
	int i, count;
	Kinetic_MaskSignals();
		for (;;) {
			if ((count = epoll_wait(connection->send_epoll, events, 2, -1)) <= 0) {
#ifdef			DEBUG
				LOGF("send thread wakeup with no event %d %s", count, strerror(errno));
#endif
				continue;
			}
#ifdef DEBUG
			LOGF("send thread wakeup with  event count ==%d", count);
#endif
			assert (count >= 0 && count <= EPOLL_EVENT_MAX);
			for (i = 0; i < count; i++){
				if (events[i].data.fd == connection->send_fd)
					read(connection->send_fd, &val, sizeof(val));
			}
			for (;;) {
				pthread_mutex_lock(&connection->pending_op_mutex);
				if(!kinetic_list_empty(&connection->pending_op_list)) {
					op = kinetic_list_first_entry(&connection->pending_op_list,
						KineticOperation, list);
					assert(op);
					kinetic_list_del(&op->list);
					pthread_mutex_unlock(&connection->pending_op_mutex);
					pthread_mutex_lock(&connection->inprogress_op_mutex);
					kinetic_list_add_tail(&op->list, &connection->inprogress_op_list);
					pthread_mutex_unlock(&connection->inprogress_op_mutex);
					KineticStatus Status = KineticPDU_Send(&op->request);
					assert(Status == KINETIC_STATUS_SUCCESS);
				}
				else {
					pthread_mutex_unlock(&connection->pending_op_mutex);
					break;
				}
			}

		}
}
static const char  *get_tag_value(char *buf, const char *tag, char *val, int val_len)
{
	const char *start;
	int i;
	if((start = strcasestr(buf, tag)) != NULL) {
		start += strlen(tag);
		while  (*start == '"' || *start == ':' || *start == '\\')  start++;
		if (*start == '\0')  return NULL;
		memset(val, 0x00, val_len);
		i = 0;
		while(*start != '"' && *start != '\0' && *start != ',') {
			if (i++ >= val_len) break;
			*val++ = *start++;
		}
	}
	return start;
}

typedef struct  _KineticHeartbeatEntry{
		struct kinetic_list_node 	list;
		Heartbeat 					hb;
		int							hits;
}KineticHeartbeatEntry;

static struct kinetic_list_head HeartbeatList;

static void RescanKineticDrives(KineticHeartbeatCallback callback)
{
KineticHeartbeatEntry *ent;
		kinetic_list_for_each_entry(ent, &HeartbeatList, list) {
			if (ent->hits == 0) {
					ent->hb.status = DRIVE_REMOVED;
					callback(&ent->hb);
					kinetic_list_del(&ent->list);
			}
			ent->hits = 0;
		}

}
static bool	SameHeartbeat(Heartbeat *hb1, Heartbeat *hb2)
{
		int i, j;
		for (i = 0; i < KINETIC_DRIVE_ADDRESSES; i++) {
			for (j = 0; j < KINETIC_DRIVE_ADDRESSES; j++) {
				if (!strncasecmp(hb1->addr[i].ipaddr, hb2->addr[j].ipaddr, sizeof(hb2->addr[j].ipaddr)) &&
						hb1->addr[i].port == hb2->addr[j].port) {
						return true;
				}
			}
		}
		return false;
}
static bool NewKineticDrive(Heartbeat *hb)
{
	bool new = true;
	KineticHeartbeatEntry *ent;
	kinetic_list_for_each_entry(ent, &HeartbeatList, list) {
		if (SameHeartbeat(hb, &ent->hb)) {
				ent->hits++;
				new = false;
				break;
		}
	}
	if (new) {
		ent = malloc(sizeof(*ent));
		memset(ent, 0x00, sizeof(*ent));
		if (ent != NULL) {
			ent->hits = 1;
			ent->hb.status = DRIVE_ADDED;
			memcpy(&ent->hb, hb, sizeof(*hb));
			kinetic_list_add(&ent->list, &HeartbeatList);
		}
		else {
				new = false;
		}
	}
	return new;

}
static void * heartbeat_thread(void *arg)
{
	struct epoll_event event;
	struct sockaddr_in addr;
	struct sockaddr from;
	int sock, len, opt = 1;
	socklen_t from_len = (socklen_t)sizeof(from);
	int epollfd =  epoll_create(2);
	int count, i;
	struct timeval start, end;
	struct ifaddrs *ifaddr, *ifa;
	struct ip_mreq group;
	Heartbeat hb;
	char	port[16];
	char	buf[KINETIC_HEARTBEAT_SIZE], *ptag;
	KineticHeartbeatCallback callback = arg;
	Kinetic_MaskSignals();
	init_kinetic_list_head(&HeartbeatList);
	printf("\nstubbed starting heart beat thread");
	if (epollfd <= 0) {
		LOGF("failed to create epoll for heartbeat socket  %s",  strerror(errno));
	}
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		LOGF("failed to create heartbeat listen socket  %s",  strerror(errno));
		return NULL;
	}
	
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0) {
		LOGF("failed to setsockopt reuseaddr heartbeat socket error  %s",  strerror(errno));
		goto hb_thread_exit;
	}
	
	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char *)&opt, sizeof(opt)) < 0) {
		LOGF("failed to setsockopt broadcast heartbeat socket error  %s",  strerror(errno));
		goto hb_thread_exit;
	}
	memset(&addr, 0x00,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(KINETIC_HEARTBEAT_PORT);
	if (bind(sock, (const struct sockaddr *)&addr, sizeof(addr)) < 0) { 
		LOGF("failed to bind heartbeat listen socket  %s",  strerror(errno));
		goto hb_thread_exit;
	}
    if (getifaddrs(&ifaddr) < 0) {
		LOGF("failed to obtain ifaddres  %s",  strerror(errno));
		goto hb_thread_exit;
	}
	for (ifa = ifaddr; (ifa != NULL); ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) continue;
		if (ifa->ifa_addr->sa_family != AF_INET)  {
			LOGF("skipping %s into group", inet_ntoa(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr));
			continue;
		}
		memset(&group, 0x00, sizeof(group));
		group.imr_interface.s_addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
		group.imr_multiaddr.s_addr = inet_addr(KINETIC_MULTICAST_GROUP);
		LOGF("Adding %s into group", inet_ntoa(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr));

		if(setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group)) < 0) {
			LOGF("setsockopt failed for group membership %s", strerror(errno));
			goto hb_thread_exit;
		}
	}
/*	
	if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
		LOGF("failed to set non-blocking mode for  heartbeat socket:%s",  strerror(errno));
		close(sock);
		return NULL;
	}
*/	
	event.events = EPOLLIN | EPOLLERR | EPOLLRDHUP;
	event.data.fd = sock;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock, &event) < 0) {
			LOGF("heartbeat thread  unable to add epoll event %s",  strerror(errno));
			goto hb_thread_exit;
	}
	gettimeofday(&start, NULL);
	LOGF("\nStarting Heartbeat Thread at %d epoll:%d socket:%d\n", 
		KINETIC_HEARTBEAT_PORT, epollfd, sock);
	for(;;) {
		gettimeofday(&end, NULL);
		if (end.tv_sec > KINETIC_DRIVE_TIMEOUT + start.tv_sec) {
			RescanKineticDrives(callback);
			gettimeofday(&start, NULL);
		}
		if ((count = epoll_wait(epollfd, &event, 1, KINETIC_TIMEOUT)) <= 0) {
				continue;
		}
		assert(event.data.fd == sock); 
		if ((len = recvfrom(sock, buf, sizeof(buf), 0, &from, &from_len)) < 0) {
				LOGF("heartbeat thread receive error %d %s",  errno, strerror(errno));
				continue;
		}
		if (len >= (int)sizeof(buf)) {
			LOGF("heartbeat length %d  is invalid... ignoring heartbeat",  len);
				continue;
		}
		buf[len] = '\0'; // NULL terminate string
		memset(&hb, 0x00, sizeof(hb));
		ptag = buf;
		for (i = 0; i < KINETIC_DRIVE_ADDRESSES; i++) {
	 		ptag = get_tag_value(ptag, KINETIC_IPV4_TAG, hb.addr[i].ipaddr, sizeof(hb.addr[i].ipaddr));
			if (ptag == NULL) break;
	 	//	ptag = get_tag_value(ptag, KINETIC_PORT_TAG, port, sizeof(port));
		//	if (ptag == NULL) break;
			hb.addr[i].port = KINETIC_PORT;
		}
		if (ptag && NewKineticDrive(&hb)) {
				hb.status = DRIVE_ADDED; 
				callback(&hb);
		}
	}
hb_thread_exit:
	close(sock);
	return NULL;
}
KineticStatus Heartbeat_Init(KineticHeartbeatCallback callback)
{
		pthread_t th;
	pthread_create(&th, NULL, heartbeat_thread, (void *)callback);
    return KINETIC_STATUS_SUCCESS;
}
