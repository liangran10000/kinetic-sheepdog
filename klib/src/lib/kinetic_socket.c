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
#define _BSD_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "kinetic_socket.h"
#include "kinetic_logger.h"
#include "kinetic_types_internal.h"
#include "kinetic_proto.h"
#include "protobuf-c/protobuf-c.h"
#include "kinetic_pdu.h"

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif // _BSD_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#define KINETIC_SEND_RETRY	(10 * 1000)
#define KINETIC_RCV_RETRY	(10 * 1000)
uint8_t		discard_buf[1024 * 1024];
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
	if ((rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr))) < 0){
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
	if (nonBlocking)
		if ((rc = fcntl(fd, F_SETFL, O_NONBLOCK)) < 0) {
			LOGF("non-blocking mode for %s:%d error%s", host, port, strerror(errno));
			close(fd);
			return rc;
		}
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

void * rcv_thread(void *arg)
{
	KineticConnection *connection = arg;
	struct epoll_event events;
	int count;
	for (;;) { 
		if ((count = epoll_wait(connection->rcv_epoll, &events, 1, -1)) <= 0) {
				LOGF("rcv thread wakeup with no event %d %s", count, strerror(errno));
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

		for (;;) {
			if ((count = epoll_wait(connection->send_epoll, events, 2, -1)) <= 0) {
				LOGF("send thread wakeup with no event %d %s", count, strerror(errno));
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
