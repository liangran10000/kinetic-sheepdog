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

#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include "kinetic_connection.h"
#include "kinetic_types_internal.h"
#include "kinetic_socket.h"
#include "kinetic_logger.h"
#include "kinetic_list.h"

STATIC pthread_mutex_t Connection_mutex;
STATIC KineticConnection ConnectionInstances[KINETIC_SESSIONS_MAX];
STATIC KineticConnection* Connections[KINETIC_SESSIONS_MAX];


KineticSessionHandle KineticConnection_NewConnection(
    const KineticSession* const config)
{
    KineticSessionHandle handle = KINETIC_HANDLE_INVALID;
    if (config == NULL) {
        return KINETIC_HANDLE_INVALID;
    }
	pthread_mutex_lock(&Connection_mutex);
    for (int idx = 0; idx < KINETIC_SESSIONS_MAX; idx++) {
        if (Connections[idx] == NULL) {
            KineticConnection* connection = &ConnectionInstances[idx];
            Connections[idx] = connection;
            //KineticCnnection_Init(connection);
            connection->connected = false;
            connection->socket = -1;
            connection->connectionID = time(NULL);
            connection->sequence = 1;
            connection->session = *config;
            init_kinetic_list_head(&connection->free_op_list);
            init_kinetic_list_head(&connection->pending_op_list);
            init_kinetic_list_head(&connection->inprogress_op_list);
            handle = (KineticSessionHandle)(idx + 1);
            break;
        }
    }
	pthread_mutex_unlock(&Connection_mutex);
    return handle;
}

void KineticConnection_FreeConnection(KineticSessionHandle* const handle)
{
    assert(handle != NULL);
    assert(*handle != KINETIC_HANDLE_INVALID);

	pthread_mutex_lock(&Connection_mutex);
    KineticConnection* connection = KineticConnection_FromHandle(*handle);
    assert(connection != NULL);
    *connection = (KineticConnection) {
        .connected = false
    };
    Connections[(int)*handle - 1] = NULL;
	pthread_mutex_unlock(&Connection_mutex);
}

KineticConnection* KineticConnection_FromHandle(KineticSessionHandle handle)
{
    assert(handle > KINETIC_HANDLE_INVALID);
    assert(handle <= KINETIC_SESSIONS_MAX);
    return Connections[(int)handle - 1];
}

void	Kinetic_Validate_Connection(KineticConnection *connection)
{
    assert(connection->socket);
    assert(connection->connected);
    assert(connection->send_epoll);
    assert(connection->rcv_epoll);
    assert(connection->send_fd);
	assert(connection->rawPDU);
	assert(connection->rawPDU);
    assert(connection->send_thread);
    assert(connection->rcv_thread);
}

KineticStatus KineticConnection_Connect(KineticConnection* const connection)
{
	struct epoll_event event;
    if (connection == NULL) {
        return KINETIC_STATUS_SESSION_EMPTY;
    }
    connection->connected = false;
	if (pthread_mutex_init(&connection->mutex, NULL)) {
			LOG("failed to initialize mutex");
			return KINETIC_STATUS_INTERNAL_ERROR;
	}
	//KineticConnection_Lock(connection);
    connection->socket = KineticSocket_Connect(
                             connection->session.host,
                             connection->session.port,
                             connection->session.nonBlocking);
    connection->connected = (connection->socket >= 0);
    if (!connection->connected) {
        LOG("Session connection failed!");
        connection->socket = KINETIC_SOCKET_DESCRIPTOR_INVALID;
        return KINETIC_STATUS_CONNECTION_ERROR;
    }
    /* create epoll events */
    connection->send_epoll = epoll_create(2);
    connection->rcv_epoll  = epoll_create(2);
    connection->send_fd = eventfd(0, EFD_NONBLOCK);
    /* add data in event */
    event.events = EPOLLIN;
    event.data.fd = connection->socket;
    epoll_ctl(connection->rcv_epoll, EPOLL_CTL_ADD, connection->socket,
    		&event);
    /* add data out and wakeup event 
    event.events = EPOLLOUT;
    epoll_ctl(connection->send_epoll, EPOLL_CTL_ADD, connection->socket,
        		&event);
	*/
    event.events = EPOLLIN;
    event.data.fd = connection->send_fd;
    epoll_ctl(connection->send_epoll, EPOLL_CTL_ADD, connection->send_fd,
            		&event);
	connection->rawPDU = malloc(sizeof(*connection->rawPDU));
	assert(connection->rawPDU);
    pthread_mutex_init(&connection->pending_op_mutex, NULL);
	pthread_mutex_init(&connection->inprogress_op_mutex, NULL);
	pthread_mutex_init(&connection->mutex, NULL);
    pthread_create(&connection->send_thread, NULL, send_thread, connection);
    pthread_create(&connection->rcv_thread, NULL,  rcv_thread, connection);
	//KineticConnection_Unlock(connection);
	Kinetic_Validate_Connection(connection);

    return KINETIC_STATUS_SUCCESS;
}

KineticStatus KineticConnection_Disconnect(KineticConnection* const connection)
{
    if (connection == NULL || connection->socket < 0) {
        return KINETIC_STATUS_SESSION_INVALID;
    }
	if (connection->socket != KINETIC_HANDLE_INVALID) {
    	close(connection->socket);
    	connection->socket = KINETIC_HANDLE_INVALID;
	}
	if (connection->send_thread)
    	pthread_cancel(connection->send_thread);
	if (connection->rcv_thread)
    	pthread_cancel(connection->rcv_thread);
	if (connection->send_fd)
    	close(connection->send_fd);
	if(connection->send_epoll)
    	close(connection->send_epoll);
    if(connection->rcv_epoll)
    	close(connection->rcv_epoll);
   	pthread_mutex_destroy(&connection->pending_op_mutex);
   	pthread_mutex_destroy(&connection->inprogress_op_mutex);
   	pthread_mutex_destroy(&connection->mutex);
	connection->send_thread = 0;
	connection->rcv_thread = 0;
	connection->send_fd = 0;
	connection->send_epoll = 0;
	connection->rcv_epoll = 0;
   	connection->socket = KINETIC_HANDLE_INVALID;
	if (connection->rawPDU) {
		free(connection->rawPDU);
		connection->rawPDU = NULL;
	}
    return KINETIC_STATUS_SUCCESS;
}

int64_t KineticConnection_GetNextSequence(KineticConnection* const connection)
{
	return __sync_add_and_fetch(&connection->sequence, 1);
	/*
	int64_t ret;
    assert(connection != NULL);
	KineticConnection_Lock(connection);
    ret = connection->sequence++;
	KineticConnection_Unlock(connection);
	return ret;
	*/
}
void KineticConnection_Init()
{
		memset(ConnectionInstances, 0x00, sizeof(ConnectionInstances));
		memset(Connections, 0x00, sizeof(Connections));
		pthread_mutex_init(&Connection_mutex, NULL);
		
}
void KineticConnection_DeInit()
{
		pthread_mutex_destroy(&Connection_mutex);

}
void KineticConnection_Lock(KineticConnection*  const connection)
{

	pthread_mutex_lock(&connection->mutex);
}
void KineticConnection_Unlock(KineticConnection*  const connection)
{
	pthread_mutex_unlock(&connection->mutex);
}
