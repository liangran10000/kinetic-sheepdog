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

#include "kinetic_connection.h"
#include "kinetic_types_internal.h"
#include "kinetic_socket.h"
#include "kinetic_logger.h"
#include "kinetic_list.h"
#include <string.h>
#include <stdlib.h>

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
            KINETIC_CONNECTION_INIT(connection);
            connection->session = *config;
			init_kinetic_list_head(&connection->pdus);
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

KineticStatus KineticConnection_Connect(KineticConnection* const connection)
{
    if (connection == NULL) {
        return KINETIC_STATUS_SESSION_EMPTY;
    }
	KineticConnection_Lock(connection);
    connection->connected = false;
    connection->socket = KineticSocket_Connect(
                             connection->session.host,
                             connection->session.port,
                             connection->session.nonBlocking);
    connection->connected = (connection->socket >= 0);
	KineticConnection_Unlock(connection);

    if (!connection->connected) {
        LOG("Session connection failed!");
        connection->socket = KINETIC_SOCKET_DESCRIPTOR_INVALID;
        return KINETIC_STATUS_CONNECTION_ERROR;
    }

    return KINETIC_STATUS_SUCCESS;
}

KineticStatus KineticConnection_Disconnect(KineticConnection* const connection)
{
    if (connection == NULL || connection->socket < 0) {
        return KINETIC_STATUS_SESSION_INVALID;
    }

	KineticConnection_Lock(connection);
    close(connection->socket);
    connection->socket = KINETIC_HANDLE_INVALID;
	KineticConnection_Unlock(connection);
    return KINETIC_STATUS_SUCCESS;
}

void KineticConnection_IncrementSequence(KineticConnection* const connection)
{
    assert(connection != NULL);
	KineticConnection_Lock(connection);
    connection->sequence++;
	KineticConnection_Unlock(connection);
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
