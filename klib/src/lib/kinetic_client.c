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

#include "kinetic_client.h"
#include "kinetic_types_internal.h"
#include "kinetic_pdu.h"
#include "kinetic_operation.h"
#include "kinetic_connection.h"
#include "kinetic_message.h"
#include "kinetic_pdu.h"
#include "kinetic_logger.h"
#include "kinetic_allocator.h"
#include <stdlib.h>

static KineticOperation * KineticClient_CreateOperation(
    KineticSessionHandle handle, KineticProto_MessageType msg_type)
{
    if (handle == KINETIC_HANDLE_INVALID) {
        LOG("Specified session has invalid handle value");
        return NULL;
    }
    KineticConnection* connection = KineticConnection_FromHandle(handle);
    if (connection == NULL) {
        LOG("Specified session is not associated with a connection");
        return NULL;
    }
    return ( KineticOperation_Create(connection, msg_type));

}

static KineticStatus KineticClient_ExecuteOperation(KineticOperation* operation)
{
	int64_t	val = 1; 
#ifdef DEBUG
    LOGF("Executing operation: 0x%llX", operation);
    if ( (operation->request.value.array.data != NULL) &&
         (operation->request.value.bytesUsed > 0)) {
        LOG("  Sending PDU w/value:");
    }
    else {
        LOG("  Sending PDU w/o value");
    }
#endif
    /* add into the pending list and signal */
    pthread_mutex_lock(&operation->connection->pending_op_mutex);
    kinetic_list_add_tail(&operation->list, &operation->connection->pending_op_list);
    pthread_mutex_unlock(&operation->connection->pending_op_mutex);
    write(operation->connection->send_fd, &val, sizeof(val));

    return KINETIC_STATUS_PENDING;


}

KineticStatus KineticClient_Connect(const KineticSession* config,
                                    KineticSessionHandle* handle)
{
    if (handle == NULL) {
        LOG("Session handle is NULL!");
        return KINETIC_STATUS_SESSION_EMPTY;
    }
    *handle = KINETIC_HANDLE_INVALID;

    if (config == NULL) {
        LOG("KineticSession is NULL!");
        return KINETIC_STATUS_SESSION_EMPTY;
    }

    if (strlen(config->host) == 0) {
        LOG("Host is empty!");
        return KINETIC_STATUS_HOST_EMPTY;
    }

    if (config->hmacKey.len < 1 || config->hmacKey.data == NULL) {
        LOG("HMAC key is NULL or empty!");
        return KINETIC_STATUS_HMAC_EMPTY;
    }

    *handle = KineticConnection_NewConnection(config);
    if (handle == KINETIC_HANDLE_INVALID) {
        LOG("Failed connecting to device!");
        return KINETIC_STATUS_SESSION_INVALID;
    }

    KineticConnection* connection = KineticConnection_FromHandle(*handle);
    if (connection == NULL) {
        LOG("Failed getting valid connection from handle!");
        return KINETIC_STATUS_CONNECTION_ERROR;
    }

    KineticStatus status = KineticConnection_Connect(connection);
    if (status != KINETIC_STATUS_SUCCESS) {
        LOGF("Failed creating connection to %s:%d", config->host, config->port);
        KineticConnection_FreeConnection(handle);
        *handle = KINETIC_HANDLE_INVALID;
        return status;
    }

    return KINETIC_STATUS_SUCCESS;
}

KineticStatus KineticClient_Disconnect(KineticSessionHandle* const handle)
{
    if (*handle == KINETIC_HANDLE_INVALID) {
        LOG("Invalid KineticSessionHandle specified!");
        return KINETIC_STATUS_SESSION_INVALID;
    }

    KineticConnection* connection = KineticConnection_FromHandle(*handle);
    if (connection == NULL) {
        LOG("Failed getting valid connection from handle!");
        return KINETIC_STATUS_CONNECTION_ERROR;
    }

    KineticStatus status = KineticConnection_Disconnect(connection);
    if (status != KINETIC_STATUS_SUCCESS) {
        LOG("Disconnection failed!");
    }

    KineticAllocator_FreeAllOperations(connection);
    KineticConnection_FreeConnection(handle);
    *handle = KINETIC_HANDLE_INVALID;

    return status;
}
void    KineticClient_InternalWait(KineticOperation * operation)
{
		pthread_mutex_lock(&operation->callback_mutex);
	    pthread_cond_wait(&operation->callback_cond, &operation->callback_mutex);
}
void    KineticClient_InternalCallback(KineticStatus status, void *ref)
{
	KineticOperation *operation = ref;
	pthread_cond_signal(&operation->callback_cond);
	operation->status = status;
}
KineticStatus KineticClient_NoOp(KineticSessionHandle handle)
{
    KineticStatus status;
    KineticOperation *operation;
    if ((operation = KineticClient_CreateOperation( handle,  KINETIC_PROTO_MESSAGE_TYPE_NOOP))
    		== NULL)
    	return  KINETIC_STATUS_NO_PDUS_AVAVILABLE;
    KineticOperation_BuildNoop(operation);
    operation->callback_internal = KineticClient_InternalCallback;

    if ((status = KineticClient_ExecuteOperation(operation)) == KINETIC_STATUS_PENDING) {
        	KineticClient_InternalWait(operation);
        	status = operation->status;
    }
    KineticOperation_Free(operation);
    return status;
}

KineticStatus KineticClient_Put(KineticSessionHandle handle,
                                KineticEntry* const entry)
{
    KineticStatus status;
    KineticOperation *operation;

    if ((operation = KineticClient_CreateOperation( handle,
			 KINETIC_PROTO_MESSAGE_TYPE_PUT)) == NULL)
    	return  KINETIC_STATUS_NO_PDUS_AVAVILABLE;

    KineticOperation_BuildPut(operation, entry);
    operation->callback_internal = KineticClient_InternalCallback;

    if ((status = KineticClient_ExecuteOperation(operation)) == KINETIC_STATUS_PENDING) {
        	KineticClient_InternalWait(operation);
        	status = operation->status;
    }
    if (status == KINETIC_STATUS_SUCCESS) {
        if (entry->newVersion.array.data != NULL && entry->newVersion.array.len > 0) {
            entry->dbVersion = entry->newVersion;
            entry->newVersion = BYTE_BUFFER_NONE;
        }
    }
    KineticOperation_Free(operation);
    return status;
}

KineticStatus KineticClient_Get(KineticSessionHandle handle,
                                KineticEntry* const entry)
{
    assert(entry != NULL);
    if (!entry->metadataOnly) {
        assert(entry->value.array.data != NULL);
    }
    KineticStatus status;
    KineticOperation *operation;
    if ((operation = KineticClient_CreateOperation( handle,
			 KINETIC_PROTO_MESSAGE_TYPE_GET)) == NULL)
		return  KINETIC_STATUS_NO_PDUS_AVAVILABLE;
    KineticOperation_BuildGet(operation, entry);
    operation->callback_internal = KineticClient_InternalCallback;
    if ((status = KineticClient_ExecuteOperation(operation)) == KINETIC_STATUS_PENDING) {
    	KineticClient_InternalWait(operation);
    	status = operation->status;
	}
    if (status == KINETIC_STATUS_SUCCESS) {
        KineticProto_KeyValue* keyValue = KineticPDU_GetKeyValue(&operation->response);
        if (keyValue != NULL) {
            if (!Copy_KineticProto_KeyValue_to_KineticEntry(keyValue, entry)) {
                status = KINETIC_STATUS_BUFFER_OVERRUN;
            }
        }
    }

    KineticOperation_Free(operation);

    return status;
}

KineticStatus KineticClient_Delete(KineticSessionHandle handle,
                                   KineticEntry* const entry)
{
    KineticStatus status;
    KineticOperation *operation;

    if ((operation = KineticClient_CreateOperation(handle,
			 KINETIC_PROTO_MESSAGE_TYPE_GET)) == NULL)
    	return  KINETIC_STATUS_NO_PDUS_AVAVILABLE;
    KineticOperation_BuildDelete(operation, entry);
    operation->callback_internal = KineticClient_InternalCallback;

    if ((status = KineticClient_ExecuteOperation(operation)) == KINETIC_STATUS_PENDING) {
        	KineticClient_InternalWait(operation);
        	status = operation->status;
    }
    KineticOperation_Free(operation);
    return status;
}

KineticStatus KineticClient_Init(const char *logFile, int logLevel)
{
	KineticConnection_Init();
	return KineticLogger_Init(logFile, logLevel);
}
KineticStatus KineticClient_DeInit()
{
	/*FIXME terminate all connections */
	KineticConnection_DeInit();
	return KINETIC_STATUS_SUCCESS;
}

KineticStatus KineticClient_GetRange(KineticSessionHandle handle,
                                KineticRange *range)
{
    assert(range != NULL );
    KineticStatus status;
    KineticOperation *operation;
    if ((operation = KineticClient_CreateOperation(handle,
			 KINETIC_PROTO_MESSAGE_TYPE_GETKEYRANGE)) == NULL)
    return  KINETIC_STATUS_NO_PDUS_AVAVILABLE;
    KineticOperation_BuildGetRange(operation, range);
    if ((status = KineticClient_ExecuteOperation(operation)) == KINETIC_STATUS_PENDING) {
        	KineticClient_InternalWait(operation);
        	status = operation->status;
    }
    if (status == KINETIC_STATUS_SUCCESS) {
        status  = KineticPDU_GetKeyRange(&operation->response, range);
    }
    KineticOperation_Free(operation);
    return status;
}

