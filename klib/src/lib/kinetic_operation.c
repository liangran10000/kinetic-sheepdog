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

#include "kinetic_operation.h"
#include "kinetic_connection.h"
#include "kinetic_message.h"
#include "kinetic_pdu.h"
#include "kinetic_allocator.h"
#include "kinetic_logger.h"
#include "kinetic_proto.h"
#include <stdlib.h>

static void KineticOperation_ValidateOperation(KineticOperation* operation)
{
    assert(operation != NULL);
    assert(operation->connection != NULL);
    assert(operation->request.proto != NULL);
    assert(operation->request.proto->command != NULL);
    assert(operation->request.proto->command->header != NULL);

}

KineticOperation *KineticOperation_Create(KineticConnection* const connection,
    				KineticProto_MessageType msg_type)
{
#ifdef DEBUG
    LOGF("\n"
         "--------------------------------------------------\n"
         "Building new operation on connection @ 0x%llX", connection);
#endif
    KineticOperation* operation = KineticAllocator_NewOperation(connection);


    if (operation == NULL) {
        LOG("Operation could not be allocated!"
            " Try reusing or freeing an Operation.");
        return NULL;
    }
    operation->connection = connection;
    KineticPDU_Init(&operation->request, connection);
	KineticPDU_InitWithMessage(&operation->request, connection, msg_type);
    operation->request.proto = &(operation->request.protoData.message.proto);
    KineticPDU_Init(&operation->response, connection);
    operation->msgType = msg_type;

    return operation;
}

KineticStatus KineticOperation_Free(KineticOperation* const operation)
{
	KineticAllocator_FreeOperation(operation, operation->connection);
    return KINETIC_STATUS_SUCCESS;
}

KineticStatus KineticOperation_GetStatus(KineticOperation* operation)
{
    KineticStatus status = KINETIC_STATUS_INVALID;

    if (operation != NULL) {
        status = KineticPDU_GetStatus(&operation->response);
    }
    return status;
}

void KineticOperation_BuildNoop(KineticOperation* const operation)
{
    KineticOperation_ValidateOperation(operation);
    operation->userData = NULL;
    operation->request.proto->command->header->messageType = KINETIC_PROTO_MESSAGE_TYPE_NOOP;
    operation->request.proto->command->header->has_messageType = true;
    operation->request.value = BYTE_BUFFER_NONE;
    operation->response.value = BYTE_BUFFER_NONE;
}

void KineticOperation_BuildPut(KineticOperation* const operation,
                               KineticEntry* const entry)
{
    KineticOperation_ValidateOperation(operation);
    operation->userData = entry;
    operation->request.proto->command->header->messageType = KINETIC_PROTO_MESSAGE_TYPE_PUT;
    operation->request.proto->command->header->has_messageType = true;
    operation->request.value = entry->value;
    operation->response.value = entry->value;

    /* why we are passing entry when entry is already assigned to operation? */
    KineticMessage_ConfigureKeyValue(&(operation->request.protoData.message), entry);
    operation->request.value.bytesUsed = entry->value.array.len;
   // operation->request->value = entry->value;
    operation->response.value = BYTE_BUFFER_NONE;
}

void KineticOperation_BuildGet(KineticOperation* const operation,
                               KineticEntry* const entry)
{
    KineticOperation_ValidateOperation(operation);
    operation->userData = entry;
    operation->request.proto->command->header->messageType = KINETIC_PROTO_MESSAGE_TYPE_GET;
    operation->request.proto->command->header->has_messageType = true;
    operation->request.value = entry->value;

    KineticMessage_ConfigureKeyValue(&(operation->request.protoData.message), entry);

    operation->request.value = BYTE_BUFFER_NONE;
    if (entry->metadataOnly)
    	operation->response.value = BYTE_BUFFER_NONE;
    else
    	operation->response.value = entry->value;
}

void KineticOperation_BuildDelete(KineticOperation* const operation,
                                  KineticEntry* const entry)
{
    KineticOperation_ValidateOperation(operation);
    operation->userData = entry;
    operation->request.proto->command->header->messageType = KINETIC_PROTO_MESSAGE_TYPE_DELETE;
    operation->request.proto->command->header->has_messageType = true;
    operation->request.value = entry->value;
    operation->response.value = entry->value;

    KineticMessage_ConfigureKeyValue(&(operation->request.protoData.message), entry);

    operation->request.value = BYTE_BUFFER_NONE;
    operation->response.value = BYTE_BUFFER_NONE;
}

void KineticOperation_BuildGetRange(KineticOperation* const operation,
                               KineticRange* const range)
{
    KineticOperation_ValidateOperation(operation);
    operation->userData = range;
    operation->request.proto->command->header->messageType = KINETIC_PROTO_MESSAGE_TYPE_GETKEYRANGE;
    operation->request.proto->command->header->has_messageType = true;
    //operation->request->value = range->value;
    //operation->response->value = range->value;
    KineticMessage_ConfigureKeyRange(&(operation->request.protoData.message), range);
    operation->request.value = BYTE_BUFFER_NONE;
    operation->response.value = BYTE_BUFFER_NONE;
    //operation->response->value = range->value;

}
