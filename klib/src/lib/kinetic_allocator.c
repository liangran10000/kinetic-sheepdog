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

#include <stdlib.h>
#include "kinetic_allocator.h"
#include "kinetic_logger.h"
#include "kinetic_connection.h"

KineticOperation* KineticAllocator_NewOperation(KineticConnection *connection)
{
	KineticOperation *op;
	KineticConnection_Lock(connection);
	if (!kinetic_list_empty(&connection->free_op_list)) {
		op = (KineticOperation *)(connection->free_op_list.n.next);
		kinetic_list_del(&op->list);
	}
	else {
		op = malloc(sizeof(*op));
		pthread_cond_init(&op->callback_cond, NULL);
		pthread_mutex_init(&op->callback_mutex, NULL);
	}
	assert(op);
	op->response.proto = op->request.proto = NULL;
	KineticConnection_Unlock(connection);
	return op;

}
static void Kinetic_FreeProto(KineticPDU *pdu)
{
	if ((pdu->proto != NULL) && pdu->protobufDynamicallyExtracted) {
	        LOG("Freeing dynamically allocated protobuf");
	        KineticProto__free_unpacked(pdu->proto, NULL);
	    };
}

void KineticAllocator_FreeOperation(KineticOperation* op, KineticConnection *connection)
{
	assert(op);
    Kinetic_FreeProto(&op->request);
    Kinetic_FreeProto(&op->response);
	KineticConnection_Lock(connection);
	//kinetic_list_del( &op->list);
	kinetic_list_add(&op->list, &connection->free_op_list);
	KineticConnection_Unlock(connection);

}

void KineticAllocator_FreeAllOperations(KineticConnection *connection)
{
	KineticOperation *op;
	KineticConnection_Lock(connection);
	while (!kinetic_list_empty(&connection->free_op_list)) {
		op = (KineticOperation *)(connection->free_op_list.n.next);
		Kinetic_FreeProto(&op->request);
		Kinetic_FreeProto(&op->response);
	  	kinetic_list_del(&op->list);
	  	pthread_mutex_destroy(&op->callback_mutex);
	  	pthread_cond_destroy(&op->callback_cond);
		free(op);
	}
	KineticConnection_Unlock(connection);
}

bool KineticAllocator_ValidateAllMemoryFreed(KineticConnection *connection)
{
	bool rc;
	KineticConnection_Lock(connection);
    if (kinetic_list_empty(&connection->inprogress_op_list) &&
    	kinetic_list_empty(&connection->free_op_list) &&
    	kinetic_list_empty(&connection->pending_op_list))
    	rc = true;
    else rc = false;
	KineticConnection_Unlock(connection);
	return rc;
}
