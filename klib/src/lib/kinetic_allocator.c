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

#include "kinetic_allocator.h"
#include "kinetic_logger.h"
#include <stdlib.h>
#include "kinetic_connection.h"
STATIC LIST_HEAD (PDUList); //= {.start = NULL, .last = NULL};
#define PDU2LIST(pdu) ( ((uint8_t *)(pdu)) - sizeof( struct list_node))

KineticPDU* KineticAllocator_NewPDU(KineticConnection *connection)
{
   KineticPDUItem * item = malloc(sizeof(KineticPDUItem));
   assert(item);
   item->PDU.proto = NULL;
	KineticConnection_Lock(connection);
   list_add(&item->list, &PDUList);
   KineticConnection_Unlock(connection);
   return &item->PDU;

}

void KineticAllocator_FreePDU(KineticPDU* pdu, KineticConnection *connection)
{
	assert(pdu);
    if ((pdu->proto != NULL) && pdu->protobufDynamicallyExtracted) {
        LOG("Freeing dynamically allocated protobuf");
        KineticProto__free_unpacked(pdu->proto, NULL);
    };
	KineticPDUItem *item = (KineticPDUItem *)PDU2LIST(pdu);
	KineticConnection_Lock(connection);
	list_del( &item->list);
	KineticConnection_Unlock(connection);
	free(item);
}

void KineticAllocator_FreeAllPDUs(KineticConnection *connection)
{
	KineticPDUItem *item;
	KineticConnection_Lock(connection);
	while (!list_empty(&connection->pdus)) {
    	item = connection->pdus.n.next;
	 	KineticPDU *pdu = &item->PDU; 
        if ( pdu->proto != NULL && pdu->protobufDynamicallyExtracted) {
               KineticProto__free_unpacked(pdu->proto, NULL);
         }
	  	list_del(&item->list);
		free(item);
	}
	KineticConnection_Unlock(connection);
}

bool KineticAllocator_ValidateAllMemoryFreed(KineticConnection *connection)
{
	bool rc;
	KineticConnection_Lock(connection);
    rc = list_empty(&connection->pdus);
	KineticConnection_Unlock(connection);
	return rc;
}
