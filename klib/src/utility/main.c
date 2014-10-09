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
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>

void ParseOptions(
    const int argc,
    char** const argv,
    KineticSession* config,
    KineticEntry* entry);

KineticStatus ExecuteOperation(
    const char* op,
    KineticSessionHandle sessionHandle,
    KineticEntry* entry);

void ConfigureEntry(
    KineticEntry* entry,
    const char* key,
    const char* tag,
    const char* version,
    KineticAlgorithm algorithm,
    const char* value);

void ReportOperationConfiguration(
    const char* operation,
    KineticSession* config,
    KineticEntry* entry);


static KineticSession SessionConfig;
static uint8_t HmacData[1024];
static KineticEntry Entry;
static uint8_t KeyData[1024];
static uint8_t TagData[1024];
static uint8_t VersionData[1024];
static uint8_t ValueData[PDU_VALUE_MAX_LEN];
static const char* TestDataString = "lorem ipsum... blah blah blah... etc.";


int main(int argc, char** argv)
{
    // Parse command line options
	int optionIndex;
    ParseOptions(argc, argv, &SessionConfig, &Entry);

    // Establish a session/connection with the Kinetic Device
	KineticClient_Init(NULL, 0);
    KineticSessionHandle sessionHandle;
    KineticStatus status = KineticClient_Connect(&SessionConfig, &sessionHandle);
    if (status != KINETIC_STATUS_SUCCESS) {
        printf("Failed connecting to host %s:%d ",
               SessionConfig.host, SessionConfig.port);
        return -1;
    }

    // Execute all specified operations in order
    for (optionIndex = 1; optionIndex < argc; optionIndex++) {
        const char* operation = argv[optionIndex];
        ReportOperationConfiguration(operation, &SessionConfig, &Entry);
        ExecuteOperation(operation, sessionHandle, &Entry);
    }

    // Shutdown the Kinetic Device session
    KineticClient_Disconnect(&sessionHandle);
    printf("\nKinetic client session terminated!\n\n");

    return 0;
}

KineticStatus ExecuteOperation(
    const char* operation,
    KineticSessionHandle sessionHandle,
    KineticEntry* entry)
{
    KineticStatus status = KINETIC_STATUS_INVALID;
	int i;
    if (strcmp("noop", operation) == 0) {
        status = KineticClient_NoOp(sessionHandle);
        if (status == KINETIC_STATUS_SUCCESS) {
            printf("\nNoOp operation completed successfully."
                   " Kinetic Device is alive and well!\n");
        }
    }

    else if (strcmp("put", operation) == 0) {
        status = KineticClient_Put(sessionHandle, entry);
        if (status == KINETIC_STATUS_SUCCESS) {
            printf("\nPut operation completed successfully."
                   " Your data has been stored!\n\n");
        }
    }

    else if (strcmp("get", operation) == 0) {
        status = KineticClient_Get(sessionHandle, entry);
        if (status == 0) {
            printf("\nGet executed successfully."
                   "The entry has been retrieved!\n\n");
        }
    }

    else if (strcmp("delete", operation) == 0) {
        status = KineticClient_Delete(sessionHandle, entry);
        if (status == 0) {
            printf("\nDelete executed successfully."
                   " The entry has been destroyed!\n\n");
        }
    }

    else if (strcmp("range", operation) == 0) {
#define MAX_KEYS 10
#define KEY_SIZE 32
		KineticRange range;
		ByteBuffer	 keys[MAX_KEYS];
		uint8_t *buf = malloc(MAX_KEYS * KEY_SIZE);
		assert(buf);
		memset(buf, 0x00,  MAX_KEYS * KEY_SIZE);
		memset(&range, 0x00, sizeof(range));
		for(i = 0; i < MAX_KEYS; i++) {
			keys[i].array.len = KEY_SIZE;
			keys[i].array.data = buf;
			buf += KEY_SIZE;
		}
		
		for (i = 0; i < MAX_KEYS; i++) {
			entry->key.array.len = (uint32_t)sprintf((char *)(entry->key.array.data), "%08x", i);
			entry->key.bytesUsed = entry->key.array.len;
			entry->force = true;
        	status = KineticClient_Put(sessionHandle, entry);
			if (status) {
					printf("put failed ...\n"); return(1);
			}
		}
		// get the last key
		status = KineticClient_Get(sessionHandle, entry);
		if (status) {
				printf("get failed ...\n"); return(1);
		}
		
		memset(&range, 0x00, sizeof(range));
		range.startKey.array.data = malloc(32);
		range.startKey.array.len = sprintf((char *)(range.startKey.array.data), "%08x", 0);
		range.endKey.array.data = malloc(32);
		range.endKey.array.len = sprintf((char *)(range.endKey.array.data), "%08x", 10);
		range.startKeyInclusive = true;
		range.endKeyInclusive = true;
		range.reverse = true;
		range.maxRequested = 100;
		range.keys = keys;

        status = KineticClient_GetRange(sessionHandle, &range);
        if (status == 0) {
        	ByteBuffer * key = range.keys;
            printf("\nrange executed successfully.\n\n");
            printf(" number of keys returned ...%d\n", range.returned);
            for (i = 0; i < MAX_KEYS; i++, key++)
            	printf("Key:%02d:%s\n", i, key->array.data);

        }
    }

    else {
        printf("\nSpecified operation '%s' is invalid!\n", operation);
        return -1;
    }

    // Print out status code description if operation was not successful
    if (status != KINETIC_STATUS_SUCCESS) {
        printf("\nERROR: Operation '%s' failed! \n\n",
               operation);
    }

    return status;
}

void ConfigureEntry(
    KineticEntry* entry,
    const char* key,
    const char* tag,
    const char* version,
    KineticAlgorithm algorithm,
    const char* value)
{
    assert(entry != NULL);

    ByteBuffer keyBuffer = ByteBuffer_Create(KeyData, sizeof(KeyData));
    ByteBuffer_AppendCString(&keyBuffer, key);
    ByteBuffer tagBuffer = ByteBuffer_Create(TagData, sizeof(TagData));
    ByteBuffer_AppendCString(&tagBuffer, tag);
    ByteBuffer versionBuffer = ByteBuffer_Create(VersionData, sizeof(VersionData));
    ByteBuffer_AppendCString(&versionBuffer, version);
    ByteBuffer valueBuffer = ByteBuffer_Create(ValueData, sizeof(ValueData));
    ByteBuffer_AppendCString(&valueBuffer, value);

    // Setup to write some test data
    *entry = (KineticEntry) {
        .key = keyBuffer,
         .tag = tagBuffer,
          .newVersion = versionBuffer,
           .algorithm = algorithm,
            .value = valueBuffer,
    };
}

void ReportOperationConfiguration(
    const char* operation,
    KineticSession* config,
    KineticEntry* entry)
{
    printf("\n"
           "Executing '%s' w/configuration:\n"
           "-------------------------------\n"
           "  host: %s\n"
           "  port: %d\n"
           "  non-blocking: %s\n"
           "  clusterVersion: %lld\n"
           "  identity: %lld\n"
           "  key: %zd bytes\n"
           "  value: %zd bytes\n",
           operation,
           config->host,
           config->port,
           config->nonBlocking ? "true" : "false",
           (long long int)config->clusterVersion,
           (long long int)config->identity,
           entry->key.bytesUsed,
           entry->value.bytesUsed);
}

void ParseOptions(
    const int argc,
    char** const argv,
    KineticSession* sessionConfig,
    KineticEntry* entry)
{
    // Create an ArgP processor to parse arguments
    struct {
        char host[HOST_NAME_MAX];
        int port;
        int nonBlocking;
        int useTls;
        int64_t clusterVersion;
        int64_t identity;
        char hmacKey[KINETIC_MAX_KEY_LEN];
        char key[64];
        char version[64];
        char tag[64];
        KineticAlgorithm algorithm;
    } cfg = {
        .host = "localhost",
        .port = KINETIC_PORT,
        .nonBlocking = false,
        .useTls = false,
        .clusterVersion = 0,
        .identity = 1,
        .hmacKey = "asdfasdf",
        .key = "SomeObjectKeyValue",
        .version = "v1.0",
        .tag = "SomeTagValue",
        .algorithm = KINETIC_ALGORITHM_SHA1,
    };

    // Create configuration for long format options
    struct option long_options[] = {
        {"non-blocking", no_argument,       &cfg.nonBlocking, true},
        {"blocking",     no_argument,       &cfg.nonBlocking, false},
        {"tls",          no_argument,       &cfg.port,        KINETIC_TLS_PORT},
        {"host",         required_argument, 0,                'h'},
        {0,              0,                 0,                0},
    };

    // Parse the options from the command line
    int option, optionIndex = 0;
    while ((option = getopt_long(argc, argv, "h", long_options, &optionIndex)) != -1) {
        // Parse options until we reach the end of the argument list
        switch (option) {
        // If this option set a flag, do nothing else now
        case 0: if (long_options[optionIndex].flag != 0) {
                break;
            }
        // Configure host
        case 'h': strcpy(cfg.host, optarg); break;
        // Discard '?', since getopt_long already printed info
        case '?': break;
        // Abort upon error
        default: assert(false);
        }
    }

    // Configure session for connection
    *sessionConfig = (KineticSession) {
        .port = cfg.port,
         .clusterVersion = cfg.clusterVersion,
          .identity = cfg.identity,
           .nonBlocking = cfg.nonBlocking,
            .hmacKey = ByteArray_Create(HmacData, strlen(cfg.hmacKey)),
    };
    memcpy(HmacData, cfg.hmacKey, strlen(cfg.hmacKey));
    strncpy(sessionConfig->host, cfg.host, HOST_NAME_MAX);

    // Populate and configure the entry to be used for operations
    ConfigureEntry(entry,
                   cfg.key, cfg.tag, cfg.version, cfg.algorithm, TestDataString);
}
