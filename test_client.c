#include "tdbus.h"
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <dbus/dbus.h>

const char *version = "0.1";
const char *iface = "br.ufpr.inf.larsis.tdbus_server_test";
const char *serverName = "br.ufpr.inf.larsis.TDBUS";
const char *objectPath = "/br/ufpr/inf/larsis/Object";

inline __attribute__((always_inline))  uint64_t rdtscp(void) {
        unsigned int low, high;

        asm volatile("rdtscp" : "=a" (low), "=d" (high));

        return low | ((uint64_t)high) << 32;
}

void tdbus_test(int count, int datatype, int arraysize) {
	DBusMessage* msg;
	DBusMessage* reply;
	DBusError err;
	uint64_t startTime = 0;
        uint64_t endTime = 0;

	dbus_error_init(&err);

	startTime = rdtscp();

	TDBusConnection* conn = tdbus_bus_request_connection("br.ufpr.inf.larsis.tdbus_client_test", DBUS_NAME_FLAG_REPLACE_EXISTING , &err);

	if (dbus_error_is_set(&err)) { 
		printf("Connection Error (%s)\n", err.message); 
		dbus_error_free(&err);
		return;
	}

	TDBusSession* session = tdbus_bus_create_session(conn, serverName, objectPath, iface, &err);

	if (dbus_error_is_set(&err)) { 
		printf("Connection Error (%s)\n", err.message); 
		dbus_error_free(&err);
		return;
	}

	endTime = rdtscp();

	printf("%ld", endTime - startTime);

	if(datatype == 1) {
		uint8_t value = 1;

		for(int i = 0; i < count; i++) {
			startTime = rdtscp();

			msg = tdbus_message_new_method_call(session, "ping8");

			tdbus_message_append_args(msg, DBUS_TYPE_BYTE, &value, DBUS_TYPE_INVALID);

			reply = tdbus_connection_send_with_reply_and_block(session, msg, DBUS_TIMEOUT_USE_DEFAULT, &err);
			if (NULL == reply) { 
				printf("Reply Null\n");
				return;
			}

			if (!dbus_message_get_args(reply, &err, DBUS_TYPE_BYTE, &value, DBUS_TYPE_INVALID)) {
				printf("Args ERROR\n");
				return;
			}

			//printf("Value: %d\n", value);

			dbus_message_unref(msg);
			dbus_message_unref(reply);

			endTime = rdtscp();

			printf(",%ld", endTime - startTime);
		}
	} else if(datatype == 2) {
		uint16_t value = 1;

		for(int i = 0; i < count; i++) {
			startTime = rdtscp();

			msg = tdbus_message_new_method_call(session, "ping16");

			tdbus_message_append_args(msg, DBUS_TYPE_UINT16, &value, DBUS_TYPE_INVALID);

			reply = tdbus_connection_send_with_reply_and_block(session, msg, DBUS_TIMEOUT_USE_DEFAULT, &err);
			if (NULL == reply) { 
				printf("Reply Null\n");
				return;
			}

			if (!dbus_message_get_args(reply, &err, DBUS_TYPE_UINT16, &value, DBUS_TYPE_INVALID)) {
				printf("Args ERROR\n");
				return;
			}

			//printf("Value: %d\n", value);

			dbus_message_unref(msg);
			dbus_message_unref(reply);

			endTime = rdtscp();

			printf(",%ld", endTime - startTime);
		}
	} else if(datatype == 3) {
		uint32_t value = 1;

		for(int i = 0; i < count; i++) {
			startTime = rdtscp();

			msg = tdbus_message_new_method_call(session, "ping32");

			tdbus_message_append_args(msg, DBUS_TYPE_UINT32, &value, DBUS_TYPE_INVALID);

			reply = tdbus_connection_send_with_reply_and_block(session, msg, DBUS_TIMEOUT_USE_DEFAULT, &err);
			if (NULL == reply) { 
				printf("Reply Null\n");
				return;
			}

			if (!dbus_message_get_args(reply, &err, DBUS_TYPE_UINT32, &value, DBUS_TYPE_INVALID)) {
				printf("Args ERROR\n");
				return;
			}

			//printf("Value: %d\n", value);

			dbus_message_unref(msg);
			dbus_message_unref(reply);

			endTime = rdtscp();

			printf(",%ld", endTime - startTime);
		}
	} else if(datatype == 4) {
		uint64_t value = 1;

		for(int i = 0; i < count; i++) {
			startTime = rdtscp();

			msg = tdbus_message_new_method_call(session, "ping64");

			tdbus_message_append_args(msg, DBUS_TYPE_UINT64, &value, DBUS_TYPE_INVALID);

			reply = tdbus_connection_send_with_reply_and_block(session, msg, DBUS_TIMEOUT_USE_DEFAULT, &err);
			if (NULL == reply) { 
				printf("Reply Null\n");
				return;
			}

			if (!dbus_message_get_args(reply, &err, DBUS_TYPE_UINT64, &value, DBUS_TYPE_INVALID)) {
				printf("Args ERROR\n");
				return;
			}

			//printf("Value: %d\n", value);

			dbus_message_unref(msg);
			dbus_message_unref(reply);

			endTime = rdtscp();

			printf(",%ld", endTime - startTime);
		}
	} else if(datatype == 5) {
		char string[arraysize + 1];
		const char* p_string = string;
		uint8_t value;

		for(int i = 0; i < arraysize; i++) {
			string[i] = 'a';
		}
		string[arraysize] = '\0';

		for(int i = 0; i < count; i++) {
			startTime = rdtscp();

			msg = tdbus_message_new_method_call(session, "string");

			tdbus_message_append_args(msg, DBUS_TYPE_STRING, &p_string, DBUS_TYPE_INVALID);

			reply = tdbus_connection_send_with_reply_and_block(session, msg, DBUS_TIMEOUT_USE_DEFAULT, &err);
			if (NULL == reply) { 
				printf("Reply Null\n");
				return;
			}

			if (!dbus_message_get_args(reply, &err, DBUS_TYPE_BYTE, &value, DBUS_TYPE_INVALID)) {
				printf("Args ERROR\n");
				return;
			}

			//printf("Value: %d\n", value);

			dbus_message_unref(msg);
			dbus_message_unref(reply);

			endTime = rdtscp();

			printf(",%ld", endTime - startTime);
		}
	} else if(datatype == 6) {
		uint8_t array[arraysize], value;
		uint8_t *p_array = array;

		for(int i = 0; i < arraysize; i++) {
			array[i] = 0;
		}

		for(int i = 0; i < count; i++) {
			startTime = rdtscp();

			msg = tdbus_message_new_method_call(session, "array");

			tdbus_message_append_args(msg, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &p_array, arraysize, DBUS_TYPE_INVALID);

			reply = tdbus_connection_send_with_reply_and_block(session, msg, DBUS_TIMEOUT_USE_DEFAULT, &err);
			if (NULL == reply) { 
				printf("Reply Null\n");
				return;
			}

			if (!dbus_message_get_args(reply, &err, DBUS_TYPE_BYTE, &value, DBUS_TYPE_INVALID)) {
				printf("Args ERROR\n");
				return;
			}

			//printf("Value: %d\n", value);

			dbus_message_unref(msg);
			dbus_message_unref(reply);

			endTime = rdtscp();

			printf(",%ld", endTime - startTime);
		}
	}

	startTime = rdtscp();

	tdbus_bus_close_session(session, &err);

	endTime = rdtscp();

	printf(",%ld\n", endTime - startTime);
}

void dbus_test(int count, int datatype, int arraysize) {
	DBusMessage* msg;
	DBusMessage* reply;
	DBusError err;
	uint64_t startTime = 0;
        uint64_t endTime = 0;
	
	dbus_error_init(&err);

	startTime = rdtscp();

	DBusConnection* conn = dbus_bus_get(DBUS_BUS_SESSION, &err);

	if (dbus_error_is_set(&err)) { 
		printf("Connection Error (%s)\n", err.message); 
		dbus_error_free(&err);
		return;
	}

	dbus_bus_request_name(conn, "br.ufpr.inf.larsis.tdbus_client_test", DBUS_NAME_FLAG_REPLACE_EXISTING , &err);

	if (dbus_error_is_set(&err)) { 
		printf("Connection Error (%s)\n", err.message); 
		dbus_error_free(&err);
		return;
	}

	endTime = rdtscp();

	printf("%ld", endTime - startTime);

	if(datatype == 1) {
		uint8_t value = 1;

		for(int i = 0; i < count; i++) {
			startTime = rdtscp();

			msg = dbus_message_new_method_call(serverName, objectPath, iface, "ping8");

			dbus_message_append_args(msg, DBUS_TYPE_BYTE, &value, DBUS_TYPE_INVALID);

			reply = dbus_connection_send_with_reply_and_block(conn, msg, DBUS_TIMEOUT_USE_DEFAULT, &err);
			if (NULL == reply) { 
				printf("Reply Null\n");
				return;
			}

			if (!dbus_message_get_args(reply, &err, DBUS_TYPE_BYTE, &value, DBUS_TYPE_INVALID)) {
				printf("Args ERROR\n");
				return;
			}

			//printf("Value: %d\n", value);

			dbus_message_unref(msg);
			dbus_message_unref(reply);

			endTime = rdtscp();

			printf(",%ld", endTime - startTime);
		}
	} else if(datatype == 2) {
		uint16_t value = 1;

		for(int i = 0; i < count; i++) {
			startTime = rdtscp();

			msg = dbus_message_new_method_call(serverName, objectPath, iface, "ping16");

			dbus_message_append_args(msg, DBUS_TYPE_UINT16, &value, DBUS_TYPE_INVALID);

			reply = dbus_connection_send_with_reply_and_block(conn, msg, DBUS_TIMEOUT_USE_DEFAULT, &err);
			if (NULL == reply) { 
				printf("Reply Null\n");
				return;
			}

			if (!dbus_message_get_args(reply, &err, DBUS_TYPE_UINT16, &value, DBUS_TYPE_INVALID)) {
				printf("Args ERROR\n");
				return;
			}

			//printf("Value: %d\n", value);

			dbus_message_unref(msg);
			dbus_message_unref(reply);

			endTime = rdtscp();

			printf(",%ld", endTime - startTime);
		}
	} else if(datatype == 3) {
		uint32_t value = 1;

		for(int i = 0; i < count; i++) {
			startTime = rdtscp();

			msg = dbus_message_new_method_call(serverName, objectPath, iface, "ping32");

			dbus_message_append_args(msg, DBUS_TYPE_UINT32, &value, DBUS_TYPE_INVALID);

			reply = dbus_connection_send_with_reply_and_block(conn, msg, DBUS_TIMEOUT_USE_DEFAULT, &err);
			if (NULL == reply) { 
				printf("Reply Null\n");
				return;
			}

			if (!dbus_message_get_args(reply, &err, DBUS_TYPE_UINT32, &value, DBUS_TYPE_INVALID)) {
				printf("Args ERROR\n");
				return;
			}

			//printf("Value: %d\n", value);

			dbus_message_unref(msg);
			dbus_message_unref(reply);

			endTime = rdtscp();

			printf(",%ld", endTime - startTime);
		}
	} else if(datatype == 4) {
		uint64_t value = 1;

		for(int i = 0; i < count; i++) {
			startTime = rdtscp();

			msg = dbus_message_new_method_call(serverName, objectPath, iface, "ping64");

			dbus_message_append_args(msg, DBUS_TYPE_UINT64, &value, DBUS_TYPE_INVALID);

			reply = dbus_connection_send_with_reply_and_block(conn, msg, DBUS_TIMEOUT_USE_DEFAULT, &err);
			if (NULL == reply) { 
				printf("Reply Null\n");
				return;
			}

			if (!dbus_message_get_args(reply, &err, DBUS_TYPE_UINT64, &value, DBUS_TYPE_INVALID)) {
				printf("Args ERROR\n");
				return;
			}

			//printf("Value: %d\n", value);

			dbus_message_unref(msg);
			dbus_message_unref(reply);

			endTime = rdtscp();

			printf(",%ld", endTime - startTime);
		}
	} else if(datatype == 5) {
		char string[arraysize + 1];
		const char* p_string = string;
		uint8_t value;

		for(int i = 0; i < arraysize; i++) {
			string[i] = 'a';
		}
		string[arraysize] = '\0';

		for(int i = 0; i < count; i++) {
			startTime = rdtscp();

			msg = dbus_message_new_method_call(serverName, objectPath, iface, "string");

			dbus_message_append_args(msg, DBUS_TYPE_STRING, &p_string, DBUS_TYPE_INVALID);

			reply = dbus_connection_send_with_reply_and_block(conn, msg, DBUS_TIMEOUT_USE_DEFAULT, &err);
			if (NULL == reply) { 
				printf("Reply Null\n");
				return;
			}

			if (!dbus_message_get_args(reply, &err, DBUS_TYPE_BYTE, &value, DBUS_TYPE_INVALID)) {
				printf("Args ERROR\n");
				return;
			}

			//printf("Value: %d\n", value);

			dbus_message_unref(msg);
			dbus_message_unref(reply);

			endTime = rdtscp();

			printf(",%ld", endTime - startTime);
		}
	} else if(datatype == 6) {
		uint8_t array[arraysize], value;
		uint8_t *p_array = array;

		for(int i = 0; i < arraysize; i++) {
			array[i] = 0;
		}

		for(int i = 0; i < count; i++) {
			startTime = rdtscp();

			msg = dbus_message_new_method_call(serverName, objectPath, iface, "array");

			dbus_message_append_args(msg, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &p_array, arraysize, DBUS_TYPE_INVALID);

			reply = dbus_connection_send_with_reply_and_block(conn, msg, DBUS_TIMEOUT_USE_DEFAULT, &err);
			if (NULL == reply) { 
				printf("Reply Null\n");
				return;
			}

			if (!dbus_message_get_args(reply, &err, DBUS_TYPE_BYTE, &value, DBUS_TYPE_INVALID)) {
				printf("Args ERROR\n");
				return;
			}

			//printf("Value: %d\n", value);

			dbus_message_unref(msg);
			dbus_message_unref(reply);

			endTime = rdtscp();

			printf(",%ld", endTime - startTime);
		}
	}

	printf(",0\n");
}

int main(int argc, char *argv[]) {
	if(argc < 4) {
		printf("Argument missing\n");
		return 0;
	}

	int trusted = atoi(argv[1]);
	int count = atoi(argv[2]);
	int datatype = atoi(argv[3]); // 1 = 1 byte; 2 = 2 bytes; 3 = 4 bytes; 4 = 8 bytes; 5 = string; 6 = array
	int arraysize = 0;

	if((datatype == 5) || (datatype == 6)) {
		if(argc < 5) {
			printf("Argument missing\n");
			return 0;
		}

		arraysize = atoi(argv[4]);
	}

	if(trusted) {
		tdbus_test(count, datatype, arraysize);
	} else {
		dbus_test(count, datatype, arraysize);
	}
}
