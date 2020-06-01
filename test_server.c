#include "tdbus.h"
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <dbus/dbus.h>
#include "enclave_u.h"

DBusHandlerResult t_server_message_handler(TDBusSession *session, DBusMessage *message, void *data);
DBusHandlerResult server_message_handler(DBusConnection *conn, DBusMessage *message, void *data);

const char *version = "0.1";
const char *iface = "br.ufpr.inf.larsis.tdbus_server_test";
const char *serverName = "br.ufpr.inf.larsis.TDBUS";
const char *objectPath = "/br/ufpr/inf/larsis/Object";

const TDBusObjectPathVTable t_server_vtable = {
	.message_function = t_server_message_handler
};

const DBusObjectPathVTable server_vtable = {
	.message_function = server_message_handler
};

TDBusConnection* tdubs_conn;

void start_tdbus_server() {
	DBusError err;

	dbus_error_init(&err);

	tdubs_conn = tdbus_bus_request_connection(serverName, DBUS_NAME_FLAG_REPLACE_EXISTING , &err);

	if (dbus_error_is_set(&err)) { 
		printf("Connection Error (%s)\n", err.message); 
		dbus_error_free(&err);
		return;
	}

	printf("Starting Server v%s\n", version);
	tdbus_main_loop_run(tdubs_conn, &t_server_vtable, NULL);
}

void start_dbus_server() {
	DBusError err;
	int rv;

	dbus_error_init(&err);

	DBusConnection* conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
	if (!conn) {
		fprintf(stderr, "Failed to get a session DBus connection: %s\n", err.message);
		return;
	}

	rv = dbus_bus_request_name(conn, serverName, DBUS_NAME_FLAG_REPLACE_EXISTING , &err);
	if (rv != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		fprintf(stderr, "Failed to request name on bus: %s\n", err.message);
		return;
	}

	if (dbus_error_is_set(&err)) { 
		printf("Connection Error (%s)\n", err.message); 
		dbus_error_free(&err);
		return;
	}

	if (!dbus_connection_register_object_path(conn, objectPath, &server_vtable, NULL)) {
		fprintf(stderr, "Failed to register a object path for 'TestObject'\n");
		return;
	}

	printf("Starting Server v%s\n", version);
	//mainloop = g_main_loop_new(NULL, false);
	/* Set up the DBus connection to work in a GLib event loop */
	//dbus_connection_setup_with_g_main(conn, NULL);
	/* Start the glib event loop */
	//g_main_loop_run(mainloop);

	while (dbus_connection_read_write_dispatch(conn, -1)) {
		DBusMessage* msg = dbus_connection_pop_message(conn);

		// loop again if we haven't got a message
		if (NULL == msg)
			continue;

		server_message_handler(conn, msg, NULL);

		// free the message
		dbus_message_unref(msg);
	}
}

int main(int argc, char *argv[]) {
	if(argc < 2) {
		printf("Argument missing\n");
		return 0;
	}

	int trusted = atoi(argv[1]);

	if(trusted) {
		start_tdbus_server();
	} else {
		start_dbus_server();
	}

	return EXIT_SUCCESS;
}

DBusHandlerResult t_server_message_handler(TDBusSession *session, TDBusMessage *message, void *data) {
	DBusHandlerResult result;
    	DBusMessage *reply = NULL;
	DBusError err;
	sgx_enclave_id_t enclave_id;

	dbus_error_init(&err);

	if (dbus_message_is_method_call(message, iface, "ping8")) {
		//printf("ping\n");
		uint8_t value;

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_BYTE, &value, DBUS_TYPE_INVALID)) {
			printf("ERROR: %s\n", err.message);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		//printf("Value: %d\n", value);
		//fflush(stdout);
		value = 1; //value * 2;

		if (!(reply = tdbus_message_new_method_return(message))) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		tdbus_message_append_args(reply, DBUS_TYPE_BYTE, &value, DBUS_TYPE_INVALID);
	} else if (dbus_message_is_method_call(message, iface, "ping16")) {
		uint16_t value;

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_UINT16, &value, DBUS_TYPE_INVALID)) {
			printf("ERROR: %s\n", err.message);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		value = 1;

		if (!(reply = tdbus_message_new_method_return(message))) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		tdbus_message_append_args(reply, DBUS_TYPE_UINT16, &value, DBUS_TYPE_INVALID);
	} else if (dbus_message_is_method_call(message, iface, "ping32")) {
		uint32_t value;

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_UINT32, &value, DBUS_TYPE_INVALID)) {
			printf("ERROR: %s\n", err.message);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		value = 1;

		if (!(reply = tdbus_message_new_method_return(message))) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		tdbus_message_append_args(reply, DBUS_TYPE_UINT32, &value, DBUS_TYPE_INVALID);
	} else if (dbus_message_is_method_call(message, iface, "ping64")) {
		uint64_t value;

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_UINT64, &value, DBUS_TYPE_INVALID)) {
			printf("ERROR: %s\n", err.message);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		value = 1;

		if (!(reply = tdbus_message_new_method_return(message))) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		tdbus_message_append_args(reply, DBUS_TYPE_UINT64, &value, DBUS_TYPE_INVALID);
	} else if (dbus_message_is_method_call(message, iface, "string")) {
		char *value;

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_STRING, &value, DBUS_TYPE_INVALID)) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		//printf("Value: %s\n", value);
		//fflush(stdout);

		uint8_t ret = 1;

		if (!(reply = tdbus_message_new_method_return(message))) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		tdbus_message_append_args(reply, DBUS_TYPE_BYTE, &ret, DBUS_TYPE_INVALID);
	} else if (dbus_message_is_method_call(message, iface, "array")) {
		uint8_t *value, len;

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &value, &len, DBUS_TYPE_INVALID)) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		//for(int i = 0; i < len; i++) {
		//	printf("value[%d] = %d\n", i, value[i]);
		//}

		uint8_t ret = 1;

		if (!(reply = tdbus_message_new_method_return(message))) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		tdbus_message_append_args(reply, DBUS_TYPE_BYTE, &ret, DBUS_TYPE_INVALID);
	} else if (dbus_message_is_method_call(message, iface, "all")) {
		char *string;
		uint8_t *array, len, value;

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_BYTE, &value, DBUS_TYPE_STRING, &string, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &array, &len, DBUS_TYPE_INVALID)) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		//printf("Value: %d\nString: %s\nArray:\n", value, string);
		//for(int i = 0; i < len; i++) {
		//	printf("value[%d] = %d\n", i, array[i]);
		//}

		value = 1; //value * 2;

		if (!(reply = tdbus_message_new_method_return(message))) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		tdbus_message_append_args(reply, DBUS_TYPE_BYTE, &value, DBUS_TYPE_INVALID);
	} else
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

fail:
	if (dbus_error_is_set(&err)) {
		if (reply)
			dbus_message_unref(reply);

		reply = dbus_message_new_error(message, err.name, err.message);
		dbus_error_free(&err);
	}

	/*
	 * In any cases we should have allocated a reply otherwise it
	 * means that we failed to allocate one.
	 */
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	/* Send the reply which might be an error one too. */
	result = DBUS_HANDLER_RESULT_HANDLED;
	if (!tdbus_connection_send(session, reply, NULL))
		result = DBUS_HANDLER_RESULT_NEED_MEMORY;
	dbus_message_unref(reply);

	return result;
}

DBusHandlerResult server_message_handler(DBusConnection *conn, DBusMessage *message, void *data) {
	DBusHandlerResult result;
    	DBusMessage *reply = NULL;
	DBusError err;
	bool quit = false;

	dbus_error_init(&err);

	if (dbus_message_is_method_call(message, iface, "ping8")) {
		//printf("ping\n");
		uint8_t value;

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_BYTE, &value, DBUS_TYPE_INVALID)) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		//printf("Value: %d\n", value);
		//fflush(stdout);
		value = 1; //value * 2;

		if (!(reply = dbus_message_new_method_return(message))) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		dbus_message_append_args(reply, DBUS_TYPE_BYTE, &value, DBUS_TYPE_INVALID);
	} else if (dbus_message_is_method_call(message, iface, "ping16")) {
		uint16_t value;

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_UINT16, &value, DBUS_TYPE_INVALID)) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		value = 1;

		if (!(reply = dbus_message_new_method_return(message))) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		dbus_message_append_args(reply, DBUS_TYPE_UINT16, &value, DBUS_TYPE_INVALID);
	} else if (dbus_message_is_method_call(message, iface, "ping32")) {
		uint32_t value;

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_UINT32, &value, DBUS_TYPE_INVALID)) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		value = 1;

		if (!(reply = dbus_message_new_method_return(message))) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		dbus_message_append_args(reply, DBUS_TYPE_UINT32, &value, DBUS_TYPE_INVALID);
	} else if (dbus_message_is_method_call(message, iface, "ping64")) {
		uint64_t value;

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_UINT64, &value, DBUS_TYPE_INVALID)) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		value = 1;

		if (!(reply = dbus_message_new_method_return(message))) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		dbus_message_append_args(reply, DBUS_TYPE_UINT64, &value, DBUS_TYPE_INVALID);
	} else if (dbus_message_is_method_call(message, iface, "string")) {
		//printf("string\n");
		char *value;

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_STRING, &value, DBUS_TYPE_INVALID)) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		//printf("Value: %s\n", value);
		//fflush(stdout);

		uint8_t ret = 1;

		if (!(reply = dbus_message_new_method_return(message))) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		dbus_message_append_args(reply, DBUS_TYPE_BYTE, &ret, DBUS_TYPE_INVALID);
	} else if (dbus_message_is_method_call(message, iface, "array")) {
		uint8_t *value, len;

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &value, &len, DBUS_TYPE_INVALID)) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		//for(int i = 0; i < len; i++) {
		//	printf("value[%d] = %d\n", i, value[i]); 
		//}

		uint8_t ret = 1;

		if (!(reply = tdbus_message_new_method_return(message))) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		tdbus_message_append_args(reply, DBUS_TYPE_BYTE, &ret, DBUS_TYPE_INVALID);
	} else
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

fail:
	if (dbus_error_is_set(&err)) {
		if (reply)
			dbus_message_unref(reply);

		reply = dbus_message_new_error(message, err.name, err.message);
		dbus_error_free(&err);
	}

	/*
	 * In any cases we should have allocated a reply otherwise it
	 * means that we failed to allocate one.
	 */
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	/* Send the reply which might be an error one too. */
	result = DBUS_HANDLER_RESULT_HANDLED;
	if (!dbus_connection_send(conn, reply, NULL))
		result = DBUS_HANDLER_RESULT_NEED_MEMORY;
	dbus_message_unref(reply);

	if (quit) {
		fprintf(stderr, "Server exiting...\n");
	}

	return result;
}
