#ifndef _TDBUS_H_
#define _TDBUS_H_

#include <dbus/dbus.h>
#include "tdbus_types.h"

TDBusConnection* tdbus_bus_request_connection(const char *name, unsigned int flags, DBusError *error);

TDBusSession* tdbus_bus_create_session(TDBusConnection *connection, const char *destination, const char *path, const char *iface, DBusError *error);

TDBusMessage* tdbus_message_new(int message_type);

TDBusMessage* tdbus_message_new_method_call(TDBusSession *session, const char *method);

TDBusMessage* tdbus_message_new_signal(TDBusSession *session, const char *name);

TDBusMessage* tdbus_message_new_method_return(TDBusMessage* message);

TDBusMessage* tdbus_message_new_error(DBusMessage *reply_to, const char *error_name, const char *error_message);

dbus_bool_t tdbus_message_append_args(TDBusMessage *message, int first_arg_type, ...);

dbus_bool_t tdbus_message_append_args_valist(TDBusMessage* message, int first_arg_type, va_list var_args);

TDBusMessage* tdbus_connection_send_with_reply_and_block(TDBusSession *session, TDBusMessage *message, int timeout_milliseconds, DBusError *error);

dbus_bool_t tdbus_connection_send(TDBusSession *session, TDBusMessage* message, dbus_uint32_t* serial);

dbus_bool_t tdbus_connection_register_object_path(TDBusConnection* connection, const char* path, const DBusObjectPathVTable* vtable, void* user_data);

void tdbus_bus_close_session(TDBusSession *session, DBusError *error);

void tdbus_main_loop_run(TDBusConnection *connection, const TDBusObjectPathVTable* vtable, void* user_data);

#endif //_TDBUS_H_
