#ifndef _TDBUS_TYPES_H_
#define _TDBUS_TYPES_H_

#include "sgx_eid.h"
#include <dbus/dbus.h>

typedef DBusMessage TDBusMessage;

typedef struct {
	sgx_enclave_id_t tdbus_eid;
	uint64_t tdbus_uid;
	DBusConnection* tdbus_connection;
} TDBusConnection;

typedef struct {
	sgx_enclave_id_t tdbus_eid;
	uint64_t tdbus_uid;
	TDBusConnection* tdbus_connection;
	char* destination;
	char* path;
	char* iface;
} TDBusSession;

typedef void              (* TDBusObjectPathUnregisterFunction) (TDBusSession *session, void *user_data);
typedef DBusHandlerResult (* TDBusObjectPathMessageFunction)    (TDBusSession *session, TDBusMessage *message, void *user_data);

typedef struct {
   TDBusObjectPathUnregisterFunction   unregister_function; 
   TDBusObjectPathMessageFunction      message_function; 
   void (* dbus_internal_pad1) (void *); 
   void (* dbus_internal_pad2) (void *); 
   void (* dbus_internal_pad3) (void *); 
   void (* dbus_internal_pad4) (void *); 
} TDBusObjectPathVTable;

#endif //_TDBUS_TYPES_H_
