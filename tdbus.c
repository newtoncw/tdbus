#include "tdbus.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#include "enclave_u.h"
#include <stdlib.h>
#include <stdio.h>

#define ENCLAVE_FILENAME "enclave.signed.so"

const char* _tdbus_enclave_error_translate(sgx_status_t status) {
	switch(status) {
		case SGX_ERROR_UNEXPECTED: return "SGX ERROR: Unexpected error";
		case SGX_ERROR_INVALID_PARAMETER: return "SGX ERROR: The parameter is incorrect";
		case SGX_ERROR_OUT_OF_MEMORY: return "SGX ERROR: Not enough memory is available to complete this operation";
		case SGX_ERROR_ENCLAVE_LOST: return "SGX ERROR: Enclave lost after power transition or used in child process created by linux:fork()";
		case SGX_ERROR_INVALID_STATE: return "SGX ERROR: SGX API is invoked in incorrect order or state";
		//case SGX_ERROR_FEATURE_NOT_SUPPORTED: return "SGX ERROR: Feature is not supported on this platform";
		//case SGX_PTHREAD_EXIT: return "SGX ERROR: Enclave is exited with pthread_exit()";
		case SGX_ERROR_INVALID_FUNCTION: return "SGX ERROR: The ecall/ocall index is invalid";
		case SGX_ERROR_OUT_OF_TCS: return "SGX ERROR: The enclave is out of TCS";
		case SGX_ERROR_ENCLAVE_CRASHED: return "SGX ERROR: The enclave is crashed";
		case SGX_ERROR_ECALL_NOT_ALLOWED: return "SGX ERROR: The ECALL is not allowed at this time, e.g. ecall is blocked by the dynamic entry table, or nested ecall is not allowed during initialization";
		case SGX_ERROR_OCALL_NOT_ALLOWED: return "SGX ERROR: The OCALL is not allowed at this time, e.g. ocall is not allowed during exception handling";
		case SGX_ERROR_STACK_OVERRUN: return "SGX ERROR: The enclave is running out of stack";
		case SGX_ERROR_UNDEFINED_SYMBOL: return "SGX ERROR: The enclave image has undefined symbol";
		case SGX_ERROR_INVALID_ENCLAVE: return "SGX ERROR: The enclave image is not correct";
		case SGX_ERROR_INVALID_ENCLAVE_ID: return "SGX ERROR: The enclave id is invalid";
		case SGX_ERROR_INVALID_SIGNATURE: return "SGX ERROR: The signature is invalid";
		case SGX_ERROR_NDEBUG_ENCLAVE: return "SGX ERROR: The enclave is signed as product enclave, and can not be created as debuggable enclave";
		case SGX_ERROR_OUT_OF_EPC: return "SGX ERROR: Not enough EPC is available to load the enclave";
		case SGX_ERROR_NO_DEVICE: return "SGX ERROR: Can't open SGX device";
		case SGX_ERROR_MEMORY_MAP_CONFLICT: return "SGX ERROR: Page mapping failed in driver";
		case SGX_ERROR_INVALID_METADATA: return "SGX ERROR: The metadata is incorrect";
		case SGX_ERROR_DEVICE_BUSY: return "SGX ERROR: Device is busy, mostly EINIT failed";
		case SGX_ERROR_INVALID_VERSION: return "SGX ERROR: Metadata version is inconsistent between uRTS and sgx_sign or uRTS is incompatible with current platform";
		case SGX_ERROR_MODE_INCOMPATIBLE: return "SGX ERROR: The target enclave 32/64 bit mode or sim/hw mode is incompatible with the mode of current uRTS";
		case SGX_ERROR_ENCLAVE_FILE_ACCESS: return "SGX ERROR: Can't open enclave file";
		case SGX_ERROR_INVALID_MISC: return "SGX ERROR: The MiscSelct/MiscMask settings are not correct";
		case SGX_ERROR_INVALID_LAUNCH_TOKEN: return "SGX ERROR: The launch token is not correct";
		case SGX_ERROR_MAC_MISMATCH: return "SGX ERROR: Indicates verification error for reports, sealed datas, etc";
		case SGX_ERROR_INVALID_ATTRIBUTE: return "SGX ERROR: The enclave is not authorized";
		case SGX_ERROR_INVALID_CPUSVN: return "SGX ERROR: The cpu svn is beyond platform's cpu svn value";
		case SGX_ERROR_INVALID_ISVSVN: return "SGX ERROR: The isv svn is greater than the enclave's isv svn";
		case SGX_ERROR_INVALID_KEYNAME: return "SGX ERROR: The key name is an unsupported value";
		case SGX_ERROR_SERVICE_UNAVAILABLE: return "SGX ERROR: Indicates aesm didn't respond or the requested service is not supported";
		case SGX_ERROR_SERVICE_TIMEOUT: return "SGX ERROR: The request to aesm timed out";
		case SGX_ERROR_AE_INVALID_EPIDBLOB: return "SGX ERROR: Indicates epid blob verification error";
		case SGX_ERROR_SERVICE_INVALID_PRIVILEGE: return "SGX ERROR: Enclave has no privilege to get launch token";
		case SGX_ERROR_EPID_MEMBER_REVOKED: return "SGX ERROR: The EPID group membership is revoked";
		case SGX_ERROR_UPDATE_NEEDED: return "SGX ERROR: SGX needs to be updated";
		case SGX_ERROR_NETWORK_FAILURE: return "SGX ERROR: Network connecting or proxy setting issue is encountered";
		case SGX_ERROR_AE_SESSION_INVALID: return "SGX ERROR: Session is invalid or ended by server";
		case SGX_ERROR_BUSY: return "SGX ERROR: The requested service is temporarily not availabe";
		case SGX_ERROR_MC_NOT_FOUND: return "SGX ERROR: The Monotonic Counter doesn't exist or has been invalided";
		case SGX_ERROR_MC_NO_ACCESS_RIGHT: return "SGX ERROR: Caller doesn't have the access right to specified VMC";
		case SGX_ERROR_MC_USED_UP: return "SGX ERROR: Monotonic counters are used out";
		case SGX_ERROR_MC_OVER_QUOTA: return "SGX ERROR: Monotonic counters exceeds quota limitation";
		case SGX_ERROR_KDF_MISMATCH: return "SGX ERROR: Key derivation function doesn't match during key exchange";
		case SGX_ERROR_UNRECOGNIZED_PLATFORM: return "SGX ERROR: EPID Provisioning failed due to platform not recognized by backend server";
		//case SGX_ERROR_UNSUPPORTED_CONFIG: return "SGX ERROR: The config for trigging EPID Provisiong or PSE Provisiong&LTP is invalid";
		case SGX_ERROR_NO_PRIVILEGE: return "SGX ERROR: Not enough privilege to perform the operation";
		case SGX_ERROR_PCL_ENCRYPTED: return "SGX ERROR: trying to encrypt an already encrypted enclave";
		case SGX_ERROR_PCL_NOT_ENCRYPTED: return "SGX ERROR: trying to load a plain enclave using sgx_create_encrypted_enclave";
		case SGX_ERROR_PCL_MAC_MISMATCH: return "SGX ERROR: section mac result does not match build time mac";
		case SGX_ERROR_PCL_SHA_MISMATCH: return "SGX ERROR: Unsealed key MAC does not match MAC of key hardcoded in enclave binary";
		case SGX_ERROR_PCL_GUID_MISMATCH: return "SGX ERROR: GUID in sealed blob does not match GUID hardcoded in enclave binary";
		case SGX_ERROR_FILE_BAD_STATUS: return "SGX ERROR: The file is in bad status, run sgx_clearerr to try and fix it";
		case SGX_ERROR_FILE_NO_KEY_ID: return "SGX ERROR: The Key ID field is all zeros, can't re-generate the encryption key";
		case SGX_ERROR_FILE_NAME_MISMATCH: return "SGX ERROR: The current file name is different then the original file name (not allowed, substitution attack)";
		case SGX_ERROR_FILE_NOT_SGX_FILE: return "SGX ERROR: The file is not an SGX file";
		case SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE: return "SGX ERROR: A recovery file can't be opened, so flush operation can't continue (only used when no EXXX is returned)";
		case SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE: return "SGX ERROR: A recovery file can't be written, so flush operation can't continue (only used when no EXXX is returned)";
		case SGX_ERROR_FILE_RECOVERY_NEEDED: return "SGX ERROR: When openeing the file, recovery is needed, but the recovery process failed";
		case SGX_ERROR_FILE_FLUSH_FAILED: return "SGX ERROR: fflush operation (to disk) failed (only used when no EXXX is returned)";
		case SGX_ERROR_FILE_CLOSE_FAILED: return "SGX ERROR: fclose operation (to disk) failed (only used when no EXXX is returned)";
		//case SGX_ERROR_UNSUPPORTED_ATT_KEY_ID: return "SGX ERROR: platform quoting infrastructure does not support the key";
		//case SGX_ERROR_ATT_KEY_CERTIFICATION_FAILURE: return "SGX ERROR: Failed to generate and certify the attestation key";
		//case SGX_ERROR_ATT_KEY_UNINITIALIZED: return "SGX ERROR: The platform quoting infrastructure does not have the attestation key available to generate quote";
		//case SGX_ERROR_INVALID_ATT_KEY_CERT_DATA: return "SGX ERROR: The data returned by the platform library's sgx_get_quote_config() is invalid";
		//case SGX_ERROR_PLATFORM_CERT_UNAVAILABLE: return "SGX ERROR: The PCK Cert for the platform is not available";
		case SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED: return "SGX ERROR: The ioctl for enclave_create unexpectedly failed with EINTR";
		default: return "";
	}
}

dbus_bool_t _tdbus_validate_session(TDBusSession *session, DBusError *error) {
	if(session == NULL) {
		dbus_set_error_const(error, "Session ERROR", "Session must be not null");
		return FALSE;
	} else if((session->tdbus_connection == NULL) || (session->tdbus_connection->tdbus_connection == NULL)) {
		dbus_set_error_const(error, "Session ERROR", "Connection must be not null");
		return FALSE;
	} else if(session->tdbus_eid <= 0) {
		dbus_set_error_const(error, "Session ERROR", "Invalid session id");
		return FALSE;
	}

	return TRUE;
}

sgx_status_t _tdbus_create_enclave(sgx_enclave_id_t* tdbus_eid) {
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;
	sgx_launch_token_t token = {0};

	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, tdbus_eid, NULL);

	return ret;
}

TDBusConnection* tdbus_bus_request_connection(const char *name, unsigned int flags, DBusError *error) {
	TDBusConnection* conn = malloc(sizeof(TDBusConnection));
	sgx_enclave_id_t eid;
	uint64_t uid;

	conn->tdbus_connection = dbus_bus_get(DBUS_BUS_SESSION, error);

	if (dbus_error_is_set(error)) {
		return NULL;
	}

	dbus_bus_request_name(conn->tdbus_connection, name, flags , error);

	if (dbus_error_is_set(error)) {
		return NULL;
	}

	sgx_status_t ret = _tdbus_create_enclave(&eid);
	conn->tdbus_eid = eid;

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _tdbus_enclave_error_translate(ret));
		return NULL;
	}

	ret = ecall_enclave_init(conn->tdbus_eid, &uid);
	conn->tdbus_uid = uid;

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _tdbus_enclave_error_translate(ret));
		return NULL;
	}

	return conn;
}

void _tdbus_session_request(TDBusConnection *connection, const char *destination, const char *path, const char *iface, uint64_t *uid, sgx_dh_msg1_t *dh_msg1, DBusError *error){
	sgx_status_t ret = SGX_SUCCESS;
	DBusMessage* reply;
	DBusMessage* msg;
	char *pReadData;
	int len;

	msg = dbus_message_new_method_call(destination, path, iface, "tdbus_session_request");
	if (msg == NULL) {
		dbus_set_error_const(error, "NULL message", "dbus_message_new_method_call failed");
		return;
	}

	dbus_message_append_args(msg, DBUS_TYPE_UINT64, &(connection->tdbus_uid), DBUS_TYPE_INVALID);

	reply = dbus_connection_send_with_reply_and_block(connection->tdbus_connection, msg, DBUS_TIMEOUT_USE_DEFAULT, error);

	dbus_message_unref(msg);

	if (dbus_error_is_set(error)) {
		return;
	}

	if(reply == NULL) {
		dbus_set_error_const(error, "NULL reply", "Server sent null reply");
		return;
	}

	if (!dbus_message_get_args(reply, error, DBUS_TYPE_UINT64, uid, DBUS_TYPE_UINT32, &ret, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &pReadData, &len, DBUS_TYPE_INVALID)) {
		return;
	}

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _tdbus_enclave_error_translate(ret));
		return;
	}

	if (len > 0) {
		memcpy(dh_msg1, pReadData, len);
	} else {
		dbus_set_error_const(error, "NULL reply", "Server sent null reply");
		return;
	}

	dbus_message_unref(reply);
}

void _tdbus_exchange_report(TDBusConnection *connection, const char *destination, const char *path, const char *iface, uint64_t *uid, sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, DBusError *error){
	sgx_status_t ret = SGX_SUCCESS;
	DBusMessage* reply;
	DBusMessage* msg;
	char *p_read_dh_msg3;
	int len_dh_msg3;

	msg = dbus_message_new_method_call(destination, path, iface, "tdbus_exchange_report");
	if (msg == NULL) {
		dbus_set_error_const(error, "NULL message", "dbus_message_new_method_call failed");
		return;
	}

	dbus_message_append_args(msg, DBUS_TYPE_UINT64, &(connection->tdbus_uid), DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dh_msg2, sizeof(sgx_dh_msg2_t), DBUS_TYPE_INVALID);

	reply = dbus_connection_send_with_reply_and_block(connection->tdbus_connection, msg, DBUS_TIMEOUT_USE_DEFAULT, error);

	dbus_message_unref(msg);

	if (dbus_error_is_set(error)) {
		return;
	}

	if(reply == NULL) {
		dbus_set_error_const(error, "NULL reply", "Server sent null reply");
		return;
	}

	if (!dbus_message_get_args(reply, error, DBUS_TYPE_UINT64, uid, DBUS_TYPE_UINT32, &ret, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &p_read_dh_msg3, &len_dh_msg3, DBUS_TYPE_INVALID)) {
		return;
	}

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _tdbus_enclave_error_translate(ret));
		return;
	}

	if (len_dh_msg3 > 0) {
		memcpy(dh_msg3, p_read_dh_msg3, len_dh_msg3);
	} else {
		dbus_set_error_const(error, "NULL reply", "Server sent null reply");
		return;
	}

	dbus_message_unref(reply);
}

TDBusSession* tdbus_bus_create_session(TDBusConnection *connection, const char *destination, const char *path, const char *iface, DBusError *error) {
	sgx_status_t status = SGX_SUCCESS, ret = SGX_SUCCESS;
	sgx_dh_msg1_t dh_msg1;
	sgx_dh_msg2_t dh_msg2;
	sgx_dh_msg3_t dh_msg3;
	sgx_dh_session_t sgx_dh_session;
	uint64_t uid;
	TDBusSession* tdbus_session = malloc(sizeof(TDBusSession));

	tdbus_session->tdbus_connection = connection;

	tdbus_session->destination = malloc(strlen(destination) + 2);
	tdbus_session->path = malloc(strlen(path) + 2);
	tdbus_session->iface = malloc(strlen(iface) + 2);

	strncpy(tdbus_session->destination, destination, strlen(destination));
	strncpy(tdbus_session->path, path, strlen(path));
	strncpy(tdbus_session->iface, iface, strlen(iface));

	tdbus_session->destination[strlen(destination)] = '\0';
	tdbus_session->path[strlen(path)] = '\0';
	tdbus_session->iface[strlen(iface)] = '\0';

	ret = ecall_init_session(connection->tdbus_eid, &sgx_dh_session, &status);

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _tdbus_enclave_error_translate(ret));
		return NULL;
	}

	_tdbus_session_request(connection, destination, path, iface, &uid, &dh_msg1, error);

	if (dbus_error_is_set(error)) {
		return NULL;
	}

	tdbus_session->tdbus_uid = uid;

	ret = ecall_initiator_proc_msg1(connection->tdbus_eid, uid, &dh_msg1, &dh_msg2, &sgx_dh_session, &status);

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _tdbus_enclave_error_translate(ret));
		return NULL;
	}

	_tdbus_exchange_report(connection, destination, path, iface, &uid, &dh_msg2, &dh_msg3, error);

	if (dbus_error_is_set(error)) {
		return NULL;
	}

	ret = ecall_initiator_proc_msg3(connection->tdbus_eid, uid, &dh_msg3, &sgx_dh_session, &status);

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _tdbus_enclave_error_translate(ret));
		return NULL;
	}

	return tdbus_session;
}

uint8_t _tdbus_get_element_byte_size(uint8_t element_type) {
	switch(element_type) { 
		case DBUS_TYPE_BYTE: return 1;
		case DBUS_TYPE_INT16:
		case DBUS_TYPE_UINT16: return 2;
		case DBUS_TYPE_INT32:
		case DBUS_TYPE_UINT32: return 4;
		case DBUS_TYPE_INT64:
		case DBUS_TYPE_UINT64:
		case DBUS_TYPE_DOUBLE: return 8;
		default: return 1;
	}
}

TDBusMessage* _tdbus_copy_message(TDBusMessage* message) {
	TDBusMessage *ret = dbus_message_new(dbus_message_get_type(message)); 

	dbus_message_set_serial(ret, dbus_message_get_serial(message));
	if(dbus_message_get_reply_serial(message) != 0) dbus_message_set_reply_serial(ret, dbus_message_get_reply_serial(message));
	dbus_message_set_no_reply(ret, dbus_message_get_no_reply(message));
	if(dbus_message_get_sender(message) != NULL) dbus_message_set_sender(ret, dbus_message_get_sender(message));
	if(dbus_message_get_destination(message) != NULL) dbus_message_set_destination(ret, dbus_message_get_destination(message));
	if(dbus_message_get_path(message) != NULL) dbus_message_set_path(ret, dbus_message_get_path(message));
	if(dbus_message_get_interface(message) != NULL) dbus_message_set_interface(ret, dbus_message_get_interface(message));
	if(dbus_message_get_member(message) != NULL) dbus_message_set_member(ret, dbus_message_get_member(message));

	return ret;
}

TDBusMessage* _tdbus_encrypt_message(TDBusSession *session, TDBusMessage* message, DBusError *error) {
	if(dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_SIGNAL) {
		return message;
	}

	DBusMessageIter iter;
	uint8_t current_type;
	uint64_t total_size = 0;

	dbus_message_iter_init(message, &iter);

	while ((current_type = dbus_message_iter_get_arg_type(&iter)) != DBUS_TYPE_INVALID) {
		uint8_t element_type = current_type;
		
		if(current_type == DBUS_TYPE_STRING) {
			const char* value;

			dbus_message_iter_get_basic(&iter, &value);

			total_size += strlen(value) + 5;
		} else if(current_type == DBUS_TYPE_ARRAY) {
			element_type = dbus_message_iter_get_element_type(&iter);
			uint8_t size = _tdbus_get_element_byte_size(element_type);
			uint32_t element_len = dbus_message_iter_get_element_count(&iter);

			total_size += (size * element_len) + 6;
		} else {
			total_size += 9;
		}

		dbus_message_iter_next(&iter);
	}

	uint8_t *payload = malloc(total_size);
	uint32_t index = 0;

	dbus_message_iter_init(message, &iter);

	while ((current_type = dbus_message_iter_get_arg_type(&iter)) != DBUS_TYPE_INVALID) {
		payload[index] = current_type;
		index++;

		if(current_type == DBUS_TYPE_STRING) {
			const char* value;

			dbus_message_iter_get_basic(&iter, &value);

			uint32_t element_len = strlen(value);

			memcpy(payload + index, &element_len, 4);
			index += 4;

			memcpy(payload + index, value, element_len);

			index += element_len;
		} else if(current_type == DBUS_TYPE_ARRAY) {
			uint8_t element_type = dbus_message_iter_get_element_type(&iter);
			uint8_t size = _tdbus_get_element_byte_size(element_type);
			uint32_t element_len = dbus_message_iter_get_element_count(&iter);

			payload[index] = element_type;
			index++;

			memcpy(payload + index, &element_len, 4);
			index += 4;

			void *value;

			DBusMessageIter sub_iter;
			dbus_message_iter_recurse(&iter, &sub_iter);

			dbus_message_iter_get_fixed_array(&sub_iter, &value, &element_len);

			memcpy(payload + index, value, size * element_len);

			index += size * element_len;
		} else {
			void *value = malloc(8);

			dbus_message_iter_get_basic(&iter, value);

			memcpy(payload + index, value, 8);

			index += 8;
		}

		dbus_message_iter_next(&iter);
	}

	uint32_t response_size = sizeof(sgx_aes_gcm_data_t) + total_size;
	uint8_t* response = malloc(response_size);
	sgx_status_t status = SGX_SUCCESS, status2 = SGX_SUCCESS;
	uint64_t uid = session->tdbus_connection->tdbus_uid;

	status2 = ecall_encrypt(session->tdbus_connection->tdbus_eid, session->tdbus_uid, payload, total_size, (sgx_aes_gcm_data_t*)response, response_size, &status);

	if(status != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _tdbus_enclave_error_translate(status));
		return NULL;
	}
	if(status2 != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _tdbus_enclave_error_translate(status2));
		return NULL;
	}

	TDBusMessage *ret = _tdbus_copy_message(message);

	dbus_message_append_args(ret, DBUS_TYPE_UINT64, &uid, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &response, response_size, DBUS_TYPE_INVALID);

	return ret;
}

TDBusMessage* _tdbus_decrypt_message(TDBusSession *session, TDBusMessage* message, DBusError *error) {
	if(dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_SIGNAL) {
		return message;
	}

	uint32_t len, payload_len, index = 0;
	uint64_t uid;
	uint8_t *cipher, *payload;
	sgx_status_t status = SGX_SUCCESS, status2 = SGX_SUCCESS;

	dbus_message_get_args(message, error, DBUS_TYPE_UINT64, &uid, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &cipher, &len, DBUS_TYPE_INVALID);

	if (dbus_error_is_set(error)) {
		return NULL;
	}

	payload_len = len - sizeof(sgx_aes_gcm_data_t);
	payload = malloc(payload_len);
	session->tdbus_uid = uid;

	status2 = ecall_decrypt(session->tdbus_connection->tdbus_eid, session->tdbus_uid, (sgx_aes_gcm_data_t*)cipher, len, payload, payload_len, &status);

	if(status != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _tdbus_enclave_error_translate(status));
		return NULL;
	}
	if(status2 != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _tdbus_enclave_error_translate(status2));
		return NULL;
	}

	TDBusMessage *ret = _tdbus_copy_message(message);

	if(payload_len <= 0) {
		return ret;
	}

	while(index < payload_len) {
		uint8_t current_type = payload[index];
		index++;

		if(current_type == DBUS_TYPE_STRING) {
			uint32_t element_len = 0;
			memcpy(&element_len, payload + index, 4);
			index += 4;

			char *value = malloc(element_len + 1);

			memcpy(value, payload + index, element_len);

			value[element_len] = '\0';

			dbus_message_append_args(ret, DBUS_TYPE_STRING, &value, DBUS_TYPE_INVALID);

			index += element_len;
		} else if(current_type == DBUS_TYPE_ARRAY) {
			uint8_t element_type = payload[index];
			index++;
			uint8_t size = _tdbus_get_element_byte_size(element_type);
			uint32_t element_len = 0;
			memcpy(&element_len, payload + index, 4);
			index += 4;

			void *value = malloc(size * element_len);

			memcpy(value, payload + index, size * element_len);

			dbus_message_append_args(ret, DBUS_TYPE_ARRAY, element_type, &value, element_len, DBUS_TYPE_INVALID);

			index += size * element_len;
		} else {
			void *value = malloc(8);

			memcpy(value, payload + index, 8);

			dbus_message_append_args(ret, current_type, value, DBUS_TYPE_INVALID);

			index += 8;
		}
	}

	return ret;
}

TDBusMessage* tdbus_message_new(int message_type) {
	return dbus_message_new(message_type);
}

TDBusMessage* tdbus_message_new_method_call(TDBusSession *session, const char *method) {
	return dbus_message_new_method_call(session->destination, session->path, session->iface, method);
}

TDBusMessage* tdbus_message_new_signal(TDBusSession *session, const char *name) {
	return dbus_message_new_signal(session->path, session->iface, name);
}

TDBusMessage* tdbus_message_new_method_return(TDBusMessage* message) {
	return dbus_message_new_method_return(message);
}

TDBusMessage* tdbus_message_new_error(DBusMessage *reply_to, const char *error_name, const char *error_message) {
	return dbus_message_new_error(reply_to, error_name, error_message);
}

dbus_bool_t tdbus_message_append_args(TDBusMessage *message, int first_arg_type, ...) {
	dbus_bool_t retval;
	va_list var_args;

	//_dbus_return_val_if_fail (message != NULL, FALSE);

	va_start (var_args, first_arg_type);
	retval = dbus_message_append_args_valist (message, first_arg_type, var_args);
	va_end (var_args);

	return retval;
}

dbus_bool_t tdbus_message_append_args_valist(TDBusMessage* message, int first_arg_type, va_list var_args) {
	return dbus_message_append_args_valist (message, first_arg_type, var_args);
}

TDBusMessage* tdbus_connection_send_with_reply_and_block(TDBusSession *session, TDBusMessage *message, int timeout_milliseconds, DBusError *error) {
	DBusMessage *msg = _tdbus_encrypt_message(session, message, error);

	if (dbus_error_is_set(error)) {
		return NULL;
	}

	DBusMessage *reply = dbus_connection_send_with_reply_and_block(session->tdbus_connection->tdbus_connection, msg, timeout_milliseconds, error);

	if (dbus_error_is_set(error)) {
		return NULL;
	}

	if(reply != NULL) {
		return _tdbus_decrypt_message(session, reply, error);
	} else {
		return NULL;
	}
}

dbus_bool_t tdbus_connection_send(TDBusSession *session, TDBusMessage* message, dbus_uint32_t* serial) {
	DBusError err;

	dbus_error_init(&err);

	DBusMessage *msg = _tdbus_encrypt_message(session, message, &err);

	return dbus_connection_send(session->tdbus_connection->tdbus_connection, msg, serial);
}

DBusHandlerResult _tdbus_server_message_handler(TDBusConnection *conn, DBusMessage *message, const TDBusObjectPathVTable* vtable, void* user_data) {
	DBusError err;
	DBusMessage *reply = NULL;
	uint64_t uid;
	sgx_status_t status, status2;

	dbus_error_init(&err);

	const char *iface = dbus_message_get_interface(message);

	if (dbus_message_is_method_call(message, iface, "tdbus_session_request")) {
		unsigned char response = 0;
		sgx_dh_msg1_t *dh_msg1 = malloc(sizeof(sgx_dh_msg1_t));
		uint64_t my_uid = conn->tdbus_uid;

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_UINT64, &uid, DBUS_TYPE_INVALID)) {
			goto fail;
		}

		status = ecall_session_request(conn->tdbus_eid, uid, dh_msg1, &status2);

		if (!(reply = dbus_message_new_method_return(message))) {
			goto fail;
		}

		if((status != SGX_SUCCESS) && (status2 != SGX_SUCCESS)) {
			my_uid = 0;

			if(status2 != SGX_SUCCESS) {
				status = status2;
			}
		}

		dbus_message_append_args(reply, DBUS_TYPE_UINT64, &my_uid, DBUS_TYPE_UINT32, &status, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dh_msg1, sizeof(sgx_dh_msg1_t), DBUS_TYPE_INVALID);
	} else if (dbus_message_is_method_call(message, iface, "tdbus_exchange_report")) {
		unsigned char response = 0;
		sgx_dh_msg2_t dh_msg2;
		sgx_dh_msg3_t *dh_msg3 = malloc(sizeof(sgx_dh_msg3_t));
		char *pReadData;
		int len;
		uint64_t my_uid = conn->tdbus_uid;

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_UINT64, &uid, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &pReadData, &len, DBUS_TYPE_INVALID)) {
			goto fail;
		}

		memcpy(&dh_msg2, pReadData, len);

		status = ecall_exchange_report(conn->tdbus_eid, uid, &dh_msg2, dh_msg3, &status2);

		if (!(reply = dbus_message_new_method_return(message))) {
			goto fail;
		}

		if((status != SGX_SUCCESS) && (status2 != SGX_SUCCESS)) {
			my_uid = 0;

			if(status2 != SGX_SUCCESS) {
				status = status2;
			}
		}

		dbus_message_append_args(reply, DBUS_TYPE_UINT64, &my_uid, DBUS_TYPE_UINT32, &status, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dh_msg3, sizeof(sgx_dh_msg3_t), DBUS_TYPE_INVALID);
	} else if (dbus_message_is_method_call(message, iface, "tdbus_close_session")) {
		unsigned char response = 0;

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_UINT64, &uid, DBUS_TYPE_INVALID)) {
			goto fail;
		} else {
			ecall_close_session(conn->tdbus_eid, uid);
		}
	} else {
		uint64_t teste;
		TDBusSession *session = malloc(sizeof(TDBusSession));
		session->tdbus_connection = conn;

		TDBusMessage *msg = _tdbus_decrypt_message(session, message, &err);

		if (dbus_error_is_set(&err)) {
			goto fail;
		} else {
			return vtable->message_function(session, msg, user_data);
		}
	}

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
	DBusHandlerResult result = DBUS_HANDLER_RESULT_HANDLED;
	if (!dbus_connection_send(conn->tdbus_connection, reply, NULL))
		result = DBUS_HANDLER_RESULT_NEED_MEMORY;
	dbus_message_unref(reply);

	return result;
}

void tdbus_main_loop_run(TDBusConnection *connection, const TDBusObjectPathVTable* vtable, void* user_data) {
	DBusMessage* msg;

	while (dbus_connection_read_write_dispatch(connection->tdbus_connection, -1)) {
		msg = dbus_connection_pop_message(connection->tdbus_connection);

		// loop again if we haven't got a message
		if (NULL == msg)
			continue;

		_tdbus_server_message_handler(connection, msg, vtable, user_data);

		// free the message
		dbus_message_unref(msg);
	}
}

dbus_bool_t tdbus_connection_register_object_path(TDBusConnection* connection, const char* path, const DBusObjectPathVTable* vtable, void* user_data) {
	return dbus_connection_register_object_path(connection->tdbus_connection, path, vtable, user_data);
}

void _tdbus_bus_close_session(TDBusSession *session, DBusError *error){
	sgx_status_t ret = SGX_SUCCESS;
	DBusMessage* reply;
	DBusMessage* msg;
	char *p_read_dh_msg3;
	int len_dh_msg3;

	msg = dbus_message_new_method_call(session->destination, session->path, session->iface, "tdbus_close_session");
	if (msg == NULL) {
		return;
	}

	dbus_message_append_args(msg, DBUS_TYPE_UINT64, &(session->tdbus_connection->tdbus_uid), DBUS_TYPE_INVALID);

	dbus_connection_send(session->tdbus_connection->tdbus_connection, msg, NULL);
}

void tdbus_bus_close_session(TDBusSession *session, DBusError *error) {
	if(!_tdbus_validate_session(session, error)) {
		return;
	}

	sgx_status_t ret = ecall_close_session(session->tdbus_connection->tdbus_eid, session->tdbus_uid);

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _tdbus_enclave_error_translate(ret));
		return;
	}

	_tdbus_bus_close_session(session, error);
}
