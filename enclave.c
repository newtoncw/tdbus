#include "sgx_tseal.h"
#include "sgx_trts.h"
#include "sgx_report.h"
#include "sgx_spinlock.h"
#include "sgx_ecp_types.h"
#include "sgx_dh.h"
#include "sgx_eid.h"
#include <string.h>

#define SESSION_COUNT 200

typedef struct {
	uint64_t uid;
	uint8_t status; //0 - closed; 1 - in progress; 2 - active
	sgx_dh_session_t dh_session;
	sgx_key_128bit_t session_dh_aek; //Session Key
} tdbus_session_t;

typedef struct tdbus_session_item *tdbus_session_pointer_t;

typedef struct tdbus_session_item {
	tdbus_session_t session;
	tdbus_session_pointer_t next;	
} tdbus_session_item_t;

typedef struct {
	tdbus_session_pointer_t first;
	tdbus_session_pointer_t last;
} session_list_t;

session_list_t _tdbus_sessions;

uint64_t uid = 0;

sgx_spinlock_t lock = SGX_SPINLOCK_INITIALIZER;

void init_sessions(void) {
	_tdbus_sessions.first = (tdbus_session_pointer_t) malloc(sizeof(tdbus_session_item_t));
	_tdbus_sessions.first->next = NULL;
	_tdbus_sessions.last = _tdbus_sessions.first;
}

int session_list_empty(void) {
	return (_tdbus_sessions.first == _tdbus_sessions.last);
}

int find_session(uint64_t uid, tdbus_session_t** session) {
	if(session_list_empty() || (uid == 0)) {
		return 0;
	}

	tdbus_session_item_t* s = _tdbus_sessions.first->next;
	while (s != NULL) {
		if(s->session.uid == uid) {
			*session = &(s->session);

			return 1;
		}

		s = s->next;
	}

	return 0;
}

sgx_dh_session_t *get_dh_session(uint64_t uid) {
	tdbus_session_t *session;

	if(find_session(uid, &session)) {
		return &(session->dh_session);
	} else {
		return NULL;
	}
}

sgx_key_128bit_t *get_session_aek(uint64_t uid) {
	tdbus_session_t *session;

	if(find_session(uid, &session)) {
		return &(session->session_dh_aek);
	} else {
		return NULL;
	}
}

void set_dh_session(uint64_t uid, sgx_dh_session_t *dh_session) {
	sgx_spin_lock(&lock);

	tdbus_session_t session;

	session.uid = uid;
	session.status = 1;
	memcpy(&(session.dh_session), dh_session, sizeof(sgx_dh_session_t));

	_tdbus_sessions.last->next = (tdbus_session_pointer_t) malloc(sizeof(tdbus_session_item_t));
	_tdbus_sessions.last = _tdbus_sessions.last->next;
	_tdbus_sessions.last->session = session;
	_tdbus_sessions.last->next = NULL;

	sgx_spin_unlock(&lock);
}

void set_session_aek(uint64_t uid, sgx_key_128bit_t *session_dh_aek) {
	sgx_spin_lock(&lock);

	tdbus_session_t *session;

	if(find_session(uid, &session)) {
		session->status = 2;
		memcpy(&(session->session_dh_aek), session_dh_aek, sizeof(sgx_key_128bit_t));
	}

	sgx_spin_unlock(&lock);
}

void close_session(uint64_t uid) {
	sgx_spin_lock(&lock);

	tdbus_session_item_t* s = _tdbus_sessions.first;

	while (s->next != NULL) {
		if(s->next->session.uid == uid) {
			tdbus_session_item_t* s2 = s->next;

			s->next = s->next->next;

			if(s->next == NULL) {
				_tdbus_sessions.last = s;
			}

			free(s2);

			break;
		}

		s = s->next;
	}

	sgx_spin_unlock(&lock);
}

void ecall_enclave_init(uint64_t *unique_id) {
	sgx_read_rand((unsigned char *)&uid, 4);

	init_sessions();

	*unique_id = uid;
}

void ecall_teste(uint64_t *unique_id) {
	*unique_id = uid;
}

void ecall_session_request(uint64_t uid, sgx_dh_msg1_t *dh_msg1, sgx_status_t *ret) {
	sgx_status_t status = SGX_SUCCESS;
	sgx_dh_session_t sgx_dh_session;

	if(dh_msg1 == NULL) {
		*ret = SGX_ERROR_INVALID_PARAMETER;
		return;
	}

	status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
	if(status != SGX_SUCCESS) {
		*ret = status;
		return;
	}

	status = sgx_dh_responder_gen_msg1(dh_msg1, &sgx_dh_session);
	if(status != SGX_SUCCESS) {
		*ret = status;
		return;
	}

	set_dh_session(uid, &sgx_dh_session);
}

void ecall_exchange_report(uint64_t uid, sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, sgx_status_t *ret) {
	sgx_key_128bit_t dh_aek;
	sgx_dh_session_enclave_identity_t initiator_identity;
	sgx_dh_session_t *sgx_dh_session = get_dh_session(uid);

	if(sgx_dh_session == NULL) {
		*ret = SGX_ERROR_INVALID_PARAMETER;
		return;
	}

	sgx_status_t status = sgx_dh_responder_proc_msg2(dh_msg2, dh_msg3, sgx_dh_session, &dh_aek, &initiator_identity);
	if(status != SGX_SUCCESS) {
		*ret = status;
		return;
	}

	set_session_aek(uid, &dh_aek);
}

void ecall_init_session(sgx_dh_session_t *session, sgx_status_t *status) {
	*status = sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, session);
}

void ecall_initiator_proc_msg1(uint64_t uid, const sgx_dh_msg1_t *msg1, sgx_dh_msg2_t *msg2, sgx_dh_session_t *dh_session, sgx_status_t *status) {
	*status = sgx_dh_initiator_proc_msg1(msg1, msg2, dh_session);

	set_dh_session(uid, dh_session);
}

void ecall_initiator_proc_msg3(uint64_t uid, const sgx_dh_msg3_t *msg3, sgx_dh_session_t *dh_session, sgx_status_t *status) {
	sgx_key_128bit_t dh_aek;
	sgx_dh_session_enclave_identity_t responder_identity;

	*status = sgx_dh_initiator_proc_msg3(msg3, dh_session, &dh_aek, &responder_identity);

	set_session_aek(uid, &dh_aek);
}

void ecall_close_session(uint64_t uid) {
	close_session(uid);
}

void ecall_encrypt(uint64_t uid, uint8_t* message, size_t message_size, sgx_aes_gcm_data_t* response, size_t response_size, sgx_status_t *status) {
	sgx_key_128bit_t *session_dh_aek = get_session_aek(uid);

	response->payload_size = message_size;

	*status = sgx_rijndael128GCM_encrypt(session_dh_aek, message, message_size, response->payload, response->reserved, sizeof(response->reserved), NULL, 0, &(response->payload_tag));
}

void ecall_decrypt(uint64_t uid, sgx_aes_gcm_data_t* message, size_t message_size, uint8_t* response, size_t response_size, sgx_status_t *status) {
	sgx_key_128bit_t *session_dh_aek = get_session_aek(uid);

	*status = sgx_rijndael128GCM_decrypt(session_dh_aek, message->payload, message->payload_size, response, message->reserved, sizeof(message->reserved), NULL, 0, &(message->payload_tag));	
}
