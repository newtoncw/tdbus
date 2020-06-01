######### SGX TOOLS ######################
SGX_SDK ?= /opt/Intel/sgxsdk
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

######## App Settings ########
App_C_Flags := -fPIC -Wno-attributes -IInclude -IApp -I$(SGX_SDK)/include -I/usr/include/dbus-1.0 -I/usr/lib/x86_64-linux-gnu/dbus-1.0/include -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include
App_Link_Flags := -L$(SGX_LIBRARY_PATH) -lsgx_urts -lpthread -lsgx_uae_service
CFLAGS_DBUS = $(shell pkg-config --cflags --libs dbus-1)
CFLAGS_DBUS_GLIB = $(shell pkg-config --cflags --libs dbus-glib-1)
CFLAGS_GIO  = $(shell pkg-config --cflags --libs gio-2.0)

######## Enclave Settings ########
Enclave_C_Flags := -nostdinc -fvisibility=hidden -fpie -fstack-protector -IInclude -IEnclave \
	-I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport

Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tcrypto -lsgx_tservice -Wl,--end-group \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0
	
Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := enclave.config.xml

.PHONY: all run

all: $(Signed_Enclave_Name) test_client test_server

run: all


######## App Objects ########
enclave_u.c: $(SGX_EDGER8R) enclave.edl
	$(SGX_EDGER8R) --untrusted enclave.edl --search-path $(SGX_SDK)/include

enclave_u.o: enclave_u.c 
	gcc $(App_C_Flags) -c $< -o $@ -g

tdbus.o: tdbus.c
	gcc $(App_C_Flags) -c $< -o $@ -g
	
test_client.o: test_client.c
	gcc $(App_C_Flags) -c $< -o $@ -g 

test_server.o: test_server.c
	gcc $(App_C_Flags) -c $< -o $@ -g

test_client: enclave_u.o test_client.o tdbus.o
	gcc $^ -o $@ $(App_Link_Flags) $(CFLAGS_DBUS)

test_server: enclave_u.o test_server.o tdbus.o
	gcc $^ -o $@ $(App_Link_Flags) $(CFLAGS_DBUS)

####### Enclave Objects ########
enclave_t.c: $(SGX_EDGER8R) enclave.edl
	$(SGX_EDGER8R) --trusted enclave.edl --search-path $(SGX_SDK)/include

enclave_t.o: enclave_t.c 
	gcc $(Enclave_C_Flags) -c $< -o $@ -g

enclave.o: enclave.c
	gcc $(Enclave_C_Flags) -c $< -o $@ -g

$(Enclave_Name): enclave_t.o enclave.o
	gcc $^ -o $@ $(Enclave_Link_Flags) -g

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)


.PHONY: clean

clean:
	@rm -f *.o test_client test_server $(Enclave_Name) $(Signed_Enclave_Name)

