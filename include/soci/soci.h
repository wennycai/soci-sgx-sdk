#ifndef SOCI_SDK_H
#define SOCI_SDK_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define SOCI_API_VERSION 1u
#define SOCI_SECURITY_128_MODULUS_BITS 3072u
typedef struct soci_runtime soci_runtime_t;
typedef enum { SOCI_OK=0, SOCI_INVALID_ARGUMENT=1, SOCI_INVALID_STATE=2,
  SOCI_NOT_FOUND=3, SOCI_IO_ERROR=4, SOCI_CRYPTO_ERROR=5,
  SOCI_UNSUPPORTED=6, SOCI_BUFFER_TOO_SMALL=7, SOCI_INTERNAL_ERROR=8 } soci_status_t;
typedef enum { SOCI_MODE_OFF=0, SOCI_MODE_SIM=1, SOCI_MODE_HW=2 } soci_mode_t;
typedef enum { SOCI_ROLE_FULL=0, SOCI_ROLE_CP=1, SOCI_ROLE_CSP=2 } soci_role_t;

typedef struct {
  uint32_t struct_version;
  uint32_t modulus_bits;
  uint64_t key_version;
  soci_role_t role;
  soci_mode_t runtime_mode;
  char key_id[65];
} soci_key_info_t;

const char* soci_get_version(void);
soci_status_t soci_runtime_create(const char* runtime_dir, soci_runtime_t** out);
void soci_runtime_close(soci_runtime_t* runtime);
soci_mode_t soci_runtime_get_mode(const soci_runtime_t* runtime);
const char* soci_runtime_get_last_error(const soci_runtime_t* runtime);
soci_status_t soci_create_key(soci_runtime_t*, const char* key_id, uint32_t bits, soci_role_t);
soci_status_t soci_open_key(soci_runtime_t*, const char* key_id, soci_role_t);
soci_status_t soci_rotate_key(soci_runtime_t*, const char* key_id);
soci_status_t soci_delete_key(soci_runtime_t*, const char* key_id);
soci_status_t soci_get_key_info(soci_runtime_t*, soci_key_info_t*);
soci_status_t soci_export_public_key(soci_runtime_t*, uint8_t*, size_t*);
soci_status_t soci_encrypt(soci_runtime_t*, const char*, uint8_t*, size_t*);
soci_status_t soci_decrypt(soci_runtime_t*, const uint8_t*, size_t, char*, size_t*);
soci_status_t soci_add(soci_runtime_t*, const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t*);
soci_status_t soci_scalar_mul(soci_runtime_t*, const uint8_t*, size_t, const char*, uint8_t*, size_t*);
soci_status_t soci_secure_mul(soci_runtime_t*, const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t*);
soci_status_t soci_secure_compare(soci_runtime_t*, const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t*);
soci_status_t soci_secure_sign_bit(soci_runtime_t*, const uint8_t*, size_t, uint8_t*, size_t*);
soci_status_t soci_secure_abs(soci_runtime_t*, const uint8_t*, size_t, uint8_t*, size_t*);
soci_status_t soci_secure_div(soci_runtime_t*, const uint8_t*, size_t, const uint8_t*, size_t,
                              uint8_t*, size_t*, uint8_t*, size_t*);
soci_status_t soci_start_cp_service(soci_runtime_t*);
soci_status_t soci_stop_cp_service(soci_runtime_t*);
soci_status_t soci_start_csp_service(soci_runtime_t*);
soci_status_t soci_stop_csp_service(soci_runtime_t*);
soci_status_t soci_health_check(soci_runtime_t*);
#ifdef __cplusplus
}
#endif
#endif
