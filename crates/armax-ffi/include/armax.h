/* ARMax — interfaz C del nodo. Ver crates/armax-ffi/src/lib.rs para la semántica completa. */
#ifndef ARMAX_H
#define ARMAX_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define ARMAX_OK           0
#define ARMAX_ERR_ARG     -1
#define ARMAX_ERR_BUFFER  -2
#define ARMAX_ERR_VAULT   -3
#define ARMAX_ERR_WALLET  -4
#define ARMAX_ERR_NODE    -5
#define ARMAX_ERR_PANIC   -6

/* Callback de bóveda (Android Keystore): lee input, escribe en out, deja los bytes en *out_len. 0 = ok. */
typedef int32_t (*armax_vault_fn)(void *ctx, const uint8_t *input, size_t input_len,
                                  uint8_t *out, size_t out_cap, size_t *out_len);
typedef struct { void *ctx; armax_vault_fn seal; armax_vault_fn open; } ArmaxVault;

int32_t armax_version(char *out, size_t cap);
int32_t armax_last_error(char *out, size_t cap);

int32_t armax_wallet_create(const ArmaxVault *vault, char *mnemonic_out, size_t mnemonic_cap,
                            uint8_t *sealed_out, size_t sealed_cap, size_t *sealed_len);
int32_t armax_wallet_restore(const ArmaxVault *vault, const char *mnemonic,
                             uint8_t *sealed_out, size_t sealed_cap, size_t *sealed_len);
int32_t armax_wallet_address(const ArmaxVault *vault, const uint8_t *sealed, size_t sealed_len,
                             char *out, size_t cap);

int32_t armax_node_start(const char *config_json, const ArmaxVault *vault,
                         const uint8_t *sealed, size_t sealed_len, void **out_handle);
int32_t armax_node_status(void *handle, char *out, size_t cap);
int32_t armax_node_history(void *handle, uint32_t limit, char *out, size_t cap);
int32_t armax_node_send(void *handle, const char *to, uint64_t amount_units, uint64_t fee_units,
                        char *out, size_t cap);
int32_t armax_node_push_sensors(void *handle, double battery_temp_c, int32_t charging,
                                int32_t battery_pct, int32_t screen_on, int64_t mem_available_mib);
int32_t armax_node_stop(void *handle);
int32_t armax_parse_amount(const char *text, uint64_t *out_units);

#ifdef __cplusplus
}
#endif
#endif
