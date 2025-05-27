#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/bn.h>

// Функция для обработки ошибок OpenSSL
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    // Инициализация OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // 1. Выбор эллиптической кривой (NID_secp256k1 - Bitcoin's curve)
    int curve_nid = NID_secp256k1; // Или другой NID (например, NID_X9_62_prime256v1)
    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(curve_nid);
    if (!ec_group) handleErrors();

    // 2. Генерация ключей для Алисы
    EC_KEY *alice_key = EC_KEY_new();
    if (!alice_key) handleErrors();
    if (EC_KEY_set_group(alice_key, ec_group) != 1) handleErrors();
    if (EC_KEY_generate_key(alice_key) != 1) handleErrors();

    // 3. Генерация ключей для Боба
    EC_KEY *bob_key = EC_KEY_new();
    if (!bob_key) handleErrors();
    if (EC_KEY_set_group(bob_key, ec_group) != 1) handleErrors();
    if (EC_KEY_generate_key(bob_key) != 1) handleErrors();

    // 4. Получение общего секрета Алисой
    // Получаем публичный ключ Боба (EC_POINT)
    const EC_POINT *bob_public_key = EC_KEY_get0_public_key(bob_key);
    if (!bob_public_key) handleErrors();

    // Выделяем буфер для общего секрета
    size_t shared_secret_size = EC_GROUP_get_degree(ec_group);
    unsigned char *alice_shared_secret = (unsigned char *)malloc(shared_secret_size);
    if (!alice_shared_secret) handleErrors();

    // Вычисляем общий секрет
    int result = ECDH_compute_key(alice_shared_secret, shared_secret_size,
                                    bob_public_key, alice_key, NULL);
    if (result != shared_secret_size) handleErrors();

    printf("Alice's shared secret: ");
    for (int i = 0; i < result; i++) {
        printf("%02x", alice_shared_secret[i]);
    }
    printf("\n");

    // 5. Получение общего секрета Бобом (аналогично)
    const EC_POINT *alice_public_key = EC_KEY_get0_public_key(alice_key);
    if (!alice_public_key) handleErrors();

    unsigned char *bob_shared_secret = (unsigned char *)malloc(shared_secret_size);
    if (!bob_shared_secret) handleErrors();

    result = ECDH_compute_key(bob_shared_secret, shared_secret_size,
                                alice_public_key, bob_key, NULL);
    if (result != shared_secret_size) handleErrors();

     printf("Bob's shared secret: ");
    for (int i = 0; i < result; i++) {
        printf("%02x", bob_shared_secret[i]);
    }
    printf("\n");

    // 6. Сравнение общих секретов (должны быть одинаковыми)
    if (memcmp(alice_shared_secret, bob_shared_secret, shared_secret_size) == 0) {
        printf("Shared secrets match!\n");
    } else {
        printf("Shared secrets do NOT match!\n");
    }

    // Очистка памяти
    free(alice_shared_secret);
    free(bob_shared_secret);
    EC_KEY_free(alice_key);
    EC_KEY_free(bob_key);
    EC_GROUP_free(ec_group);
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}