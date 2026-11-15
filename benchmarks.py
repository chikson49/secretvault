
import os
import time
import statistics

import encryption


# Benchmark configuration
SALT = os.urandom(encryption.SALT_LENGTH)
PASSPHRASE = "BenchmarkPassphrase123!"
AAD = b"secure-vault-benchmark-v1"

CIPHERS = [
    encryption.AES_CIPHER,
    encryption.CHACHA_CIPHER
]

DATA_SIZES = [
    1024,          # 1 KB
    10 * 1024,     # 10 KB
    100 * 1024,    # 100 KB
    1024 * 1024,   # 1 MB
    5 * 1024 * 1024  # 5 MB
]

REPETITIONS = {
    1024: 500,
    10 * 1024: 300,
    100 * 1024: 100,
    1024 * 1024: 30,
    5 * 1024 * 1024: 10
}

SAMPLES = 5


def measure_time(function, repetitions):

    measurements = []

    # Warm-up
    for _ in range(3):
        function()

    # Actual measurements
    for _ in range(SAMPLES):

        start = time.perf_counter()

        for _ in range(repetitions):
            function()

        end = time.perf_counter()

        average_time = (end - start) / repetitions

        measurements.append(average_time)

    return statistics.median(measurements)


def benchmark_kdf():

    print("\n===== PBKDF2 KEY DERIVATION =====")

    measurements = []

    for _ in range(7):

        start = time.perf_counter()

        key = encryption.derive_key(
            PASSPHRASE,
            SALT,
            encryption.ITERATIONS
        )

        end = time.perf_counter()

        measurements.append(end - start)

    average = statistics.median(measurements)

    print("KDF: PBKDF2-HMAC-SHA256")
    print("Iterations:", encryption.ITERATIONS)
    print("Key length:", len(key) * 8, "bits")
    print("Median derivation time:", round(average * 1000, 4), "ms")

    return key


def benchmark_cipher(cipher_name, key, plaintext):

    repetitions = REPETITIONS[len(plaintext)]

    # Verify correctness before benchmarking
    nonce, ciphertext = encryption.encrypt_data(
        key,
        plaintext,
        AAD,
        cipher_name
    )

    decrypted = encryption.decrypt_data(
        key,
        nonce,
        ciphertext,
        AAD,
        cipher_name
    )

    if decrypted != plaintext:
        raise RuntimeError("Encryption/decryption verification failed")

    # Benchmark encryption
    def encrypt_operation():

        encryption.encrypt_data(
            key,
            plaintext,
            AAD,
            cipher_name
        )

    encryption_time = measure_time(
        encrypt_operation,
        repetitions
    )

    # Benchmark decryption
    def decrypt_operation():

        encryption.decrypt_data(
            key,
            nonce,
            ciphertext,
            AAD,
            cipher_name
        )

    decryption_time = measure_time(
        decrypt_operation,
        repetitions
    )

    # Calculate throughput
    size_mb = len(plaintext) / (1024 * 1024)

    encryption_speed = size_mb / encryption_time
    decryption_speed = size_mb / decryption_time

    return {
        "encryption_ms": encryption_time * 1000,
        "decryption_ms": decryption_time * 1000,
        "encryption_mb_s": encryption_speed,
        "decryption_mb_s": decryption_speed
    }


def main():

    print("========================================")
    print(" AES-256-GCM vs CHACHA20-POLY1305")
    print(" PERFORMANCE BENCHMARK")
    print("========================================")

    print("\nIterations per measurement:", SAMPLES)

    # Measure PBKDF2 separately
    key = benchmark_kdf()

    results = []

    for size in DATA_SIZES:

        print("\n----------------------------------------")
        print("PLAINTEXT SIZE:", size, "bytes")
        print("----------------------------------------")

        plaintext = os.urandom(size)

        for cipher_name in CIPHERS:

            print("\nTesting:", cipher_name)

            result = benchmark_cipher(
                cipher_name,
                key,
                plaintext
            )

            result["cipher"] = cipher_name
            result["size_bytes"] = size

            results.append(result)

            print(
                "Encryption:",
                round(result["encryption_ms"], 4),
                "ms"
            )

            print(
                "Decryption:",
                round(result["decryption_ms"], 4),
                "ms"
            )

            print(
                "Encryption throughput:",
                round(result["encryption_mb_s"], 2),
                "MB/s"
            )

            print(
                "Decryption throughput:",
                round(result["decryption_mb_s"], 2),
                "MB/s"
            )

    print("\n========================================")
    print(" BENCHMARK COMPLETED")
    print("========================================")

    print("\nFINAL COMPARISON")

    print(
        f"{'Size':<12}"
        f"{'Cipher':<24}"
        f"{'Encrypt (ms)':<16}"
        f"{'Decrypt (ms)':<16}"
    )

    for result in results:

        print(
            f"{result['size_bytes']:<12}"
            f"{result['cipher']:<24}"
            f"{result['encryption_ms']:<16.4f}"
            f"{result['decryption_ms']:<16.4f}"
        )


if __name__ == "__main__":
    main()
