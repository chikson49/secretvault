
import os
import time
import statistics

import encryption


# ==========================================
# BENCHMARK CONFIGURATION
# ==========================================

SALT = os.urandom(encryption.SALT_LENGTH)
PASSPHRASE = "BenchmarkPassphrase123!"
AAD = b"secure-vault-benchmark-v1"

CIPHERS = [
    encryption.AES_CIPHER,
    encryption.CHACHA_CIPHER
]

DATA_SIZES = [
    1024,               # 1 KB
    10 * 1024,          # 10 KB
    100 * 1024,         # 100 KB
    1024 * 1024,        # 1 MB
    5 * 1024 * 1024     # 5 MB
]

REPETITIONS = {
    1024: 500,
    10 * 1024: 300,
    100 * 1024: 100,
    1024 * 1024: 30,
    5 * 1024 * 1024: 10
}

WARMUP_ROUNDS = 3
SAMPLES = 30


# ==========================================
# MEASUREMENT FUNCTION
# ==========================================

def measure_batch(function, repetitions):

    start = time.perf_counter()

    for _ in range(repetitions):
        function()

    end = time.perf_counter()

    return (end - start) / repetitions


def calculate_statistics(measurements):

    return {
        "median": statistics.median(measurements),
        "mean": statistics.mean(measurements),
        "stddev": statistics.stdev(measurements)
    }


# ==========================================
# PBKDF2 BENCHMARK
# ==========================================

def benchmark_kdf():

    print("\n===== PBKDF2 KEY DERIVATION =====")

    # Warm-up
    for _ in range(WARMUP_ROUNDS):
        encryption.derive_key(
            PASSPHRASE,
            SALT,
            encryption.ITERATIONS
        )

    measurements = []

    for _ in range(SAMPLES):

        start = time.perf_counter()

        key = encryption.derive_key(
            PASSPHRASE,
            SALT,
            encryption.ITERATIONS
        )

        end = time.perf_counter()

        measurements.append(end - start)

    stats = calculate_statistics(measurements)

    print("KDF: PBKDF2-HMAC-SHA256")
    print("Iterations:", encryption.ITERATIONS)
    print("Key length:", len(key) * 8, "bits")
    print("Samples:", SAMPLES)

    print(
        "Median:",
        round(stats["median"] * 1000, 4), "ms"
    )

    print(
        "Mean:",
        round(stats["mean"] * 1000, 4), "ms"
    )

    print(
        "Standard deviation:",
        round(stats["stddev"] * 1000, 4), "ms"
    )

    return key


# ==========================================
# CIPHER BENCHMARK
# ==========================================

def benchmark_size(size, key):

    plaintext = os.urandom(size)
    repetitions = REPETITIONS[size]

    print("\n----------------------------------------")
    print("PLAINTEXT SIZE:", size, "bytes")
    print("----------------------------------------")

    operations = {}
    measurements = {}

    # Prepare operations and verify correctness
    for cipher_name in CIPHERS:

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
            raise RuntimeError(
                f"Verification failed for {cipher_name}"
            )

        def encrypt_operation(cipher=cipher_name):
            encryption.encrypt_data(
                key,
                plaintext,
                AAD,
                cipher
            )

        def decrypt_operation(
            cipher=cipher_name,
            n=nonce,
            c=ciphertext
        ):
            encryption.decrypt_data(
                key,
                n,
                c,
                AAD,
                cipher
            )

        operations[cipher_name] = {
            "encrypt": encrypt_operation,
            "decrypt": decrypt_operation
        }

        measurements[cipher_name] = {
            "encrypt": [],
            "decrypt": []
        }

    # Warm-up both algorithms
    for _ in range(WARMUP_ROUNDS):

        for cipher_name in CIPHERS:

            operations[cipher_name]["encrypt"]()
            operations[cipher_name]["decrypt"]()

    # Alternate cipher order to reduce order bias
    for sample in range(SAMPLES):

        if sample % 2 == 0:
            test_order = CIPHERS
        else:
            test_order = list(reversed(CIPHERS))

        for cipher_name in test_order:

            encryption_time = measure_batch(
                operations[cipher_name]["encrypt"],
                repetitions
            )

            decryption_time = measure_batch(
                operations[cipher_name]["decrypt"],
                repetitions
            )

            measurements[cipher_name]["encrypt"].append(
                encryption_time
            )

            measurements[cipher_name]["decrypt"].append(
                decryption_time
            )

    results = []

    # Calculate final statistics
    for cipher_name in CIPHERS:

        enc_stats = calculate_statistics(
            measurements[cipher_name]["encrypt"]
        )

        dec_stats = calculate_statistics(
            measurements[cipher_name]["decrypt"]
        )

        size_mib = size / (1024 * 1024)

        result = {
            "cipher": cipher_name,
            "size_bytes": size,

            "encryption_ms":
                enc_stats["median"] * 1000,

            "encryption_mean_ms":
                enc_stats["mean"] * 1000,

            "encryption_stddev_ms":
                enc_stats["stddev"] * 1000,

            "decryption_ms":
                dec_stats["median"] * 1000,

            "decryption_mean_ms":
                dec_stats["mean"] * 1000,

            "decryption_stddev_ms":
                dec_stats["stddev"] * 1000,

            "encryption_mib_s":
                size_mib / enc_stats["median"],

            "decryption_mib_s":
                size_mib / dec_stats["median"]
        }

        results.append(result)

        print("\nTesting:", cipher_name)

        print(
            "Encryption median:",
            round(result["encryption_ms"], 4), "ms"
        )

        print(
            "Encryption mean:",
            round(result["encryption_mean_ms"], 4), "ms"
        )

        print(
            "Encryption standard deviation:",
            round(result["encryption_stddev_ms"], 4), "ms"
        )

        print(
            "Decryption median:",
            round(result["decryption_ms"], 4), "ms"
        )

        print(
            "Decryption mean:",
            round(result["decryption_mean_ms"], 4), "ms"
        )

        print(
            "Decryption standard deviation:",
            round(result["decryption_stddev_ms"], 4), "ms"
        )

        print(
            "Encryption throughput:",
            round(result["encryption_mib_s"], 2), "MiB/s"
        )

        print(
            "Decryption throughput:",
            round(result["decryption_mib_s"], 2), "MiB/s"
        )

    return results


# ==========================================
# MAIN
# ==========================================

def main():

    print("========================================")
    print(" AES-256-GCM vs CHACHA20-POLY1305")
    print(" PERFORMANCE BENCHMARK")
    print("========================================")

    print("Warm-up rounds:", WARMUP_ROUNDS)
    print("Measured samples:", SAMPLES)

    # PBKDF2 is measured separately
    key = benchmark_kdf()

    all_results = []

    for size in DATA_SIZES:

        results = benchmark_size(size, key)

        all_results.extend(results)

    # Final comparison
    print("\n========================================")
    print(" FINAL COMPARISON")
    print("========================================")

    print(
        f"{'Size':<12}"
        f"{'Cipher':<24}"
        f"{'Encrypt ms':<14}"
        f"{'Decrypt ms':<14}"
    )

    for result in all_results:

        print(
            f"{result['size_bytes']:<12}"
            f"{result['cipher']:<24}"
            f"{result['encryption_ms']:<14.4f}"
            f"{result['decryption_ms']:<14.4f}"
        )

    print("\nBenchmark completed successfully.")


if __name__ == "__main__":
    main()
