import time
import random
import matplotlib.pyplot as plt
from itertools import product

# ------------------------------------------------------------
# STUDENT SETTINGS
# ------------------------------------------------------------

q = 97                 # modulus
dimension = 4          # number of secret values
samples = 20           # number of equations
noise_size = 4         # error range: -noise_size to +noise_size

# Set secret bound as q-1 for larger/harder secret
# Set secret bound 12 for success in brute force attack
secret_bound = q - 1    

show_secret = True     # set False if you want to attack blindly

# ------------------------------------------------------------
# 1. Generate LWE System
# ------------------------------------------------------------

def generate_lwe(q, dimension, samples, noise_size, secret_bound):
    """
    Creates a simplified LWE system:

        b = A*s + e mod q

    A is public.
    b is public.
    s is the secret key.
    e is the small error/noise.
    """

    s = vector(ZZ, [random.randint(1, secret_bound) for _ in range(dimension)])

    A_rows = []
    clean_outputs = []
    noisy_outputs = []
    errors = []

    for i in range(samples):
        row = [random.randint(0, q - 1) for _ in range(dimension)]
        e = random.randint(-noise_size, noise_size)

        clean_b = sum(row[j] * s[j] for j in range(dimension)) % q
        noisy_b = (clean_b + e) % q

        A_rows.append(row)
        clean_outputs.append(clean_b)
        noisy_outputs.append(noisy_b)
        errors.append(e)

    A = Matrix(ZZ, A_rows)
    b = vector(ZZ, noisy_outputs)

    return A, b, s, errors, clean_outputs, noisy_outputs


# ------------------------------------------------------------
# 2. Known-Key Decryption / Recovery ## FIX THIS... MATRIX INVERSE... A ISNT INVERT?... HOW CAN I DECRYPT NOT ATTACK...
# ------------------------------------------------------------

def decrypt_with_secret_key(A, b, s, q, noise_size):
    """
    If the secret key s is known, we can recompute A*s mod q.

    This does not remove the noise from b directly, but it shows that the
    person who knows s can verify the clean outputs and measure the error.
    """

    recovered_clean_outputs = []
    recovered_errors = []
    successful_checks = 0

    for i in range(A.nrows()):
        clean_value = int(sum(A[i, j] * s[j] for j in range(A.ncols())) % q)
        noisy_value = int(b[i])

        error = (noisy_value - clean_value) % q

        # Convert modular error back into a small signed error
        if error > q // 2:
            error = error - q

        recovered_clean_outputs.append(clean_value)
        recovered_errors.append(error)

        if -noise_size <= error <= noise_size:
            successful_checks += 1

    success_rate = successful_checks / A.nrows()

    return recovered_clean_outputs, recovered_errors, success_rate


# ------------------------------------------------------------
# 3. Attack Methods
# ------------------------------------------------------------

def get_best_secret(possible_secrets):
    if len(possible_secrets) > 0:
        return possible_secrets[0][0], possible_secrets[0][1]
    return None, None


def check_candidate_secret(A, b, candidate, q, noise_size):
    score = 0

    for i in range(A.nrows()):
        predicted = int(sum(A[i, j] * candidate[j] for j in range(A.ncols())) % q)
        difference = int((b[i] - predicted) % q)

        if difference <= noise_size or difference >= q - noise_size:
            score += 1

    return score / A.nrows()


def linear_algebra_attack(A, b, q, dimension, noise_size):
    start = time.time()

    result = {
        "name": "Linear Algebra",
        "success": False,
        "possible_secrets": [],
        "recovered_secret": None,
        "accuracy": None,
        "checked": 0,
        "time": 0,
        "reason": ""
    }

    if A.nrows() != A.ncols():
        result["reason"] = "A is not square, so A^-1*b cannot be computed."
        result["time"] = time.time() - start
        return result

    try:
        A_mod = Matrix(GF(q), A)
        b_mod = vector(GF(q), list(b))

        if A_mod.det() == 0:
            result["reason"] = "A is square but not invertible modulo q."
            result["time"] = time.time() - start
            return result

        candidate = A_mod.inverse() * b_mod
        candidate_tuple = tuple(int(x) for x in candidate)

        accuracy = check_candidate_secret(A, b, candidate_tuple, q, noise_size)

        if accuracy >= 0.85:
            result["success"] = True
            result["possible_secrets"].append((candidate_tuple, round(accuracy, 3)))
            result["recovered_secret"] = candidate_tuple
            result["accuracy"] = round(accuracy, 3)
            result["reason"] = "A was square and invertible, and the recovered secret matched the noisy equations."
        else:
            result["reason"] = "A^-1*b produced a candidate, but noise prevented exact recovery."

    except:
        result["reason"] = "Linear algebra attack failed."

    result["time"] = time.time() - start
    return result


def brute_force_attack_method(A, b, q, dimension, noise_size, search_limit=12):
    start = time.time()

    possible_secrets = []
    total_checked = 0
    search_values = list(range(1, min(q, search_limit + 1)))

    for guess_tuple in product(search_values, repeat=dimension):
        total_checked += 1
        accuracy = check_candidate_secret(A, b, guess_tuple, q, noise_size)

        if accuracy >= 0.85:
            possible_secrets.append((guess_tuple, round(accuracy, 3)))

    recovered_secret, recovered_accuracy = get_best_secret(possible_secrets)

    return {
        "name": "Brute Force",
        "success": len(possible_secrets) > 0,
        "possible_secrets": possible_secrets,
        "recovered_secret": recovered_secret,
        "accuracy": recovered_accuracy,
        "checked": total_checked,
        "time": time.time() - start,
        "reason": "Brute force checks every possible secret in the search range."
    }


def lll_toy_attack(A, b, q, dimension, noise_size, search_limit=12):
    start = time.time()

    possible_secrets = []
    total_checked = 0
    search_values = list(range(1, min(q, search_limit + 1)))

    for guess_tuple in product(search_values, repeat=dimension):
        total_checked += 1
        errors = []

        for i in range(A.nrows()):
            predicted = int(sum(A[i, j] * guess_tuple[j] for j in range(dimension)) % q)
            difference = int((b[i] - predicted) % q)

            if difference > q // 2:
                difference -= q

            errors.append(difference)

        error_size = sum(abs(e) for e in errors)
        accuracy = check_candidate_secret(A, b, guess_tuple, q, noise_size)

        if accuracy >= 0.85 and error_size <= A.nrows() * noise_size:
            possible_secrets.append((guess_tuple, round(accuracy, 3)))

    recovered_secret, recovered_accuracy = get_best_secret(possible_secrets)

    return {
        "name": "LLL / Lattice-Style Toy Attack",
        "success": len(possible_secrets) > 0,
        "possible_secrets": possible_secrets,
        "recovered_secret": recovered_secret,
        "accuracy": recovered_accuracy,
        "checked": total_checked,
        "time": time.time() - start,
        "reason": "This toy version searches for secrets that create small error vectors."
    }


def bkw_toy_attack(A, b, q, dimension, noise_size, search_limit=12):
    start = time.time()

    possible_secrets = []
    total_checked = 0
    search_values = list(range(1, min(q, search_limit + 1)))

    for guess_tuple in product(search_values, repeat=dimension):
        total_checked += 1
        accuracy = check_candidate_secret(A, b, guess_tuple, q, noise_size)

        if accuracy >= 0.85:
            possible_secrets.append((guess_tuple, round(accuracy, 3)))

    recovered_secret, recovered_accuracy = get_best_secret(possible_secrets)

    return {
        "name": "BKW-Style Toy Attack",
        "success": len(possible_secrets) > 0,
        "possible_secrets": possible_secrets,
        "recovered_secret": recovered_secret,
        "accuracy": recovered_accuracy,
        "checked": total_checked,
        "time": time.time() - start,
        "reason": "This toy version models BKW by testing whether guessed secrets keep errors small."
    }


def hybrid_attack(A, b, q, dimension, noise_size, search_limit=12):
    start = time.time()

    possible_secrets = []
    total_checked = 0
    split = dimension // 2
    search_values = list(range(1, min(q, search_limit + 1)))

    for first_half in product(search_values, repeat=split):
        for second_half in product(search_values, repeat=dimension - split):
            guess_tuple = first_half + second_half
            total_checked += 1

            accuracy = check_candidate_secret(A, b, guess_tuple, q, noise_size)

            if accuracy >= 0.85:
                possible_secrets.append((guess_tuple, round(accuracy, 3)))

    recovered_secret, recovered_accuracy = get_best_secret(possible_secrets)

    return {
        "name": "Hybrid Attack",
        "success": len(possible_secrets) > 0,
        "possible_secrets": possible_secrets,
        "recovered_secret": recovered_secret,
        "accuracy": recovered_accuracy,
        "checked": total_checked,
        "time": time.time() - start,
        "reason": "This toy hybrid attack combines partial guessing with an error check."
    }


def run_all_attacks(A, b, q, dimension, noise_size, search_limit=12):
    attacks = [
        linear_algebra_attack(A, b, q, dimension, noise_size),
        brute_force_attack_method(A, b, q, dimension, noise_size, search_limit),
        lll_toy_attack(A, b, q, dimension, noise_size, search_limit),
        bkw_toy_attack(A, b, q, dimension, noise_size, search_limit),
        hybrid_attack(A, b, q, dimension, noise_size, search_limit)
    ]

    successful_attacks = [attack for attack in attacks if attack["success"]]

    if len(successful_attacks) == 0:
        fastest = None
    else:
        fastest = min(successful_attacks, key=lambda attack: attack["time"])

    return attacks, successful_attacks, fastest


# ------------------------------------------------------------
# 4. Parameter Diagnosis
# ------------------------------------------------------------

def explain_parameters(q, dimension, samples, noise_size, A):
    print("\nPARAMETER ANALYSIS")
    print("-" * 60)

    if noise_size == 0:
        print("System Status: BROKEN")
        print("Reason: Noise is zero, so the clean and noisy equations are identical.")
        print("Without noise, the system behaves more like ordinary linear algebra.")

    elif noise_size == 1:
        print("System Status: WEAK")
        print("Reason: Noise is very small, so the secret is only lightly hidden.")

    elif noise_size >= q - 1:
        print("System Status: UNRELIABLE")
        print("Reason: Noise is almost the same size as q.")
        print("This makes many different secret vectors look correct.")
        print("The attack may return an incorrect secret because the system is too ambiguous.")

    elif noise_size >= q // 2:
        print("System Status: VERY UNRELIABLE")
        print("Reason: Noise is very large compared to q.")
        print("Large noise can make several different secrets satisfy the same noisy equations.")

    elif noise_size > q // 4:
        print("System Status: UNRELIABLE")
        print("Reason: Noise is too large compared to q.")
        print("The secret may be hidden, but attack recovery can become unreliable.")

    else:
        print("Noise Status: Reasonable for a classroom demo.")
        print("Reason: The error hides the exact equation while staying close to the clean output.")

    if q < 20:
        print("\nModulus Warning: q is very small.")
    else:
        print("\nModulus Status: q is acceptable for this demo.")

    if dimension <= 2:
        print("\nDimension Note: Dimension is small enough for brute force.")
    else:
        print("\nDimension Note: Higher dimension increases the search space.")

    if samples < dimension:
        print("\nSample Warning: Fewer samples than secret dimensions.")
        print("Reason: There may not be enough equations to identify the secret.")
    else:
        print("\nSample Status: Good for classroom testing.")

    print("\nMatrix Shape Check:")
    print("A has", A.nrows(), "rows and", A.ncols(), "columns.")

    if A.nrows() != A.ncols():
        print("A is not square, so it does not have a normal inverse.")
        print("This means we cannot recover s by simply computing A^-1 * b.")
        print("This is normal in LWE because A is often rectangular.")
    else:
        print("A is square, so invertibility can be checked.")

        try:
            A_mod = Matrix(GF(q), A)

            if A_mod.det() != 0:
                print("A is invertible modulo q.")

                if noise_size == 0:
                    print("Since noise is zero, s could be recovered using A^-1 * b.")
                else:
                    print("However, since noise is present, A^-1 * b may not recover the true s exactly.")
            else:
                print("A is square but not invertible modulo q.")

        except:
            print("Could not check invertibility modulo q.")

# ------------------------------------------------------------
# 5. Run Full Demo
# ------------------------------------------------------------

print("=" * 60)
print("POST-QUANTUM SECURITY: LWE VISUALIZATION LAB")
print("=" * 60)

A, b, s, errors, clean_outputs, noisy_outputs = generate_lwe(
    q, dimension, samples, noise_size, secret_bound
)

print("\nPUBLIC INFORMATION")
print("-" * 60)
print("q =", q)
print("dimension =", dimension)
print("samples =", samples)
print("noise_size =", noise_size)

print("\nPublic matrix A:")
print(A)

print("\nPublic vector b, noisy outputs:")
print(b)

print("\nSTUDENT OUTPUT TABLE VALUES")
print("-" * 60)
print("Public Matrix A, first row:", A[0])
print("Error Values:", errors)
print("Clean Outputs:", clean_outputs)
print("Noisy Outputs:", noisy_outputs)

if show_secret:
    print("\nSECRET INFORMATION")
    print("-" * 60)
    print("Secret vector s =", s)
else:
    print("\nSecret is hidden for student attack.")

explain_parameters(q, dimension, samples, noise_size, A)


# ------------------------------------------------------------
# 6. Known-Key Decryption / Recovery
# ------------------------------------------------------------

print("\nKNOWN-KEY DECRYPTION / RECOVERY")
print("-" * 60)

recovered_clean, recovered_errors, success_rate = decrypt_with_secret_key(
    A, b, s, q, noise_size
)

print("Recovered clean outputs using secret key:")
print(recovered_clean)

print("\nRecovered error values:")
print(recovered_errors)

print("\nKnown-key recovery success rate:", round(success_rate * 100, 2), "%")

if success_rate == 1:
    print("Decryption Result: SUCCESS")
    print("Reason: Knowing the secret key allows the system to verify the noisy outputs.")
else:
    print("Decryption Result: PARTIAL FAILURE")
    print("Reason: Some recovered errors were outside the expected noise range.")


# ------------------------------------------------------------
# 7. Attack Results
# ------------------------------------------------------------

print("\nATTACK RESULTS")
print("-" * 60)

attacks, successful_attacks, fastest_attack = run_all_attacks(
    A, b, q, dimension, noise_size, search_limit=12
)

if fastest_attack is None:
    print("Fastest Successful Attack: None")
    print("Attack Result: FAILURE")
    print("Reason: No attack successfully recovered a likely secret.")

else:
    print("Fastest Successful Attack:", fastest_attack["name"])
    print("Recovered Secret:", fastest_attack["recovered_secret"])
    print("Accuracy:", fastest_attack["accuracy"])
    print("Total guesses checked:", fastest_attack["checked"])
    print("Attack time:", round(fastest_attack["time"], 6), "seconds")

    if fastest_attack["recovered_secret"] == tuple(s):
        print("Attack Result: SUCCESS")
        print("Reason: The attack recovered the true secret.")
    else:
        print("Attack Result: INCORRECT SECRET")

        if noise_size >= q // 2:
            print("Reason: The noise is very large compared to the modulus.")
            print("Large noise causes many different secret vectors to satisfy the equations,")
            print("so the attack cannot uniquely determine the true secret.")

        elif len(fastest_attack["possible_secrets"]) > 1:
            print("Reason: Multiple candidate secrets satisfy the noisy equations.")
            print("The attack returned one valid candidate, but it is not necessarily the true secret.")

        elif fastest_attack["accuracy"] < 1.0:
            print("Reason: The recovered secret only partially matches the noisy equations.")
            print("The attack did not have enough information to recover the exact secret.")

        else:
            print("Reason: The noisy equations do not uniquely identify the true secret.")

    print("\nPossible secrets found:")
    for item in fastest_attack["possible_secrets"][:10]:
        print(item)

    if fastest_attack["recovered_secret"] == tuple(s):
        print("\nConfirmed: The fastest attack found the actual secret:", tuple(s))
    else:
        print("\nThe fastest attack found a possible secret, but not the exact displayed secret.")

    successful_names = [attack["name"] for attack in successful_attacks]
    print("\nConfirmed: The real secret can be found by", ", ".join(successful_names))


print("\nATTACK METHOD SUMMARY")
print("-" * 60)

for attack in attacks:
    status = "SUCCESS" if attack["success"] else "FAILED"

    print("\n" + attack["name"])
    print("-" * 30)
    print("Status:", status)
    print("Recovered Secret:", attack["recovered_secret"])
    print("Accuracy:", attack["accuracy"])
    print("Reason:", attack["reason"])

    # Additional explanation
    if attack["success"] and attack["recovered_secret"] != tuple(s):

        if noise_size >= q // 2:
            print("Why the secret is incorrect: Noise is large enough that many different")
            print("secret vectors produce outputs that appear equally valid.")

        elif len(attack["possible_secrets"]) > 1:
            print("Why the secret is incorrect: Several candidate secrets fit the data,")
            print("so the attack returned the first one it found.")

        else:
            print("Why the secret is incorrect: The noisy equations do not uniquely")
            print("identify the true secret.")

    elif not attack["success"]:
        print("Why it failed: No candidate secret satisfied the attack criteria.")

    else:
        print("Why it succeeded: The recovered secret matches the true secret.")

    print("Time:", round(attack["time"], 6), "seconds")
    print("Guesses Checked:", attack["checked"])


print("\nSECRET COMPARISON")
print("-" * 60)
print("True Secret:", tuple(s))

for attack in attacks:
    recovered = attack["recovered_secret"]

    if recovered is None:
        print(attack["name"] + ": No secret recovered.")
    elif recovered == tuple(s):
        print(attack["name"] + ":", recovered, "✓")
    else:
        print(attack["name"] + ":", recovered, "Different from true secret")

successful_recovered = [
    attack["recovered_secret"]
    for attack in attacks
    if attack["recovered_secret"] is not None
]

if len(successful_recovered) == 0:
    print("\nResult: No attacks recovered a secret.")
elif all(secret == successful_recovered[0] for secret in successful_recovered):
    print("\nResult: All successful attacks recovered the same secret vector.")
else:
    print("\nResult: Different attacks recovered different candidate secrets.")

# ------------------------------------------------------------
# 8. Worksheet Plot 1: Scatter Plot
# ------------------------------------------------------------

plt.figure(figsize=(8, 5))
plt.scatter(range(samples), clean_outputs, color="blue", label="Without Error")
plt.scatter(range(samples), noisy_outputs, color="red", label="With Error")
plt.xlabel("Sample Number")
plt.ylabel("Output Value mod q")
plt.title("LWE Scatter Plot: Without Error vs With Error")
plt.legend()
plt.grid(True)
plt.savefig("lwe_scatter_plot.png")
plt.show()

# ============================================================
# LWE NOISE COMPARISON FIGURE
# Creates one 2x2 image comparing noise sizes 0, 2, 4, and 8
# Designed to run inside SageMath
# ============================================================

import random as pyrandom
import matplotlib.pyplot as plt

# ------------------------------------------------------------
# Fixed simulation parameters
# ------------------------------------------------------------
q = 97
dimension = 4
samples = 20
secret_bound = q - 1
noise_levels = [0, 2, 4, 8]

# ------------------------------------------------------------
# Generate one fixed public matrix A and secret vector s
# These stay the same in every subplot
# ------------------------------------------------------------
pyrandom.seed("fixed_lwe_instance")

A = [
    [
        pyrandom.randint(0, int(q - 1))
        for _ in range(int(dimension))
    ]
    for _ in range(int(samples))
]

s = [
    pyrandom.randint(0, int(secret_bound))
    for _ in range(int(dimension))
]

# ------------------------------------------------------------
# Compute clean outputs:
# b_clean = A*s mod q
# ------------------------------------------------------------
clean_outputs = []

for i in range(int(samples)):
    value = sum(
        A[i][j] * s[j]
        for j in range(int(dimension))
    )

    clean_outputs.append(int(value % q))

# ------------------------------------------------------------
# Create one figure with four subplots
# ------------------------------------------------------------
fig, axes = plt.subplots(2, 2, figsize=(12, 9))
axes = axes.flatten()

for panel_index, noise_size in enumerate(noise_levels):

    # Use a reproducible string seed for each noise level
    pyrandom.seed("noise_level_{}".format(int(noise_size)))

    # Create the error vector
    if int(noise_size) == 0:
        error_values = [
            0 for _ in range(int(samples))
        ]
    else:
        error_values = [
            pyrandom.randint(
                -int(noise_size),
                int(noise_size)
            )
            for _ in range(int(samples))
        ]

    # Compute noisy outputs:
    # b_noisy = A*s + e mod q
    noisy_outputs = [
        int(
            (
                clean_outputs[i]
                + error_values[i]
            ) % q
        )
        for i in range(int(samples))
    ]

    sample_numbers = list(range(int(samples)))
    ax = axes[panel_index]

    # Plot clean outputs
    ax.scatter(
        sample_numbers,
        clean_outputs,
        marker="o",
        label="Without Error"
    )

    # Plot noisy outputs
    ax.scatter(
        sample_numbers,
        noisy_outputs,
        marker="x",
        label="With Error"
    )

    # Draw a line connecting each clean output
    # to its corresponding noisy output
    for i in range(int(samples)):
        ax.plot(
            [i, i],
            [clean_outputs[i], noisy_outputs[i]],
            linewidth=0.7,
            alpha=0.5
        )

    ax.set_title(
        "Noise Size = {}".format(int(noise_size))
    )

    ax.set_xlabel("Sample Number")
    ax.set_ylabel(r"Output Value mod $q$")
    ax.set_ylim(-5, int(q) + 5)
    ax.grid(True, alpha=0.35)
    ax.legend(fontsize=8)

# ------------------------------------------------------------
# Format the overall figure
# ------------------------------------------------------------
fig.suptitle(
    "Effect of Increasing Random Error on LWE Outputs",
    fontsize=16
)

fig.tight_layout(
    rect=[0, 0, 1, 0.95]
)

# ------------------------------------------------------------
# Save the image at publication quality
# ------------------------------------------------------------
output_filename = "noise_experiment.png"

plt.savefig(
    output_filename,
    dpi=300,
    bbox_inches="tight"
)

plt.show()

print(
    "Saved combined noise comparison figure as:",
    output_filename
)

# ------------------------------------------------------------
# 9. Optional Professor Plot: Clean vs Noisy
# ------------------------------------------------------------

plt.figure(figsize=(6, 6))
plt.scatter(clean_outputs, noisy_outputs, color="red", label="With Error")
plt.plot([0, q], [0, q], color="blue", linestyle="--", label="No Error Line")
plt.xlabel("Output Without Error")
plt.ylabel("Output With Error")
plt.title("Effect of Random Error on LWE Outputs")
plt.legend()
plt.grid(True)
plt.savefig("lwe_clean_vs_noisy.png")
plt.show()


# ------------------------------------------------------------
# 10. Classroom Takeaway
# ------------------------------------------------------------

print("\nCLASSROOM TAKEAWAY")
print("-" * 60)
print("Blue represents outputs without error.")
print("Red represents outputs with error.")
print("Small error keeps the red points close to the blue points.")
print("If the secret key is known, the clean outputs can be recovered and checked.")
print("If the secret key is not known, an attacker has to search for it.")
print("Brute force can succeed only when the secret range is small enough.")
print("As the dimension and secret range increase, brute force becomes much harder.")