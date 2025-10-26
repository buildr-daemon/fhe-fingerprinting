### Disclaimer: 
This is my first time working on a full cpp project , so it's a little messy, there is open-fhe python library but was not sure about the full availability of the api so went ahead with cpp.


### Software Design: 

/harness: contains the primary logic for the code ,
main.cpp -> orchestrates everything ,
./data_synthesis.py -> generates data 1000x 512D unit-normalized vectors ,
and a query vector -> 512 D it is encrypted and unit-nomralized during the run to simulate real world use case ,
/users -> simulated users who will have different parts of the key and only the threshold max will be decrypted at the end ,
openfhe -> built openfhe 1.42.0 for this project  , to dowload it with this project run 
git clone --recursive-submodule <repo-link>
### SETUP INSTRUCTIONS:
run the ./build_main.sh after editing the CMakeLists.txt for your path to the openfhe library, 

### CKKS Params:
CKKS params (
    ring dimension: calculated by openfhe internally , 
    modulus chain: 20 , 
    scaling factor: 1024 ,
),

### My system specifications:
I am running it on :
OS: Macos
compiler: clang++
CPU: arm based M2 pro

### How to reproduce
I have used datasets from the /datasets folder running the simulation again on them should result in the same results

### One unified command
./main compare 1 0.85
1 -> dataset no
0.85 -> threshold

### Design Notes:
https://www.notion.so/Mercle-Assignment-Design-notes-29644d413d1a801cba3bf7229fb322f5?source=copy_link

### Results

Logs: 
```
❯ ./main full 1 0.85

╔════════════════════════════════════════╗
║     FULL PIPELINE EXECUTION            ║
╚════════════════════════════════════════╝

[Step 1/4] Generating multiparty keys...

========================================
Initializing Multiparty CKKS
========================================
✓ CryptoContext initialized
  Ring Dimension: 65536
  Security Level: 128-bit classic
  Multiplicative Depth: 15

========================================
Generating Multiparty Keys
========================================

[User 1] Generating key pair...
✓ User 1 key pair generated

[User 2] Generating key pair...
[Joint] Generating shared public key for (s_a + s_b)...
✓ User 2 key pair generated
✓ Shared public key generated (embedded in User 2's public key)

[User 1] Generating evaluation multiplication key...
✓ User 1 evaluation key generated

[User 2] Generating evaluation multiplication key...
✓ User 2 evaluation key generated

[Joint] Generating shared evaluation multiplication key...
✓ Shared evaluation multiplication key generated

[User 1] Generating evaluation sum key...
✓ User 1 evaluation sum key generated

[User 2] Generating joint evaluation sum key...
✓ Joint evaluation sum key for (s_a + s_b) generated

[Joint] Combining evaluation sum keys...
✓ Final joint evaluation sum key inserted

✓ All multiparty keys generated successfully!

========================================
Saving Keys to Disk
========================================

[Shared] Saving crypto context...
✓ Crypto context saved to both user directories

[User 1] Saving keys...
✓ User 1 keys saved to: users/user1/
  - public_key.txt
  - secret_key.txt

[User 2] Saving keys...
✓ User 2 keys saved to: users/user2/
  - public_key.txt
  - secret_key.txt

[Shared] Saving joint public key...
✓ Joint public key saved to both user directories
  - joint_public_key.txt

[Shared] Saving evaluation multiplication keys...
✓ Evaluation multiplication keys saved to both user directories
  - key-eval-mult.txt

[Shared] Saving evaluation sum keys...
✓ Evaluation sum keys saved to both user directories
  - key-eval-sum.txt

✓ All keys saved successfully!

========================================
Verifying Multiparty Keys
========================================

Test vector: [1, 2, 3]
✓ Encrypted with joint public key

Note: Multiparty threshold decryption requires cooperation
      from both parties. This is a security feature!
✓ Key verification PASSED (encryption works correctly)

========================================
Multiparty Key Generation Summary
========================================

✓ Successfully generated multiparty CKKS keys
✓ Number of parties: 2
✓ Scheme: CKKS (Complex Number Encoding)
✓ Security Level: 128-bit

Keys saved to:
  User 1: users/user1/
  User 2: users/user2/

Each user has:
  - cryptocontext.txt (shared crypto parameters)
  - public_key.txt (individual public key)
  - secret_key.txt (individual secret key)
  - joint_public_key.txt (shared public key for encryption)

Usage:
  - Encryption: Use joint_public_key.txt
  - Decryption: Requires both user's secret keys (threshold)
========================================

[Step 2/4] Encrypting vectors...
╔════════════════════════════════════════╗
║   Vector Encryption Module             ║
║   Multiparty CKKS System               ║
╚════════════════════════════════════════╝

========================================
Loading Crypto Context and Keys
========================================
✓ Crypto context loaded
  Ring Dimension: 65536
  Batch Size: 1024
✓ Joint public key loaded

========================================
Encrypting Storage Vectors
========================================

[Dataset] Loaded storage vectors
  Number of vectors: 1000
  Dimension: 512
  Total elements: 512000

[Encryption] Processing vectors...
  Encrypted 1/1000 vectors
  Encrypted 100/1000 vectors
  Encrypted 200/1000 vectors
  Encrypted 300/1000 vectors
  Encrypted 400/1000 vectors
  Encrypted 500/1000 vectors
  Encrypted 600/1000 vectors
  Encrypted 700/1000 vectors
  Encrypted 800/1000 vectors
  Encrypted 900/1000 vectors
  Encrypted 1000/1000 vectors
✓ All storage vectors encrypted and saved

========================================
Encrypting Query Vector
========================================

[Dataset] Loaded query vector
  Dimension: 512

[Normalization] Computing unit normalization...
  Original norm: 22.3937
  Normalized norm: 1
✓ Query vector normalized to unit length
✓ Query vector encrypted and saved
✓ Metadata saved to: encrypted_data/metadata.txt

========================================
Encryption Summary
========================================

✓ Encryption completed successfully
✓ Encrypted data saved to: encrypted_data/

Files created:
  - storage_0.bin to storage_999.bin (1000 vectors)
  - query.bin (query vector)
  - metadata.txt (encryption metadata)
========================================

[Step 3/4] Computing encrypted max similarity...
╔════════════════════════════════════════╗
║  Homomorphic Similarity Computer       ║
║  Multiparty CKKS System                ║
╚════════════════════════════════════════╝

[Configuration] Threshold: 0.85
[Configuration] Max method: softmax

========================================
Loading Crypto Context
========================================
✓ Crypto context loaded

[Loading] Evaluation multiplication keys...
✓ Evaluation multiplication keys loaded

[Loading] Evaluation sum keys...
✓ Evaluation sum keys loaded

[Loading] Query vector...
✓ Query vector loaded

========================================
Computing Cosine Similarities
========================================

[Processing] Computing 1000 dot products...
  Computed 1/1000 similarities
  Computed 100/1000 similarities
  Computed 200/1000 similarities
  Computed 300/1000 similarities
  Computed 400/1000 similarities
  Computed 500/1000 similarities
  Computed 600/1000 similarities
  Computed 700/1000 similarities
  Computed 800/1000 similarities
  Computed 900/1000 similarities
  Computed 1000/1000 similarities
✓ All similarities computed

========================================
Computing Encrypted Maximum
========================================

[Validation] Input similarities count: 1000
[Validation] Crypto context valid: Yes

[Algorithm] Softmax approximation
  Sharpness α: 10
  Formula: max ≈ Σ(x_i * exp(α*x_i)) / Σ(exp(α*x_i))

[Step 1] Scaling similarities by α...
[Step 2] Computing exponentials (polynomial approximation)...
  Processed 1/1000 exponentials
  Processed 100/1000 exponentials
  Processed 200/1000 exponentials
  Processed 300/1000 exponentials
  Processed 400/1000 exponentials
  Processed 500/1000 exponentials
  Processed 600/1000 exponentials
Error in computation
```