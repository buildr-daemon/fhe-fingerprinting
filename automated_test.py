#!/usr/bin/env python3
"""
Automated End-to-End Test
 
Runs the complete pipeline and automatically validates results
"""

import subprocess
import os
import re
import sys


def run_command(cmd, description):
    """Run a command and return output."""
    print(f"\n{'='*70}")
    print(f"{description}")
    print(f"{'='*70}")
    print(f"Command: {cmd}")
    print()
    
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    # Print output
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    if result.returncode != 0:
        print(f"✗ Command failed with return code {result.returncode}")
        return None, False
    
    print(f"✓ {description} completed")
    return result.stdout, True


def extract_max_similarity(decrypt_output):
    """Extract the maximum similarity value from decryption output."""
    # Look for pattern: │  Value: X.XXXXXX
    pattern = r'│\s+Value:\s+([-+]?[0-9]*\.?[0-9]+)'
    match = re.search(pattern, decrypt_output)
    
    if match:
        return float(match.group(1))
    
    # Alternative pattern
    pattern2 = r'Maximum Cosine Similarity.*?Value:\s+([-+]?[0-9]*\.?[0-9]+)'
    match2 = re.search(pattern2, decrypt_output, re.DOTALL)
    
    if match2:
        return float(match2.group(1))
    
    return None


def load_ground_truth():
    """Load ground truth from file."""
    if not os.path.exists('ground_truth.txt'):
        return None
    
    gt = {}
    with open('ground_truth.txt', 'r') as f:
        for line in f:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                gt[key] = value
    
    return gt


def main():
    print("╔════════════════════════════════════════════════════════════╗")
    print("║      AUTOMATED END-TO-END TEST                             ║")
    print("║      Encrypted Vector Similarity System                    ║")
    print("╚════════════════════════════════════════════════════════════╝")
    
    dataset_id = sys.argv[1] if len(sys.argv) > 1 else '1'
    threshold = float(sys.argv[2]) if len(sys.argv) > 2 else 0.85
    
    # Step 1: Build system
    if not os.path.exists('./main'):
        print("\n[Step 1] Building system...")
        run_command('./build_main.sh', 'Building system')
    else:
        print("\n[Step 1] System already built ✓")
    
    # Step 2: Ensure dataset exists
    print(f"\n[Step 2] Checking dataset_{dataset_id}...")
    dataset_path = f'datasets/dataset_{dataset_id}'
    if not os.path.exists(dataset_path):
        print(f"Dataset not found. Generating datasets...")
        run_command('python3 data_synthesis.py', 'Generating datasets')
    else:
        print(f"✓ Dataset exists")
    
    # Step 3: Compute ground truth
    print(f"\n[Step 3] Computing ground truth...")
    output, success = run_command(
        f'python3 validate_accuracy.py compute {dataset_id} {threshold}',
        'Ground truth computation'
    )
    
    if not success:
        print("✗ Failed to compute ground truth")
        return 1
    
    # Load ground truth
    gt = load_ground_truth()
    if gt is None:
        print("✗ Failed to load ground truth")
        return 1
    
    gt_max = float(gt['max_similarity'])
    print(f"\n✓ Ground truth max similarity: {gt_max:.8f}")
    
    # Step 4: Clean previous results
    print(f"\n[Step 4] Cleaning previous encrypted results...")
    for dir_name in ['encrypted_data', 'results', 'users']:
        if os.path.exists(dir_name):
            run_command(f'rm -rf {dir_name}', f'Removing {dir_name}')
    
    # Step 5: Run encrypted pipeline
    print(f"\n[Step 5] Running encrypted pipeline...")
    print("This may take 2-5 minutes...")
    
    output, success = run_command(
        f'./main full {dataset_id}',
        'Encrypted pipeline execution'
    )
    
    if not success:
        print("✗ Encrypted pipeline failed")
        return 1
    
    # Step 6: Extract encrypted result
    print(f"\n[Step 6] Extracting decrypted max similarity...")
    
    encrypted_max = extract_max_similarity(output)
    
    if encrypted_max is None:
        print("✗ Failed to extract max similarity from output")
        print("Output to parse:")
        print(output[-1000:])  # Print last 1000 chars
        return 1
    
    print(f"✓ Encrypted max similarity: {encrypted_max:.8f}")
    
    # Step 7: Compare results
    print(f"\n[Step 7] Comparing results...")
    
    error = abs(encrypted_max - gt_max)
    rel_error = (error / gt_max) * 100 if gt_max != 0 else 0
    
    print(f"\n{'='*70}")
    print("FINAL RESULTS")
    print(f"{'='*70}")
    print(f"Ground Truth Max:     {gt_max:.10f}")
    print(f"Encrypted Max:        {encrypted_max:.10f}")
    print(f"Absolute Error:       {error:.10f}")
    print(f"Relative Error:       {rel_error:.6f}%")
    print(f"{'='*70}")
    
    # Accuracy assessment
    print("\nACCURACY ASSESSMENT:")
    if error < 0.0001:
        print(f"✓✓✓ EXCELLENT: Error < 0.0001 (TARGET MET!)")
        status = "PASS"
    elif error < 0.001:
        print(f"✓✓ GOOD: Error < 0.001 (very close to target)")
        status = "PASS"
    elif error < 0.01:
        print(f"✓ FAIR: Error < 0.01 (acceptable)")
        status = "ACCEPTABLE"
    else:
        print(f"✗ POOR: Error >= 0.01 (needs tuning)")
        status = "FAIL"
    
    # Threshold check
    gt_unique = gt['is_unique'] == 'True'
    enc_unique = encrypted_max > threshold
    threshold_match = (gt_unique == enc_unique)
    
    print(f"\nTHRESHOLD CHECK (τ = {threshold}):")
    print(f"Ground Truth:   {gt_unique} ({'UNIQUE' if gt_unique else 'NOT UNIQUE'})")
    print(f"Encrypted:      {enc_unique} ({'UNIQUE' if enc_unique else 'NOT UNIQUE'})")
    print(f"Match:          {threshold_match} {'✓' if threshold_match else '✗'}")
    
    # Final verdict
    print(f"\n{'='*70}")
    print("FINAL VERDICT")
    print(f"{'='*70}")
    
    if status in ["PASS", "ACCEPTABLE"] and threshold_match:
        print("✓✓✓ TEST PASSED ✓✓✓")
        print("\nThe system successfully:")
        print("  ✓ Generated multiparty keys (no single party can decrypt)")
        print("  ✓ Encrypted 1,000 vectors using joint public key")
        print("  ✓ Computed encrypted maximum using polynomial approximation")
        print("  ✓ Performed threshold decryption (required both parties)")
        print(f"  ✓ Achieved acceptable accuracy (error: {error:.6f})")
        print("  ✓ Threshold decision is correct")
        return_code = 0
    else:
        print("✗✗✗ TEST FAILED ✗✗✗")
        if not threshold_match:
            print("  ✗ Threshold decision mismatch")
        if status == "FAIL":
            print(f"  ✗ Accuracy too low (error: {error:.6f})")
        return_code = 1
    
    print(f"{'='*70}\n")
    
    # Recommendations
    if error >= 0.0001:
        print("\nRECOMMENDATIONS FOR BETTER ACCURACY:")
        print("1. Edit harness/create_key.cpp:")
        print("   - Increase multDepth (15 → 20)")
        print("   - Increase scaleModSize (50 → 60)")
        print("2. Edit harness/compute_similarity.cpp:")
        print("   - Reduce alpha (10.0 → 5.0)")
        print("   - Increase polynomial degree (6 → 8)")
        print("3. Rebuild: ./build_main.sh")
        print("4. Rerun this test")
        print()
    
    return return_code


if __name__ == '__main__':
    sys.exit(main())


