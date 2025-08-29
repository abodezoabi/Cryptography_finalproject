#!/bin/bash

set -e  # Exit immediately if any command fails

echo "🔍 Testing invalid key/IV lengths for AES-OFB..."

# Constants
PLAINTEXT="data/plaintext.txt"
OUTPUT="data/encrypted.bin"

# Go back to project root and rebuild
echo "🛠 Rebuilding project..."
cd ..
make clean
if ! make > /dev/null 2>&1; then
    echo "❌ Build failed!"
    exit 1
fi
cd - > /dev/null

# Create test directory if needed
mkdir -p data

# Create a valid plaintext file
echo "This is a test message for AES-OFB mode!" > "$PLAINTEXT"

# Helper function
run_test() {
    local keylen=$1
    local ivlen=$2
    local expect_fail=$3
    
    head -c "$keylen" /dev/urandom > tmp_key.bin
    head -c "$ivlen" /dev/urandom > tmp_iv.bin

    echo -n "🔧 Key: ${keylen} bytes, IV: ${ivlen} bytes → "

    if ../aes_ofb -e "$PLAINTEXT" "$OUTPUT" tmp_key.bin tmp_iv.bin > /dev/null 2>&1; then
        if [ "$expect_fail" = true ]; then
            echo "❌ FAIL: Should have rejected invalid length"
            exit 1
        else
            echo "✅ PASS (valid)"
        fi
    else
        if [ "$expect_fail" = true ]; then
            echo "✅ PASS (caught invalid)"
        else
            echo "❌ FAIL: Should have accepted valid length"
            exit 1
        fi
    fi
}

# Test cases
echo "=== Testing Invalid Cases ==="
run_test 10 16 true    # Too short key
run_test 20 16 true    # Too long key
run_test 16 8 true     # Too short IV
run_test 16 32 true    # Too long IV
run_test 12 12 true    # Both key and IV wrong
run_test 15 16 true    # Borderline key length
run_test 16 15 true    # Borderline IV length

echo "=== Testing Valid Case ==="
run_test 16 16 false   # Valid case

# Cleanup
rm -f tmp_key.bin tmp_iv.bin "$OUTPUT"
rm -rf data/*  
rmdir -p data    
# Final clean build
echo "🧹 Final cleanup..."
cd ..
make clean > /dev/null 2>&1
cd - > /dev/null

echo "=== Test Summary ==="
echo "Total invalid cases tested: 7"
echo "Total valid cases tested: 1"
echo "🎉 All tests passed successfully!"