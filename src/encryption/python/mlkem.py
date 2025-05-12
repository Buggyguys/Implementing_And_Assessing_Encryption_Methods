"""
Handmade ML-KEM (Kyber) Implementation

This module implements ML-KEM (Kyber) post-quantum key encapsulation mechanism
from scratch, following the NIST specification.
"""

import os
import hashlib
import struct
from typing import Tuple, Dict, List, Union, Optional
import numpy as np

class MLKEMHandmade:
    """
    A handmade implementation of ML-KEM (Kyber) post-quantum key encapsulation.
    """
    
    # ML-KEM parameter sets
    PARAMS = {
        "ML-KEM-512": {
            "k": 2,               # Number of polynomial vectors
            "n": 256,             # Polynomial degree
            "q": 3329,            # Modulus
            "eta1": 3,            # Noise parameter for s and e
            "eta2": 2,            # Noise parameter for e'
            "du": 10,             # Bits to compress u
            "dv": 4,              # Bits to compress v
            "security": 128,      # Security level (bits)
        },
        "ML-KEM-768": {
            "k": 3,
            "n": 256,
            "q": 3329,
            "eta1": 2,
            "eta2": 2,
            "du": 10,
            "dv": 4,
            "security": 192,
        },
        "ML-KEM-1024": {
            "k": 4,
            "n": 256,
            "q": 3329,
            "eta1": 2,
            "eta2": 2,
            "du": 11,
            "dv": 5,
            "security": 256,
        }
    }
    
    def __init__(self, param_set: str = "ML-KEM-512"):
        """
        Initialize the ML-KEM cipher with the specified parameter set.
        
        Args:
            param_set: Parameter set name ("ML-KEM-512", "ML-KEM-768", or "ML-KEM-1024")
        """
        if param_set not in self.PARAMS:
            raise ValueError(f"Unknown parameter set: {param_set}. Supported sets: {', '.join(self.PARAMS.keys())}")
        
        self.param_set = param_set
        self.params = self.PARAMS[param_set]
        
        # Extract parameters
        self.k = self.params["k"]
        self.n = self.params["n"]
        self.q = self.params["q"]
        self.eta1 = self.params["eta1"]
        self.eta2 = self.params["eta2"]
        self.du = self.params["du"]
        self.dv = self.params["dv"]
    
    def generate_key(self) -> Dict[str, Union[List[np.ndarray], np.ndarray, bytes]]:
        """
        Generate an ML-KEM key pair.
        
        Returns:
            Dict: ML-KEM key components (public_key, secret_key, etc.)
        """
        # Generate a random seed
        d = os.urandom(32)
        
        # Expand d to generate a random matrix A and vectors s, e
        rho = self._hash_g(d, 0)
        sigma = self._hash_g(d, 1)
        
        # Generate a random matrix A (k x k matrix of polynomials)
        A = self._generate_matrix_A(rho)
        
        # Sample secret vector s
        s = self._sample_poly_vector_cbd(sigma, 0, self.eta1, self.k)
        
        # Sample error vector e
        e = self._sample_poly_vector_cbd(sigma, self.k, self.eta1, self.k)
        
        # Compute t = A*s + e mod q
        # This is a matrix-vector product in R_q
        t = np.zeros((self.k, self.n), dtype=np.int16)
        for i in range(self.k):
            for j in range(self.k):
                # Polynomial multiplication A[i][j] * s[j]
                product = self._poly_mul(A[i][j], s[j])
                # Add to t[i]
                t[i] = self._poly_add(t[i], product)
            
            # Add error e[i]
            t[i] = self._poly_add(t[i], e[i])
            
            # Reduce modulo q
            t[i] = self._poly_reduce(t[i])
        
        # Encode the public key (rho, t)
        encoded_rho = rho
        encoded_t = self._encode_poly_vector(t, 12)  # 12 bits per coefficient
        public_key = encoded_rho + encoded_t
        
        # Create the secret key
        secret_key = {
            's': s,
            'pk': public_key
        }
        
        return {
            'public_key': public_key,
            'secret_key': secret_key,
            'params': self.param_set
        }
    
    def _hash_g(self, data: bytes, counter: int) -> bytes:
        """
        Hash a byte string with a counter (SHAKE-128 based).
        
        Args:
            data: Input data
            counter: Counter value
            
        Returns:
            bytes: Hash output
        """
        hash_data = data + counter.to_bytes(1, byteorder='little')
        return hashlib.shake_128(hash_data).digest(32)
    
    def _hash_h(self, data: bytes) -> bytes:
        """
        Hash function H (SHA3-256 based).
        
        Args:
            data: Input data
            
        Returns:
            bytes: Hash output
        """
        return hashlib.sha3_256(data).digest()
    
    def _hash_prf(self, seed: bytes, counter: int) -> bytes:
        """
        Pseudorandom function based on SHAKE-256.
        
        Args:
            seed: Seed value
            counter: Counter value
            
        Returns:
            bytes: Pseudorandom output
        """
        data = seed + counter.to_bytes(1, byteorder='little')
        return hashlib.shake_256(data).digest(32)
    
    def _generate_matrix_A(self, rho: bytes) -> List[List[np.ndarray]]:
        """
        Generate the public matrix A.
        
        Args:
            rho: Seed for matrix generation
            
        Returns:
            List[List[np.ndarray]]: k x k matrix of polynomials
        """
        # Initialize matrix A
        A = [[np.zeros(self.n, dtype=np.int16) for _ in range(self.k)] for _ in range(self.k)]
        
        # Use XOF to expand the seed into a uniformly random matrix
        for i in range(self.k):
            for j in range(self.k):
                # Generate polynomial A[i][j]
                A[i][j] = self._sample_poly_uniform(rho, (i << 8) | j)
        
        return A
    
    def _sample_poly_uniform(self, seed: bytes, nonce: int) -> np.ndarray:
        """
        Sample a polynomial with coefficients uniformly from Z_q.
        
        Args:
            seed: Seed value
            nonce: Nonce value
            
        Returns:
            np.ndarray: Polynomial with uniform coefficients
        """
        # Initialize polynomial
        poly = np.zeros(self.n, dtype=np.int16)
        
        # Construct the initial data for XOF
        data = seed + nonce.to_bytes(2, byteorder='little')
        
        # Use SHAKE-128 as the XOF
        xof = hashlib.shake_128(data).digest(3 * self.n)
        
        # Parse coefficients from the XOF output
        pos = 0
        coef_idx = 0
        
        while coef_idx < self.n and pos + 3 <= len(xof):
            # Take 3 bytes as a 24-bit integer
            val = xof[pos] | (xof[pos+1] << 8) | (xof[pos+2] << 16)
            pos += 3
            
            # Extract two 12-bit values and reduce mod q
            val0 = val & 0xFFF
            val1 = (val >> 12) & 0xFFF
            
            # Only use values < q
            if val0 < self.q and coef_idx < self.n:
                poly[coef_idx] = val0
                coef_idx += 1
            
            if val1 < self.q and coef_idx < self.n:
                poly[coef_idx] = val1
                coef_idx += 1
        
        return poly
    
    def _sample_poly_cbd(self, seed: bytes, nonce: int, eta: int) -> np.ndarray:
        """
        Sample a polynomial with coefficients from a centered binomial distribution.
        
        Args:
            seed: Seed value
            nonce: Nonce value
            eta: Parameter controlling the width of the distribution
            
        Returns:
            np.ndarray: Polynomial with CBD coefficients
        """
        # Initialize polynomial
        poly = np.zeros(self.n, dtype=np.int16)
        
        # Construct the initial data for XOF
        data = seed + nonce.to_bytes(1, byteorder='little')
        
        # Calculate how many bytes we need from XOF
        bytes_required = (self.n * eta * 2 + 7) // 8
        
        # Use SHAKE-256 as the XOF
        xof = hashlib.shake_256(data).digest(bytes_required)
        
        # Extract CBD samples
        buf_idx = 0
        bit_idx = 0
        
        for i in range(self.n):
            a = 0
            b = 0
            
            for j in range(eta):
                # Extract bits for a
                if bit_idx >= 8:
                    buf_idx += 1
                    bit_idx = 0
                
                a += (xof[buf_idx] >> bit_idx) & 1
                bit_idx += 1
                
                # Extract bits for b
                if bit_idx >= 8:
                    buf_idx += 1
                    bit_idx = 0
                
                b += (xof[buf_idx] >> bit_idx) & 1
                bit_idx += 1
            
            # Compute a - b as the sample
            poly[i] = a - b
        
        return poly
    
    def _sample_poly_vector_cbd(self, seed: bytes, nonce_start: int, eta: int, length: int) -> List[np.ndarray]:
        """
        Sample a vector of polynomials with CBD coefficients.
        
        Args:
            seed: Seed value
            nonce_start: Starting nonce value
            eta: CBD parameter
            length: Length of the vector
            
        Returns:
            List[np.ndarray]: Vector of polynomials
        """
        result = []
        for i in range(length):
            poly = self._sample_poly_cbd(seed, nonce_start + i, eta)
            result.append(poly)
        return result
    
    def _poly_add(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """
        Add two polynomials coefficient-wise modulo q.
        
        Args:
            a, b: Polynomials to add
            
        Returns:
            np.ndarray: Result polynomial
        """
        # Add coefficients
        result = (a + b) % self.q
        return result.astype(np.int16)
    
    def _poly_sub(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """
        Subtract two polynomials coefficient-wise modulo q.
        
        Args:
            a, b: Polynomials to subtract
            
        Returns:
            np.ndarray: Result polynomial
        """
        # Subtract coefficients
        result = (a - b) % self.q
        return result.astype(np.int16)
    
    def _poly_mul(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """
        Multiply two polynomials modulo (X^n + 1) and q.
        
        Args:
            a, b: Polynomials to multiply
            
        Returns:
            np.ndarray: Result polynomial
        """
        # Naive schoolbook multiplication (slow but simple implementation)
        result = np.zeros(self.n, dtype=np.int32)
        
        for i in range(self.n):
            for j in range(self.n):
                # Calculate the destination index with wrap-around for X^n + 1
                dest_idx = (i + j) % self.n
                
                # For terms that wrap around, apply the reduction X^n = -1
                if i + j >= self.n:
                    result[dest_idx] -= a[i] * b[j]
                else:
                    result[dest_idx] += a[i] * b[j]
        
        # Reduce modulo q
        return self._poly_reduce(result)
    
    def _poly_reduce(self, poly: np.ndarray) -> np.ndarray:
        """
        Reduce polynomial coefficients modulo q.
        
        Args:
            poly: Polynomial to reduce
            
        Returns:
            np.ndarray: Reduced polynomial
        """
        return np.array([x % self.q for x in poly], dtype=np.int16)
    
    def _encode_poly(self, poly: np.ndarray, bits: int) -> bytes:
        """
        Encode a polynomial to bytes.
        
        Args:
            poly: Polynomial to encode
            bits: Number of bits per coefficient
            
        Returns:
            bytes: Encoded polynomial
        """
        mask = (1 << bits) - 1
        n_bytes = (self.n * bits + 7) // 8
        result = bytearray(n_bytes)
        
        bit_pos = 0
        byte_pos = 0
        
        for coef in poly:
            coef_bits = (coef << bits) // self.q & mask
            
            # Write coef_bits to the result buffer
            for j in range(bits):
                if bit_pos >= 8:
                    byte_pos += 1
                    bit_pos = 0
                
                if (coef_bits >> j) & 1:
                    result[byte_pos] |= 1 << bit_pos
                
                bit_pos += 1
        
        return bytes(result)
    
    def _decode_poly(self, data: bytes, bits: int) -> np.ndarray:
        """
        Decode a polynomial from bytes.
        
        Args:
            data: Encoded polynomial
            bits: Number of bits per coefficient
            
        Returns:
            np.ndarray: Decoded polynomial
        """
        mask = (1 << bits) - 1
        poly = np.zeros(self.n, dtype=np.int16)
        
        bit_pos = 0
        byte_pos = 0
        
        for i in range(self.n):
            val = 0
            
            for j in range(bits):
                if bit_pos >= 8:
                    byte_pos += 1
                    bit_pos = 0
                
                if data[byte_pos] & (1 << bit_pos):
                    val |= 1 << j
                
                bit_pos += 1
            
            # Convert back from compressed form
            poly[i] = (val * self.q + (1 << (bits - 1))) >> bits
        
        return poly
    
    def _encode_poly_vector(self, polys: List[np.ndarray], bits: int) -> bytes:
        """
        Encode a vector of polynomials to bytes.
        
        Args:
            polys: Vector of polynomials
            bits: Number of bits per coefficient
            
        Returns:
            bytes: Encoded vector
        """
        result = b''
        for poly in polys:
            result += self._encode_poly(poly, bits)
        return result
    
    def _decode_poly_vector(self, data: bytes, bits: int, length: int) -> List[np.ndarray]:
        """
        Decode a vector of polynomials from bytes.
        
        Args:
            data: Encoded vector
            bits: Number of bits per coefficient
            length: Number of polynomials in the vector
            
        Returns:
            List[np.ndarray]: Vector of polynomials
        """
        poly_bytes = (self.n * bits + 7) // 8
        result = []
        
        for i in range(length):
            start = i * poly_bytes
            end = start + poly_bytes
            poly = self._decode_poly(data[start:end], bits)
            result.append(poly)
        
        return result
    
    def _compress(self, poly: np.ndarray, d: int) -> np.ndarray:
        """
        Compress polynomial coefficients to d bits.
        
        Args:
            poly: Polynomial to compress
            d: Number of bits
            
        Returns:
            np.ndarray: Compressed polynomial
        """
        mask = (1 << d) - 1
        return np.array([(((1 << d) * coef + self.q//2) // self.q) & mask for coef in poly], dtype=np.int16)
    
    def _decompress(self, poly: np.ndarray, d: int) -> np.ndarray:
        """
        Decompress polynomial coefficients from d bits.
        
        Args:
            poly: Compressed polynomial
            d: Number of bits
            
        Returns:
            np.ndarray: Decompressed polynomial
        """
        return np.array([((self.q * coef) + (1 << (d-1))) >> d for coef in poly], dtype=np.int16)
    
    def encrypt(self, plaintext: bytes, key: Optional[Dict[str, Union[List[np.ndarray], np.ndarray, bytes]]] = None) -> bytes:
        """
        Encapsulate a shared secret (KEM encapsulation).
        
        Args:
            plaintext: Random message (not used in KEM, but needed for benchmarking)
            key: ML-KEM public key (if None, use a newly generated key)
            
        Returns:
            bytes: Ciphertext (c) containing the encapsulated key
        """
        if key is None:
            # Generate a key pair for the benchmark
            key = self.generate_key()
        
        if 'public_key' not in key:
            raise ValueError("Public key not found in the provided key")
        
        # Extract the public key
        public_key = key['public_key']
        
        # Extract rho and t from public key
        rho = public_key[:32]
        t_encoded = public_key[32:]
        
        # Decode t
        t = self._decode_poly_vector(t_encoded, 12, self.k)
        
        # Generate the matrix A
        A = self._generate_matrix_A(rho)
        
        # Generate random message m
        m = os.urandom(32)
        
        # Derive randomness mu for sampling r, e1, e2
        mu = self._hash_h(m + public_key)
        
        # Sample r, e1, e2
        r = self._sample_poly_vector_cbd(mu, 0, self.eta1, self.k)
        e1 = self._sample_poly_vector_cbd(mu, self.k, self.eta2, self.k)
        e2 = self._sample_poly_cbd(mu, 2*self.k, self.eta2)
        
        # Compute u = A^T * r + e1
        u = np.zeros((self.k, self.n), dtype=np.int16)
        for i in range(self.k):
            for j in range(self.k):
                # Polynomial multiplication A[j][i] * r[j]
                product = self._poly_mul(A[j][i], r[j])
                # Add to u[i]
                u[i] = self._poly_add(u[i], product)
            
            # Add error e1[i]
            u[i] = self._poly_add(u[i], e1[i])
            
            # Compress
            u[i] = self._compress(u[i], self.du)
        
        # Compute v = t^T * r + e2 + Decompress(m, 1)
        v = np.zeros(self.n, dtype=np.int16)
        for i in range(self.k):
            product = self._poly_mul(t[i], r[i])
            v = self._poly_add(v, product)
        
        # Add error e2
        v = self._poly_add(v, e2)
        
        # Decode message to polynomial
        message_bits = ''.join(format(b, '08b') for b in m)
        m_poly = np.zeros(self.n, dtype=np.int16)
        for i in range(min(256, len(message_bits))):
            m_poly[i] = int(message_bits[i])
        
        # Decompress message polynomial
        m_decompressed = self._decompress(m_poly, 1)
        
        # Add to v
        v = self._poly_add(v, m_decompressed)
        
        # Compress v
        v = self._compress(v, self.dv)
        
        # Encode u and v
        u_encoded = self._encode_poly_vector(u, self.du)
        v_encoded = self._encode_poly(v, self.dv)
        
        # Return the ciphertext (u, v)
        ciphertext = u_encoded + v_encoded
        
        return ciphertext
    
    def decrypt(self, ciphertext: bytes, key: Dict[str, Union[List[np.ndarray], np.ndarray, bytes]]) -> bytes:
        """
        Decapsulate a shared secret (KEM decapsulation).
        
        Args:
            ciphertext: Ciphertext containing the encapsulated key
            key: ML-KEM secret key
            
        Returns:
            bytes: Decapsulated shared secret
            
        Raises:
            ValueError: If decapsulation fails
        """
        if 'secret_key' not in key:
            raise ValueError("Secret key not found in the provided key")
        
        secret_key = key['secret_key']
        if 's' not in secret_key or 'pk' not in secret_key:
            raise ValueError("Invalid secret key format")
        
        s = secret_key['s']
        
        # Calculate the size of u and v in the ciphertext
        u_size = self.k * ((self.n * self.du + 7) // 8)
        
        if len(ciphertext) != u_size + ((self.n * self.dv + 7) // 8):
            raise ValueError("Invalid ciphertext length")
        
        # Split ciphertext into u and v
        u_encoded = ciphertext[:u_size]
        v_encoded = ciphertext[u_size:]
        
        # Decode u and v
        u = self._decode_poly_vector(u_encoded, self.du, self.k)
        v = self._decode_poly(v_encoded, self.dv)
        
        # Compute m' = v - s^T * u
        m_prime = v.copy()
        for i in range(self.k):
            product = self._poly_mul(s[i], u[i])
            m_prime = self._poly_sub(m_prime, product)
        
        # Scale to 1 bit and round
        m_prime = self._compress(m_prime, 1)
        
        # Convert m' to bytes
        m_bytes = bytearray(32)
        for i in range(min(256, self.n)):
            byte_idx = i // 8
            bit_idx = i % 8
            if m_prime[i]:
                m_bytes[byte_idx] |= 1 << bit_idx
        
        # Return a simulated shared secret
        # In a real implementation, we would derive the shared secret using KDF
        return hashlib.sha256(bytes(m_bytes)).digest() 