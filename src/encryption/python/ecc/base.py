from .key_utils import generate_key_pair, generate_custom_key_pair

class ECCImplementationBase:
    
    def __init__(self, curve="P-256", **kwargs):
        self.curve = curve
        self.name = "ECC"
        self.description = f"ECC-{curve}"
        self.public_key = None
        self.private_key = None
        self.is_custom = kwargs.get('is_custom', False)
        
        if self.is_custom:
            self.description = f"Custom {self.description}"
        else:
            self.description = f"Cryptography.io {self.description}"
    
    def generate_key_pair(self):
        # generate a key pair of the specified curve
        if self.is_custom:
            self.public_key, self.private_key = generate_custom_key_pair(self.curve)
        else:
            self.public_key, self.private_key = generate_key_pair(self.curve)
        return self.public_key, self.private_key
    
    def generate_key(self):
        # generate a key pair and return it as a single object for benchmark compatibility
        self.public_key, self.private_key = self.generate_key_pair()
        return (self.public_key, self.private_key)
    
    def encrypt(self, data, public_key):
        # encrypt data using ECIES (Elliptic Curve Integrated Encryption Scheme)
        raise NotImplementedError("Subclasses must implement this method")
    
    def decrypt(self, ciphertext, private_key):
        # decrypt data using ECIES 
        raise NotImplementedError("Subclasses must implement this method")
    
    def sign(self, data, private_key):
        # sign data using ECDSA 
        raise NotImplementedError("Subclasses must implement this method")
    
    def verify(self, data, signature, public_key):
        # verify signature using ECDSA 
        raise NotImplementedError("Subclasses must implement this method")                                      