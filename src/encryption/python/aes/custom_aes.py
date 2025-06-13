from .mix_cols import (
    S_BOX, INV_S_BOX, RCON, 
    MIX_COL_2, MIX_COL_3, MIX_COL_9, MIX_COL_11, MIX_COL_13, MIX_COL_14
)

class CustomAES:
    
    # cache the lookup tables at the class level for faster access
    from .mix_cols import (
        S_BOX, INV_S_BOX, MIX_COL_2, MIX_COL_3, MIX_COL_9,
        MIX_COL_11, MIX_COL_12, MIX_COL_13, MIX_COL_14, RCON
    )
    
    def __init__(self, key):

        # validate key size
        key_length = len(key)
        if key_length not in (16, 24, 32):
            raise ValueError("Key size must be 16, 24, or 32 bytes (128, 192, or 256 bits)")
        
        self.key = key
        self.key_size = key_length
        
        # determine number of rounds based on key size
        if self.key_size == 16:    # AES-128
            self.rounds = 10
        elif self.key_size == 24:  # AES-192
            self.rounds = 12
        else:                      # AES-256
            self.rounds = 14
            
        # generate key schedule once during initialization
        self.key_schedule = self._expand_key(key)
        
        # cache for round keys and temporary state matrices
        self._key_cache = {}
        self._temp_state = [[0 for _ in range(4)] for _ in range(4)]
    
    def _expand_key(self, master_key):
        
        key_bytes = list(master_key)
        key_length = len(key_bytes)
        
        # total number of 32-bit words in the expanded key
        total_words = 4 * (self.rounds + 1)
        
        # initialize expanded key with zeros
        expanded_key = bytearray(total_words * 4)
        
        # first part of the expanded key is the master key
        for i in range(key_length):
            expanded_key[i] = key_bytes[i]
            
        # store S_BOX locally for faster access
        s_box = self.S_BOX
        rcon = self.RCON
        
        # expand the key
        i = key_length
        rcon_iteration = 1
        
        # temp buffer for transformation
        temp = bytearray(4)
        
        while i < len(expanded_key):
            # save last 4 bytes for the next core step
            temp[0] = expanded_key[i-4]
            temp[1] = expanded_key[i-3]
            temp[2] = expanded_key[i-2]
            temp[3] = expanded_key[i-1]
            
            # perform the core key schedule step for each master key
            if i % key_length == 0:
                # rotate left by storing to temp array
                t = temp[0]
                temp[0] = temp[1]
                temp[1] = temp[2]
                temp[2] = temp[3]
                temp[3] = t
                
                # apply S-box
                temp[0] = s_box[temp[0]]
                temp[1] = s_box[temp[1]]
                temp[2] = s_box[temp[2]]
                temp[3] = s_box[temp[3]]
                
                # XOR with round constant (Rcon)
                temp[0] ^= rcon[rcon_iteration]
                rcon_iteration += 1
            
            # extra S-Box for 256-bit keys
            elif key_length == 32 and i % key_length == 16:
                temp[0] = s_box[temp[0]]
                temp[1] = s_box[temp[1]]
                temp[2] = s_box[temp[2]]
                temp[3] = s_box[temp[3]]
                
            # XOR with corresponding bytes from key_length bytes earlier
            for j in range(4):
                expanded_key[i] = expanded_key[i - key_length] ^ temp[j]
                i += 1
                
        return expanded_key
    
    def _bytes_to_state(self, data):

        # direct indexing for speed
        state = self._temp_state
        state[0][0] = data[0]
        state[0][1] = data[4]
        state[0][2] = data[8]
        state[0][3] = data[12]
        state[1][0] = data[1]
        state[1][1] = data[5]
        state[1][2] = data[9]
        state[1][3] = data[13]
        state[2][0] = data[2]
        state[2][1] = data[6]
        state[2][2] = data[10]
        state[2][3] = data[14]
        state[3][0] = data[3]
        state[3][1] = data[7]
        state[3][2] = data[11]
        state[3][3] = data[15]
        return state
    
    def _state_to_bytes(self, state):

        # direct indexing for speed
        result = bytearray(16)
        result[0] = state[0][0]
        result[1] = state[1][0]
        result[2] = state[2][0]
        result[3] = state[3][0]
        result[4] = state[0][1]
        result[5] = state[1][1]
        result[6] = state[2][1]
        result[7] = state[3][1]
        result[8] = state[0][2]
        result[9] = state[1][2]
        result[10] = state[2][2]
        result[11] = state[3][2]
        result[12] = state[0][3]
        result[13] = state[1][3]
        result[14] = state[2][3]
        result[15] = state[3][3]
        return bytes(result)
    
    def _sub_bytes(self, state):
        #apply the S-box to each byte 
        s_box = self.S_BOX
        
        # unrolled loops for performance
        state[0][0] = s_box[state[0][0]]
        state[0][1] = s_box[state[0][1]]
        state[0][2] = s_box[state[0][2]]
        state[0][3] = s_box[state[0][3]]
        state[1][0] = s_box[state[1][0]]
        state[1][1] = s_box[state[1][1]]
        state[1][2] = s_box[state[1][2]]
        state[1][3] = s_box[state[1][3]]
        state[2][0] = s_box[state[2][0]]
        state[2][1] = s_box[state[2][1]]
        state[2][2] = s_box[state[2][2]]
        state[2][3] = s_box[state[2][3]]
        state[3][0] = s_box[state[3][0]]
        state[3][1] = s_box[state[3][1]]
        state[3][2] = s_box[state[3][2]]
        state[3][3] = s_box[state[3][3]]
    
    def _inv_sub_bytes(self, state):
        # inverse S-box foe each byte 
        inv_s_box = self.INV_S_BOX
        
        state[0][0] = inv_s_box[state[0][0]]
        state[0][1] = inv_s_box[state[0][1]]
        state[0][2] = inv_s_box[state[0][2]]
        state[0][3] = inv_s_box[state[0][3]]
        state[1][0] = inv_s_box[state[1][0]]
        state[1][1] = inv_s_box[state[1][1]]
        state[1][2] = inv_s_box[state[1][2]]
        state[1][3] = inv_s_box[state[1][3]]
        state[2][0] = inv_s_box[state[2][0]]
        state[2][1] = inv_s_box[state[2][1]]
        state[2][2] = inv_s_box[state[2][2]]
        state[2][3] = inv_s_box[state[2][3]]
        state[3][0] = inv_s_box[state[3][0]]
        state[3][1] = inv_s_box[state[3][1]]
        state[3][2] = inv_s_box[state[3][2]]
        state[3][3] = inv_s_box[state[3][3]]
    
    def _shift_rows(self, state):
        #shift rows of state matrix using swap operations

        # row 1: Shift left by 1
        state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
        
        # row 2: Shift left by 2 (swap first with third, second with fourth)
        state[2][0], state[2][2] = state[2][2], state[2][0]
        state[2][1], state[2][3] = state[2][3], state[2][1]
        
        # row 3: Shift left by 3 (equivalent to right shift by 1)
        state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]
    
    def _inv_shift_rows(self, state):
        """Inverse shift the rows of the state matrix using optimized swap operations."""
        # row 1: Shift right by 1
        state[1][0], state[1][1], state[1][2], state[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
        
        # row 2: Shift right by 2 (swap first with third, second with fourth)
        state[2][0], state[2][2] = state[2][2], state[2][0]
        state[2][1], state[2][3] = state[2][3], state[2][1]
        
        # row 3: Shift right by 3 (equivalent to left shift by 1)
        state[3][0], state[3][1], state[3][2], state[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]
    
    def _mix_columns(self, state):
        """Mix the columns of the state matrix using the Galois Field with lookup tables."""
        # cache the table references for fast access
        mix_2 = self.MIX_COL_2
        mix_3 = self.MIX_COL_3
        
        # process columns
        for i in range(4):
            a = state[0][i]
            b = state[1][i]
            c = state[2][i]
            d = state[3][i]
            
            # perform all calculations at once 
            state[0][i] = mix_2[a] ^ mix_3[b] ^ c ^ d
            state[1][i] = a ^ mix_2[b] ^ mix_3[c] ^ d
            state[2][i] = a ^ b ^ mix_2[c] ^ mix_3[d]
            state[3][i] = mix_3[a] ^ b ^ c ^ mix_2[d]
    
    def _inv_mix_columns(self, state):
        mix_9 = self.MIX_COL_9
        mix_11 = self.MIX_COL_11
        mix_13 = self.MIX_COL_13
        mix_14 = self.MIX_COL_14
        
        for i in range(4):
            a = state[0][i]
            b = state[1][i]
            c = state[2][i]
            d = state[3][i]
            
            state[0][i] = mix_14[a] ^ mix_11[b] ^ mix_13[c] ^ mix_9[d]
            state[1][i] = mix_9[a] ^ mix_14[b] ^ mix_11[c] ^ mix_13[d]
            state[2][i] = mix_13[a] ^ mix_9[b] ^ mix_14[c] ^ mix_11[d]
            state[3][i] = mix_11[a] ^ mix_13[b] ^ mix_9[c] ^ mix_14[d]
    
    def _add_round_key(self, state, key_schedule, round_num):
        # XOE the round key to state matrix
        # check if this round key is in cache
        cache_key = f"round_{round_num}"
        if cache_key not in self._key_cache:
            key_offset = round_num * 16
            
            # pre-compute/cache round key
            round_key = [
                [key_schedule[key_offset + 0], key_schedule[key_offset + 4], 
                 key_schedule[key_offset + 8], key_schedule[key_offset + 12]],
                [key_schedule[key_offset + 1], key_schedule[key_offset + 5], 
                 key_schedule[key_offset + 9], key_schedule[key_offset + 13]],
                [key_schedule[key_offset + 2], key_schedule[key_offset + 6], 
                 key_schedule[key_offset + 10], key_schedule[key_offset + 14]],
                [key_schedule[key_offset + 3], key_schedule[key_offset + 7], 
                 key_schedule[key_offset + 11], key_schedule[key_offset + 15]]
            ]
            self._key_cache[cache_key] = round_key
        
        round_key = self._key_cache[cache_key]
        
        state[0][0] ^= round_key[0][0]
        state[0][1] ^= round_key[0][1]
        state[0][2] ^= round_key[0][2]
        state[0][3] ^= round_key[0][3]
        state[1][0] ^= round_key[1][0]
        state[1][1] ^= round_key[1][1]
        state[1][2] ^= round_key[1][2]
        state[1][3] ^= round_key[1][3]
        state[2][0] ^= round_key[2][0]
        state[2][1] ^= round_key[2][1]
        state[2][2] ^= round_key[2][2]
        state[2][3] ^= round_key[2][3]
        state[3][0] ^= round_key[3][0]
        state[3][1] ^= round_key[3][1]
        state[3][2] ^= round_key[3][2]
        state[3][3] ^= round_key[3][3]
    
    def encrypt_block(self, plaintext):

        if len(plaintext) != 16:
            raise ValueError("Plaintext block must be 16 bytes")
        
        # convert plaintext to state matrix
        state = self._bytes_to_state(plaintext)
        
        # initial round key addition
        self._add_round_key(state, self.key_schedule, 0)
        
        # main rounds 
        for round_num in range(1, self.rounds):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, self.key_schedule, round_num)
        
        # final round 
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self.key_schedule, self.rounds)
        
        # convert state back to bytes
        return self._state_to_bytes(state)
    
    def decrypt_block(self, ciphertext):

        if len(ciphertext) != 16:
            raise ValueError("Ciphertext block must be 16 bytes")
        
        # convert to state matrix
        state = self._bytes_to_state(ciphertext)
        
        # initial round key addition
        self._add_round_key(state, self.key_schedule, self.rounds)
        
        # main rounds (in reverse, unrolled)
        for round_num in range(self.rounds - 1, 0, -1):
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)
            self._add_round_key(state, self.key_schedule, round_num)
            self._inv_mix_columns(state)
        
        # final round
        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)
        self._add_round_key(state, self.key_schedule, 0)
        
        # convert state back to bytes
        return self._state_to_bytes(state)
