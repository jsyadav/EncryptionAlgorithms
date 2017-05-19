package com.example.jyadav.encryptionalgorithms;

public class Blake2b {

	byte[] b= new byte[128];                     // input buffer
	long[] h= new long[8];                      // chained state
	long[] t = new long[2];                      // total number of bytes
	int c;                           // pointer for b[]
	int outlen;                      // digest size

	static long blake2b_iv[] = {
	    0x6A09E667F3BCC908L, 0xBB67AE8584CAA73BL,
	    0x3C6EF372FE94F82BL, 0xA54FF53A5F1D36F1L,
	    0x510E527FADE682D1L, 0x9B05688C2B3E6C1FL,
	    0x1F83D9ABFB41BD6BL, 0x5BE0CD19137E2179L
	};

	public static int blake2b(byte[] out, int outlen, byte[] key, int keylen,
			byte[] in , int inlen) {
		Blake2b b2b = new Blake2b();
		if (b2b.blake2b_init(outlen, key, keylen)<0)
	        return -1;
		
		b2b.blake2b_update(in, inlen);
		b2b.blake2b_final(out);
		return 0;
		
	}

	private void blake2b_final(byte[] out) {
	    this.t[0] += this.c;                // mark last block offset
	    if (this.t[0] < this.c)             // carry overflow
	        this.t[1]++;                    // high word

	    while (this.c < 128)                // fill up with zeros
	        this.b[this.c++] = 0;
	    blake2b_compress(1);           // final block flag = 1

	    // little endian convert and store
	    for (int i = 0; i < this.outlen; i++) {
	        out[i] = (byte) ((this.h[i >> 3] >> (8 * (i & 7))) & 0xFF); // JIT check for typecast
	    }
	}

	private void blake2b_update( byte[] in, int inlen) {
		 int i;

	    for (i = 0; i < inlen; i++) {
	        if (this.c == 128) {            // buffer full ?
	        	this.t[0] += this.c;        // add counters
	            if (this.t[0] < this.c)     // carry overflow ?
	                this.t[1]++;            // high word
	            blake2b_compress(0);   // compress (not last)	            
	            this.c = 0;                 // counter to zero
	        }
	        this.b[this.c++] = in[i];
	    }		    
	}

	long B2B_GET64(int offset) {		
		return
			(((long) b[  offset] & 0xFF )       ^ 
		    (((long) b[1+offset] & 0xFF) <<  8) ^  
		    (((long) b[2+offset] & 0xFF) << 16) ^ 
		    (((long) b[3+offset] & 0xFF) << 24) ^ 
		    (((long) b[4+offset] & 0xFF) << 32) ^ 
		    (((long) b[5+offset] & 0xFF) << 40) ^ 
		    (((long) b[6+offset] & 0xFF) << 48) ^ 
		    (((long) b[7+offset] & 0xFF) << 56));		
	}
	
	/* G0 sigmas */
	static final int[] sig_g00 = {  0, 14, 11,  7,  9,  2, 12, 13,  6, 10,  0, 14, };
	static final int[] sig_g01 = {  1, 10,  8,  9,  0, 12,  5, 11, 15,  2,  1, 10, };

	/* G1 sigmas */
	static final int[] sig_g10 = {  2,  4, 12,  3,  5,  6,  1,  7, 14,  8,  2,  4, };
	static final int[] sig_g11 = {  3,  8,  0,  1,  7, 10, 15, 14,  9,  4,  3,  8, };

	/* G2 sigmas */
	static final int[] sig_g20 = {  4,  9,  5, 13,  2,  0, 14, 12, 11,  7,  4,  9, };
	static final int[] sig_g21 = {  5, 15,  2, 12,  4, 11, 13,  1,  3,  6,  5, 15, };

	/* G3 sigmas */
	static final int[] sig_g30 = {  6, 13, 15, 11, 10,  8,  4,  3,  0,  1,  6, 13, };
	static final int[] sig_g31 = {  7,  6, 13, 14, 15,  3, 10,  9,  8,  5,  7,  6, };

	/* G4 sigmas */
	static final int[] sig_g40 = {  8,  1, 10,  2, 14,  4,  0,  5, 12, 15,  8,  1, };
	static final int[] sig_g41 = {  9, 12, 14,  6,  1, 13,  7,  0,  2, 11,  9, 12, };

	/* G5 sigmas */
	static final int[] sig_g50 = { 10,  0,  3,  5, 11,  7,  6, 15, 13,  9, 10,  0, };
	static final int[] sig_g51 = { 11,  2,  6, 10, 12,  5,  3,  4,  7, 14, 11,  2, };

	/* G6 sigmas */
	static final int[] sig_g60 = { 12, 11,  7,  4,  6, 15,  9,  8,  1,  3, 12, 11, };
	static final int[] sig_g61 = { 13,  7,  1,  0,  8, 14,  2,  6,  4, 12, 13,  7, };

	/* G7 sigmas */
	static final int[] sig_g70 = { 14,  5,  9, 15,  3,  1,  8,  2, 10, 13, 14,  5, };
	static final int[] sig_g71 = { 15,  3,  4,  8, 13,  9, 11, 10,  5,  0, 15,  3, };

	private void blake2b_compress(int last) {	    
	        int i;
	        long[] v = new long[16];
	        long[] m = new long[16];

	        for (i = 0; i < 8; i++) {           // init work variables
	            v[i] = this.h[i];
	            v[i + 8] = blake2b_iv[i];
	        }

	        v[12] ^= this.t[0];                 // low 64 bits of offset
	        v[13] ^= this.t[1];                 // high 64 bits
	        if (last==1)                           // last block flag set ?
	            v[14] = ~v[14];	     

	        for (i = 0; i < 16; i++) {            // get little-endian words
	            m[i] = B2B_GET64(8*i);	            
	        }
	        
			for (int r = 0; r < 12; r++) {

				/**		G (r, 0, 0, 4,  8, 12); */

				v[ 0] = v[ 0] + v[ 4] + m [sig_g00[r]];
				v[12] ^= v[ 0];
				v[12] = ( v[12] << 32 ) | ( v[12] >>> 32 );
				v[ 8] = v[ 8] + v[12];
				v[ 4] ^= v[ 8];
				v[ 4] = ( v[ 4] >>> 24 ) | ( v[ 4] << 40 );
				v[ 0] = v[ 0] + v[ 4] + m [sig_g01[r]];
				v[12] ^= v[ 0];
				v[12] = ( v[12] >>> 16 ) | ( v[12] << 48 );
				v[ 8] = v[ 8] + v[12];
				v[ 4] ^= v[ 8];
				v[ 4] = ( v[ 4] << 1 ) | ( v[ 4] >>> 63 );

				/**		G (r, 1, 1, 5,  9, 13); */

				v[ 1] = v[ 1] + v[ 5] + m[sig_g10[r]];
				v[13] ^= v[ 1];
				v[13] = ( v[13] << 32 ) | ( v[13] >>> 32 );
				v[ 9] = v[ 9] + v[13];
				v[ 5] ^= v[ 9];
				v[ 5] = ( v[ 5] >>> 24 ) | ( v[ 5] << 40 );
				v[ 1] = v[ 1] + v[ 5] + m[sig_g11[r]];
				v[13] ^= v[ 1];
				v[13] = ( v[13] >>> 16 ) | ( v[13] << 48 );
				v[ 9] = v[ 9] + v[13];
				v[ 5] ^= v[ 9];
				v[ 5] = ( v[ 5] << 1 ) | ( v[ 5] >>> 63 );

				/**		G (r, 2, 2, 6, 10, 14); */

				v[ 2] = v[ 2] + v[ 6] + m[sig_g20[r]];
				v[14] ^= v[ 2];
				v[14] = ( v[14] << 32 ) | ( v[14] >>> 32 );
				v[10] = v[10] + v[14];
				v[ 6] ^= v[10];
				v[ 6] = ( v[ 6] >>> 24 ) | ( v[ 6] << 40 );
				v[ 2] = v[ 2] + v[ 6] + m[sig_g21[r]];
				v[14] ^= v[ 2];
				v[14] = ( v[14] >>> 16 ) | ( v[14] << 48 );
				v[10] = v[10] + v[14];
				v[ 6] ^= v[10];
				v[ 6] = ( v[ 6] << 1 ) | ( v[ 6] >>> 63 );

				/**		G (r, 3, 3, 7, 11, 15); */

				v[ 3] = v[ 3] + v[ 7] + m[sig_g30[r]];
				v[15] ^= v[ 3];
				v[15] = ( v[15] << 32 ) | ( v[15] >>> 32 );
				v[11] = v[11] + v[15];
				v[ 7] ^= v[11];
				v[ 7] = ( v[ 7] >>> 24 ) | ( v[ 7] << 40 );
				v[ 3] = v[ 3] + v[ 7] + m[sig_g31[r]];
				v[15] ^= v[ 3];
				v[15] = ( v[15] >>> 16 ) | ( v[15] << 48 );
				v[11] = v[11] + v[15];
				v[ 7] ^= v[11];
				v[ 7] = ( v[ 7] << 1 ) | ( v[ 7] >>> 63 );

				/**		G (r, 4, 0, 5, 10, 15); */

				v[ 0] = v[ 0] + v[ 5] + m[sig_g40[r]];
				v[15] ^= v[ 0];
				v[15] = ( v[15] << 32 ) | ( v[15] >>> 32 );
				v[10] = v[10] + v[15];
				v[ 5] ^= v[10];
				v[ 5] = ( v[ 5] >>> 24 ) | ( v[ 5] << 40 );
				v[ 0] = v[ 0] + v[ 5] + m[sig_g41[r]];
				v[15] ^= v[ 0];
				v[15] = ( v[15] >>> 16 ) | ( v[15] << 48 );
				v[10] = v[10] + v[15];
				v[ 5] ^= v[10];
				v[ 5] = ( v[ 5] << 1 ) | ( v[ 5] >>> 63 );

				/**		G (r, 5, 1, 6, 11, 12); */

				v[ 1] = v[ 1] + v[ 6] + m[sig_g50[r]];
				v[12] ^= v[ 1];
				v[12] = ( v[12] << 32 ) | ( v[12] >>> 32 );
				v[11] = v[11] + v[12];
				v[ 6] ^= v[11];
				v[ 6] = ( v[ 6] >>> 24 ) | ( v[ 6] << 40 );
				v[ 1] = v[ 1] + v[ 6] + + m[sig_g51[r]];
				v[12] ^= v[ 1];
				v[12] = ( v[12] >>> 16 ) | ( v[12] << 48 );
				v[11] = v[11] + v[12];
				v[ 6] ^= v[11];
				v[ 6] = ( v[ 6] << 1 ) | ( v[ 6] >>> 63 );

				/**		G (r, 6, 2, 7,  8, 13); */

				v[ 2] = v[ 2] + v[ 7] + m[sig_g60[r]];
				v[13] ^= v[ 2];
				v[13] = ( v[13] << 32 ) | ( v[13] >>> 32 );
				v[ 8] = v[ 8] + v[13];
				v[ 7] ^= v[ 8];
				v[ 7] = ( v[ 7] >>> 24 ) | ( v[ 7] << 40 );
				v[ 2] = v[ 2] + v[ 7] + m[sig_g61[r]];
				v[13] ^= v[ 2];
				v[13] = ( v[13] >>> 16 ) | ( v[13] << 48 );
				v[ 8] = v[ 8] + v[13];
				v[ 7] ^= v[ 8];
				v[ 7] = ( v[ 7] << 1 ) | ( v[ 7] >>> 63 );

				/**		G (r, 7, 3, 4,  9, 14); */

				v[ 3] = v[ 3] + v[ 4] + m[sig_g70[r]];
				v[14] ^= v[ 3];
				v[14] = ( v[14] << 32 ) | ( v[14] >>> 32 );
				v[ 9] = v[ 9] + v[14];
				v[ 4] ^= v[ 9];
				v[ 4] = ( v[ 4] >>> 24 ) | ( v[ 4] << 40 );
				v[ 3] = v[ 3] + v[ 4] + m[sig_g71[r]];
				v[14] ^= v[ 3];
				v[14] = ( v[14] >>> 16 ) | ( v[14] << 48 );
				v[ 9] = v[ 9] + v[14];
				v[ 4] ^= v[ 9];
				v[ 4] = ( v[ 4] << 1 ) | ( v[ 4] >>> 63 );
			}


	        for( i = 0; i < 8; ++i )
	            this.h[i] ^= v[i] ^ v[i + 8];		
	}

	private int blake2b_init(int outlen, byte[] key, int keylen) {
		int i;
	    
	    if (outlen == 0 || outlen > 64 || keylen > 64)
	        return -1;                      // illegal parameters
	    
	    for (i = 0; i < 8; i++)             // state, "param block"
	        this.h[i] = blake2b_iv[i];
	    
	    this.h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;
	 
	    
	    this.t[0] = 0;                      // input count low word
	    this.t[1] = 0;                      // input count high word
	    this.c = 0;                         // pointer within buffer
	    this.outlen = outlen;
	    
	    for (i = keylen; i < 128; i++)      // zero input block
	    	this.b[i] = 0;
	    if (keylen > 0) {
	        blake2b_update(key, keylen);
	        this.c = 128;                   // at the end
	    }
	    
	    return 0;
	}

}
