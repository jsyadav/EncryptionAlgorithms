package com.example.jyadav.encryptionalgorithms;

// norx3261
public class Norx {
	public final static int CRYPTO_KEYBYTES = 32;
	public final static int CRYPTO_NSECBYTES = 0;
	public final static int CRYPTO_NPUBBYTES = 16;
	public final static int CRYPTO_ABYTES = 32;
	
	public final static int  NORX_W = 32;           /* Word size */
	public final static int  NORX_L = 6;            /* Round number */
	public final static int  NORX_P = 1;            /* Parallelism degree */
	public final static int  NORX_T = (NORX_W * 4); /* Tag size */
	
	//public final static int  NORX_N = (NORX_W *  2) ;    /* Nonce size */
	//public final static int  NORX_K = (NORX_W *  4) ;   /* Key size */
	public final static int  NORX_B = (NORX_W * 16) ;    /* Permutation width */
	public final static int  NORX_C = (NORX_W *  4)  ;   /* Capacity */
	public final static int  NORX_R = (NORX_B - NORX_C); /* Rate */
	
	public final static int  HEADER_TAG  = 0x01;
	public final static int  PAYLOAD_TAG = 0x02;
	public final static int  TRAILER_TAG = 0x04;
	public final static int  FINAL_TAG   = 0x08;
	public final static int  BRANCH_TAG  = 0x10;
	public final static int  MERGE_TAG   = 0x20;

    /* Rotation constants */
    public final static int R0 = 8;
    public final static int R1 = 11;
    public final static int R2 = 16;
    public final static int R3 = 31;
	
	public final static void print(String name, byte var[], long len, int offset) {
	    int i;
	    System.out.printf("%s[%d]=", name, len);
	    for (i = 0; i < len; ++i) {
	      String byteacter = String.format("%02x", var[i+offset]);
	      System.out.printf("%s", byteacter);
	    }
	    System.out.printf("\n");
	  }
	
	public static int[] S ;
	static int H(int a, int b) {
		return ((a ^ b) ^ ((a & b) << 1));
	}
	static int ROTR(int a, int r) {
		return ((a >>> r) | (a << (NORX_W - r)));
	}
	
	static void G(int a, int b, int c, int d) {
		S[a] = H(S[a], S[b]);
		S[d] = ROTR(S[a] ^ S[d],  8);
		S[c] = H(S[c], S[d]);
		S[b] = ROTR(S[b] ^ S[c], 11);
		S[a] = H(S[a], S[b]);
		S[d] = ROTR(S[a] ^ S[d], 16);
		S[c] = H(S[c], S[d]);
		S[b] = ROTR(S[b] ^ S[c], 31);
	}
	
	static void F1()
	{
	    /* Column step */
	    G(S[ 0], S[ 4], S[ 8], S[12]);
	    G(S[ 1], S[ 5], S[ 9], S[13]);
	    G(S[ 2], S[ 6], S[10], S[14]);
	    G(S[ 3], S[ 7], S[11], S[15]);
	    /* Diagonal step */
	    G(S[ 0], S[ 5], S[10], S[15]);
	    G(S[ 1], S[ 6], S[11], S[12]);
	    G(S[ 2], S[ 7], S[ 8], S[13]);
	    G(S[ 3], S[ 4], S[ 9], S[14]);
	}
	static void F()
	{
	    /* Column step */
	    G(0, 4, 8, 12);
	    G(1, 5, 9, 13);
	    G(2, 6, 10, 14);
	    G(3, 7, 11, 15);
	    /* Diagonal step */
	    G(0, 5, 10, 15);
	    G(1, 6, 11, 12);
	    G(2, 7, 8, 13);
	    G(3, 4, 9, 14);
	}
	static int LOAD(final byte[] bytes, final int off) {
        int word = 0;
        int index = off;

        word = (bytes[index++] & 0xff);
        word = (word << 8) | (bytes[index++] & 0xff);
        word = (word << 8) | (bytes[index++] & 0xff);
        word = (word << 8) | (bytes[index++] & 0xff);

        return word;
    }
	 static void STORE(final int word, final byte[] bytes, final int off) {

         int index = off + 4 - 1;// changed 8 to 4
         bytes[index--] = (byte)word;
         bytes[index--] = (byte)(word >> 8);
         bytes[index--] = (byte)(word >> 16);
         bytes[index--] = (byte)(word >> 24);
         
     }
	 static int BYTES(int x) {
		 return (((x) + 7) / 8);
	 }
	 static int WORDS(int x) {
		 return (((x) + (NORX_W-1)) / NORX_W);
	 }
	 /* The core permutation */
	 static void norx_permute(){	  
	     for (int i = 0; i < NORX_L; ++i) {
	         F();
	     }
	 }
	 static void norx_init(byte[] k, byte[] n){

		S = new int[16];
	     int i;
	     for(i = 0; i < 16; ++i) {
	         S[i] = i;
	     }

	     F();
	     F();

	     S[ 0] = LOAD(n, 0 * BYTES(NORX_W));
	     S[ 1] = LOAD(n , 1 * BYTES(NORX_W));

	     S[ 4] = LOAD(k , 0 * BYTES(NORX_W));
	     S[ 5] = LOAD(k , 1 * BYTES(NORX_W));
	     S[ 6] = LOAD(k , 2 * BYTES(NORX_W));
	     S[ 7] = LOAD(k , 3 * BYTES(NORX_W));

	     S[12] ^= NORX_W;
	     S[13] ^= NORX_L;
	     S[14] ^= NORX_P;
	     S[15] ^= NORX_T;

	     norx_permute();
	 }
	 static void norx_pad(byte[] out, byte[] in, int offset, int inlen){
	     for(int i=0; i < inlen;i++) {
	    	 out[i] = in[i+offset];
	     }
	     out[inlen] = 0x01;
	     out[BYTES(NORX_R) - 1] |= 0x80;
	 }
	 static  void norx_absorb_block(byte[] in, int offset, int tag){
	     S[15] ^= tag;
	     norx_permute();

	     for (int i = 0; i < WORDS(NORX_R); ++i) {
	         S[i] ^= LOAD(in , offset+ (i * BYTES(NORX_W)));
	     }
	 }

	 
	 static void norx_absorb_lastblock(byte[] in, int offset, int inlen, int tag){
	     byte[] lastblock = new byte[BYTES(NORX_R)];
	     norx_pad(lastblock, in, offset, inlen);
	     norx_absorb_block(lastblock,0, tag);
	 }
	 static void norx_absorb_data(byte[] in, int inlen, int tag){
		 int offset = 0;
	     if (inlen > 0)
	     {
	         while (inlen >= BYTES(NORX_R))
	         {
	             norx_absorb_block(in,offset, tag);	            
	             inlen -= BYTES(NORX_R);
	             offset += BYTES(NORX_R);
	         }
	         norx_absorb_lastblock(in, offset, inlen, tag);	         
	     }
	 }
	 static void norx_encrypt_block(byte[] out, byte[] in, int offset){
	     S[15] ^= PAYLOAD_TAG;
	     norx_permute();
	     for (int i = 0; i < WORDS(NORX_R); ++i) {
	         S[i] ^= LOAD(in , offset +( i * BYTES(NORX_W)));
	         STORE(S[i], out, offset + (i * BYTES(NORX_W)));
	     }
	 }

	 static void norx_encrypt_lastblock(byte[] out, byte[] in, int offset, int inlen){
	     byte[] lastblock = new byte[BYTES(NORX_R)];
	     norx_pad(lastblock, in, offset, inlen);
	     norx_encrypt_block(lastblock, lastblock, 0);
	     //memcpy(out, lastblock, inlen);
	     for (int i=0; i< inlen; i++) {
	    	 out[i+offset] = lastblock[i];
	     }
	 }
	 static void norx_encrypt_data(byte[] out, byte[] in, int inlen) {
		 int offset =0;
	     if (inlen > 0){
	         while (inlen >= BYTES(NORX_R)){
	             norx_encrypt_block(out, in, offset);	             
	             inlen -= BYTES(NORX_R);
	             offset    += BYTES(NORX_R);
	             //in    += BYTES(NORX_R);
	             //out   += BYTES(NORX_R);
	         }
	         norx_encrypt_lastblock(out, in, offset, inlen);
	     }
	 }
	 static void norx_finalise(byte[] tag, int offset){
	     byte[] lastblock = new byte[BYTES(NORX_R)];

	     S[15] ^= FINAL_TAG;
	     norx_permute();
	     norx_permute();

	     for (int i = 0; i < WORDS(NORX_R); ++i) {
	         STORE(S[i], lastblock, (i * BYTES(NORX_W)));
	     }

	     for (int i = 0; i <BYTES(NORX_T);i++ ) {
	    	 tag[offset + i] = lastblock[i];
	     }

	     //burn(lastblock, 0, BYTES(NORX_R)); /* burn full state dump */
	     //burn(state, 0, sizeof(norx_state_t)); /* at this point we can also burn the state */
	 }
	static int crypto_aead_encrypt(byte c[], int clen, byte m[], int mlen, byte ad[], int adlen,
		      byte nsec[], byte npub[], byte k[]) {
	    norx_init(k, npub);
	    norx_absorb_data(ad, adlen, HEADER_TAG);
	    norx_encrypt_data(c, m, mlen);
	    //norx_absorb_data(state, z, zlen, TRAILER_TAG);
	    norx_finalise(c, mlen);
	    clen = mlen + BYTES(NORX_T);
	    //burn(state, 0, sizeof(norx_state_t));
		
		 return clen;
	}
	static  void norx_decrypt_block(byte[] out, byte[] in, int offset){
	    S[15] ^= PAYLOAD_TAG;
	    norx_permute();
	    for (int i = 0; i < WORDS(NORX_R); ++i) {
	        int c = LOAD(in, offset+ (i * BYTES(NORX_W)));
	        STORE(S[i]^c , out, offset+ (i * BYTES(NORX_W)));
	        S[i] = c;
	    }
	}

	static  void norx_decrypt_lastblock(byte[] out, byte[] in, int offset, int inlen){
	    byte[] lastblock = new byte[BYTES(NORX_R)];
	    S[15] ^= PAYLOAD_TAG;
	    norx_permute();
	    int i;
	    for(i = 0; i < WORDS(NORX_R); ++i) {
	        STORE(S[i], lastblock , 0 + (i * BYTES(NORX_W)));
	    }

	    for (i=0;i<inlen;i++) {
	    	lastblock[i] = in[offset+i];
	    }
	    lastblock[inlen] ^= 0x01;
	    lastblock[BYTES(NORX_R) - 1] ^= 0x80;

	    for (i = 0; i < WORDS(NORX_R); ++i) {
	        int c = LOAD(lastblock , i * BYTES(NORX_W));
	        STORE(S[i] ^ c,lastblock , i * BYTES(NORX_W));
	        S[i] = c;
	    }

	    for (i =0;i < inlen;i++) {
	    	out[offset+i] = lastblock[i];
	    }
	    //burn(lastblock, 0, sizeof lastblock);
	}
	static void norx_decrypt_data(byte[] out, byte[] in, int inlen){
    	int offset =0;
		if (inlen > 0){
	        while (inlen >= BYTES(NORX_R)){
	            norx_decrypt_block(out, in, offset);	            
	            inlen -= BYTES(NORX_R);
	            offset    += BYTES(NORX_R);
	            //in    += BYTES(NORX_R);
	            //out   += BYTES(NORX_R);
	        }
	        norx_decrypt_lastblock(out, in, offset, inlen);	        
	    }
	}
	/* Verify tags in constant time: 0 for success, -1 for fail */
	static int norx_verify_tag(byte[] tag1, int offset, byte[] tag2){	   
	    int acc = 0;

	    for (int i = 0; i < BYTES(NORX_T); ++i) {
	        acc |= tag1[i+offset] ^ tag2[i];
	    }

	    return (((acc - 1) >> 8) & 1) - 1;
	}

	static int crypto_aead_decrypt(byte m[], int mlen, byte nsec[], byte c[], int clen, byte ad[],
		      int adlen, byte npub[], byte k[]) {
		int result = -1;
	    byte[] tag = new byte [BYTES(NORX_T)];

	    if (clen < BYTES(NORX_T)) {
	        return -1;
	    }

	    norx_init(k, npub);
	    norx_absorb_data(ad, adlen, HEADER_TAG);
	    norx_decrypt_data(m, c, clen - BYTES(NORX_T));
	    //norx_absorb_data(state, z, zlen, TRAILER_TAG);
	    norx_finalise(tag, 0);
	    mlen = clen - BYTES(NORX_T);

	    result = norx_verify_tag(c , clen - BYTES(NORX_T), tag);
	    
	    if (result != 0) { // burn decrypted plaintext on auth failure 
	        //burn(m, 0, clen - BYTES(NORX_T));
	    }
	    //burn(state, 0, sizeof(norx_state_t));
	    
	    return mlen;

	}
}
