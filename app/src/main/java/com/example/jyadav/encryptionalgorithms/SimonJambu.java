package com.example.jyadav.encryptionalgorithms;

public class SimonJambu {

	public final static int CRYPTO_KEYBYTES = 16;
	public final static int CRYPTO_NSECBYTES = 0;
	public final static int CRYPTO_NPUBBYTES = 8;
	public final static int CRYPTO_ABYTES = 8;
	public final static int CRYPTO_NOOVERLAP = 1;
	public final static int BS = 16;           // block size in byte
	public final static int PBS = 8;           // plaintext block size in byte
	
	
	public final static void print(String name, byte var[], long len, int offset) {
	    int i;
	    System.out.printf("%s[%d]=", name, len);
	    for (i = 0; i < len; ++i) {
	      String byteacter = String.format("%02x", var[i+offset]);
	      System.out.printf("%s", byteacter);
	    }
	    System.out.printf("\n");
	  }
	public final static void print(String name, long var[], long len, int offset) {
	    int i;
	    System.out.printf("%s[%d]=", name, len);
	    for (i = 0; i < len; ++i) {
	      String byteacter = String.format("%02x", var[i+offset]);
	      System.out.printf("%s", byteacter);
	    }
	    System.out.printf("\n");
	  }

	private static final byte[][] Z = new byte[][] {
        {01, 01, 01, 01, 01, 00, 01, 00, 00, 00, 01, 00, 00, 01, 00, 01, 00, 01, 01, 00, 00, 00, 00, 01, 01, 01, 00, 00, 01, 01, 00, 01, 01, 01, 01, 01, 00, 01, 00, 00, 00, 01, 00, 00, 01, 00, 01, 00, 01, 01, 00, 00, 00, 00, 01, 01, 01, 00, 00, 01, 01, 00, },
        {01, 00, 00, 00, 01, 01, 01, 00, 01, 01, 01, 01, 01, 00, 00, 01, 00, 00, 01, 01, 00, 00, 00, 00, 01, 00, 01, 01, 00, 01, 00, 01, 00, 00, 00, 01, 01, 01, 00, 01, 01, 01, 01, 01, 00, 00, 01, 00, 00, 01, 01, 00, 00, 00, 00, 01, 00, 01, 01, 00, 01, 00, },
        {01, 00, 01, 00, 01, 01, 01, 01, 00, 01, 01, 01, 00, 00, 00, 00, 00, 00, 01, 01, 00, 01, 00, 00, 01, 00, 00, 01, 01, 00, 00, 00, 01, 00, 01, 00, 00, 00, 00, 01, 00, 00, 00, 01, 01, 01, 01, 01, 01, 00, 00, 01, 00, 01, 01, 00, 01, 01, 00, 00, 01, 01, },
        {01, 01, 00, 01, 01, 00, 01, 01, 01, 00, 01, 00, 01, 01, 00, 00, 00, 01, 01, 00, 00, 01, 00, 01, 01, 01, 01, 00, 00, 00, 00, 00, 00, 01, 00, 00, 01, 00, 00, 00, 01, 00, 01, 00, 00, 01, 01, 01, 00, 00, 01, 01, 00, 01, 00, 00, 00, 00, 01, 01, 01, 01, },
        {01, 01, 00, 01, 00, 00, 00, 01, 01, 01, 01, 00, 00, 01, 01, 00, 01, 00, 01, 01, 00, 01, 01, 00, 00, 00, 01, 00, 00, 00, 00, 00, 00, 01, 00, 01, 01, 01, 00, 00, 00, 00, 01, 01, 00, 00, 01, 00, 01, 00, 00, 01, 00, 00, 01, 01, 01, 00, 01, 01, 01, 01, }
    };
	
	static long[] EK ; // 68 round keys for Simon128/128
	static long S0;
	static long S1;
	static long SR;
	public final static int wordSize = 8;
	public final static int wordSizeBits = wordSize*8;
	public final static int blockSize = wordSize * 2;
	public final static int rounds = 68;
	public final static int sequenceBase = 2;
	

	 static long rotr(long i, int distance){
         return (i >>> distance) | (i << (wordSizeBits - distance));
     }
	static  void SimonKeySetup128(byte[] keyBytes){
    	//print("Key", keyBytes, 16,0);
        EK = new long[rounds];// 68 round keys for Simon128/128
        // Determine number of key words m
        int keyWords = keyBytes.length / wordSize;
        byte[] constants = Z[sequenceBase + keyWords - 2];
        long c = 0xfffffffffffffffcl;

        // Load k[m-1]..k[0]
        for (int i = 0; i < keyWords; i++){
            EK[i] = bytesToWord(keyBytes, (keyWords - i - 1) * wordSize);
        }

        // Key expansion
        for (int i = keyWords; i < rounds; i++){
            long tmp = (rotr(EK[i - 1], 3));
            if (keyWords == 4){
                tmp ^= EK[i - 3];
            }
            tmp = (tmp ^ rotr(tmp, 1));
            EK[i] = tmp ^ EK[i - keyWords] ^ constants[(i - keyWords) % 62] ^ c;
        }
        //print("new Key", EK, EK.length,0);
    }
	static long bytesToWord(final byte[] bytes, final int off) {
		if ((off + wordSize) > bytes.length)
        {
            throw new IllegalArgumentException();
        }
        long word = 0;
        int index = off;

        word = (bytes[index++] & 0xffl);
        word = (word << 8) | (bytes[index++] & 0xffl);
        word = (word << 8) | (bytes[index++] & 0xffl);
        word = (word << 8) | (bytes[index++] & 0xffl);
        word = (word << 8) | (bytes[index++] & 0xffl);
        word = (word << 8) | (bytes[index++] & 0xffl);
        word = (word << 8) | (bytes[index++] & 0xffl);
        word = (word << 8) | (bytes[index++] & 0xffl);

        return word;
    }
	 static void wordToBytes(final long word, final byte[] bytes, final int off)
     {
         if ((off + wordSize) > bytes.length)
         {
             throw new IllegalArgumentException();
         }
         int index = off + 8 - 1;

         bytes[index--] = (byte)word;
         bytes[index--] = (byte)(word >> 8);
         bytes[index--] = (byte)(word >> 16);
         bytes[index--] = (byte)(word >> 24);
         bytes[index--] = (byte)(word >> 32);
         bytes[index--] = (byte)(word >> 40);
         bytes[index--] = (byte)(word >> 48);
         bytes[index--] = (byte)(word >> 56);
         
     }

	
	
	static long rotl(long i, int distance)
    {
        return (i << distance) | (i >>> (wordSizeBits - distance));
    }

	static void SimonEncrypt128() {
		long x = S0;
        long y = S1;
        for (int r = 0; r < 68; r++){
            long tmp = x;
            x = (y ^ (rotl(x, 1) & rotl(x, 8)) ^ rotl(x, 2) ^ EK[r]);
            y = tmp;
        }
        S0 = x;
        S1 = y;
	}

	static void jambu_initialization(byte[] iv){		
        S0 = bytesToWord(iv, 0);
        S1 = 0;
        /* update stateS with encryption */
        SimonEncrypt128();
        /* constant injection */
        S0 ^= 0x5;
        /* stateR initialization */
        SR = S1;
	}
	
	static void jambu_aut_ad_step( byte[] adblock, int offset){
		SimonEncrypt128();
		S0 ^= SR ^ 0x01;
		S1 ^= bytesToWord(adblock, offset);
		SR ^= S1;
	}

	static void jambu_aut_ad_partial(byte[] adblock, int offset, int len){
		byte [] p = new byte[8];
		for (int i = 0;i<len;i++) {
			p[i] = adblock[offset + i];
		}
		p[len] = (byte)0x80; // pad '1'
		for (int i = len+1;i<8;i++) {
			p[i] = 0x00; // pad '0' 
		}
		SimonEncrypt128();
		S0 ^= SR ^ 0x01;
		S1 ^= bytesToWord(p,0);
		SR ^= S1;
		
		return;
	}

	static void jambu_aut_ad_full(){
		SimonEncrypt128();		
		S0 ^= SR ^ 0x01;
		S1 ^= 0x80;
		SR ^= S1;
	}

	static void jambu_enc_aut_msg_step(byte[] m, byte[] c, int offset){
        SimonEncrypt128();
        S0 ^= SR;
        S1 ^= bytesToWord(m,offset);
        SR ^= S1;
        wordToBytes((S0 ^ bytesToWord(m,offset)), c, offset );
	} 

	/* Deal with partial final block */
	static void jambu_enc_aut_msg_partial(byte[] m, byte[] c, int offset, int len){  
        byte [] p = new byte[8];
		for (int i = 0;i<len;i++) {
			p[i] = m[offset + i];
		}
		p[len] = (byte)0x80; // pad '1'
		for (int i = len+1;i<8;i++) {
			p[i] = 0x00; // pad '0' 
		}
		SimonEncrypt128();
        S0 ^= SR;
        S1 ^= bytesToWord(p,0);
        SR ^= S1;
        wordToBytes((S0 ^ bytesToWord(p,0)), c, offset );
	} 

	static void jambu_enc_aut_msg_full(){  
        SimonEncrypt128();
        S0 ^= SR;
        S1 ^= 0x80;
        SR ^= S1;
    }
	static void jambu_dec_aut_msg_step(byte[] m, byte[] c, int offset ){
        SimonEncrypt128();
        S0 ^= SR;
        wordToBytes((S0 ^ bytesToWord(c, offset)), m, offset );
        S1 ^= bytesToWord(m,offset);
        SR ^= S1;
	} 

	static void jambu_dec_aut_partial(byte[] m, byte[] c, int offset, int len){
	   byte[] p = new byte[8];

        SimonEncrypt128();
        S0 ^= SR;
        wordToBytes((S0 ^ bytesToWord(c,offset)), p, 0 );
        
        p[len] = (byte)0x80;
        for (int i = len+1;i<8;i++) {
			p[i] = 0x00; // pad '0' 
		}
        for (int i = 0;i<len;i++) {
			m[offset + i] = p[i];
		}

        S1 ^= bytesToWord(p,0);
        SR ^= S1;
	} 

	static  void jambu_tag_generation(int msglen, byte[] c){
        SimonEncrypt128();
        S0 ^= SR ^ 0x03;
        SR ^= S1;
        SimonEncrypt128();
        wordToBytes((S0 ^ S1 ^ SR), c, msglen );        
	}
	static  int jambu_tag_verification(int msglen, byte[] c)
	{
	        byte[] t = new byte[8];
	        int check = 0;
	        int i;
	        SimonEncrypt128();
	        S0 ^= SR ^ 0x03;
	        SR ^= S1;
	        SimonEncrypt128();
	        wordToBytes(S0 ^ S1 ^ SR, t,0) ;
	        for (i = 0; i < PBS; i++) check |= (c[msglen+i] ^ t[i]);
	        if (0 == check) return 1; else return -1;
	}

	static int crypto_aead_encrypt(byte c[], int clen, byte m[], int mlen, byte ad[], int adlen,
	      byte nsec[], byte npub[], byte k[]) {
	 	int i;
	 
	    // key expansion
	    SimonKeySetup128(k);
	
	    // Initialization
	    jambu_initialization(npub);
	
	    // process the associated data
	    for (i = 0; (i + PBS) <= adlen; i += PBS) {
	            jambu_aut_ad_step(ad, i);
	    }
	
	    // deal with the partial block of associated data
	    // in this program, we assume that the message length is a multiple of bytes.
	    if ((adlen & (PBS-1)) != 0)  {
	            jambu_aut_ad_partial(ad, i, adlen & (PBS-1));
	    }
	    else {
	            jambu_aut_ad_full();
	    }

	    // encrypt the plaintext, we assume that the message length is multiple of bytes. 
	    for (i = 0; (i + PBS) <= mlen; i += PBS) {
	            jambu_enc_aut_msg_step(m, c, i);
	    }
	
	    // deal with the final plaintext block
	    if ((mlen & (PBS-1)) != 0) {
	            jambu_enc_aut_msg_partial( m, c, i, mlen & (PBS-1));
	    }
	    else{
	            jambu_enc_aut_msg_full();
	    }
	
	    // finalization stage, we assume that the tag length is a multiple of bytes
	    jambu_tag_generation(mlen, c);
	    clen = mlen + PBS;
	    
	    
    return clen;
		
	}
	
	static int crypto_aead_decrypt(byte m[], int mlen, byte nsec[], byte c[], int clen, byte ad[],
		      int adlen, byte npub[], byte k[]) {
		int i;
		// key expansion
	    SimonKeySetup128(k);
	 // Initialization
	    jambu_initialization(npub);
	 // process the associated data
        for (i = 0; (i + PBS) <= adlen; i += PBS) {
                jambu_aut_ad_step(ad, i);
        }

        // deal with the partial block of associated data
        // in this program, we assume that the message length is a multiple of bytes.
        if (  (adlen & (PBS - 1)) != 0 )  {
                jambu_aut_ad_partial(ad, i, adlen & (PBS - 1));
        }
        else{
                jambu_aut_ad_full();
        }

        // decrypt the ciphertext
        mlen = clen - PBS;
        for (i = 0; (i + PBS) <= mlen; i = i + PBS) {
                jambu_dec_aut_msg_step(m, c, i);
        }

        // deal with the final block
        if (((mlen) & (PBS - 1)) != 0) {
                jambu_dec_aut_partial(m, c, i, mlen & (PBS - 1));
        }
        else {
                jambu_enc_aut_msg_full();
        }

        // verification, we assume that the tag length is a multiple of bytes  
        jambu_tag_verification(mlen, c);

		return mlen;
	}
	
	

}
