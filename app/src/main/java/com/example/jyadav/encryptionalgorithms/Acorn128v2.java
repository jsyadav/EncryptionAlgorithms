package com.example.jyadav.encryptionalgorithms;

public class Acorn128v2 {
	
	public final static int CRYPTO_KEYBYTES = 16;
	public final static int CRYPTO_NSECBYTES = 0;
	public final static int CRYPTO_NPUBBYTES = 16;
	public final static int CRYPTO_ABYTES = 16;
	public final static int CRYPTO_NOOVERLAP = 1;
	
	public byte[] m;
	public int mlen;
	public byte[] ad;
	public int adlen;
	public byte[] k;
	public byte[] c;
	public int clen;
	public byte[] nsec;
	public byte[] npub;
	public byte[] p;
	public int plen;
	public byte[] state;
	
	public Acorn128v2(byte[] msg, int mlen, byte[] ad, int adlen,
			byte[] key, byte[] pub, byte[] sec, byte[] cipher, int clen ) {
		this.m = msg;
		this.mlen = mlen;
		this.ad = ad;
		this.adlen = adlen;
		this.k = key;
		this.npub = pub;
		this.nsec = sec;
		this.c = cipher;
		this.clen = clen;
		this.state = new byte[293];
		
	}
	
	public final static void print(String name, byte var[], long len, int offset) {
	    int i;
	    System.out.printf("%s[%d]=", name, len);
	    for (i = 0; i < len; ++i) {
	      String byteacter = String.format("%02x", var[i+offset]);
	      System.out.printf("%s", byteacter);
	    }
	    System.out.printf("\n");
	  }

	
	public static byte maj(byte x, byte y,byte z) {
		return (byte) (  ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))  );
	}
	public static byte ch(byte x, byte y,byte z) {
		return (byte)(  ((x) & (y)) ^ ( ((x) ^ 1) & (z))  );
	}

	static byte KSG128(byte state[])
	{
	    return (byte) ( state[12] ^ state[154] ^ maj(state[235], state[61], state[193]) );
	}

	static byte FBK128(byte state[], byte ks[], byte ca, byte cb)
	{
	    byte f;
	    ks[0] = KSG128(state);
	    f  = (byte) (state[0] ^ (state[107] ^ 1) ^ maj(state[244], state[23], state[160]) ^ ch(state[230], state[111], state[66]) ^ (ca & state[196]) ^ (cb & (ks[0])));
	    return f;
	}

	static void Encrypt_StateUpdate128_1bit(byte state[], byte plaintextbit, 
			byte ciphertextbit[], byte ks[], byte ca, byte cb)
	{
	    int  j;
	    byte f;

	    state[289] ^= state[235] ^ state[230];
	    state[230] ^= state[196] ^ state[193];
	    state[193] ^= state[160] ^ state[154];
	    state[154] ^= state[111] ^ state[107];
	    state[107] ^= state[66]  ^ state[61];
	    state[61]  ^= state[23]  ^ state[0];

	    f  = FBK128(state, ks, ca, cb);

	    for (j = 0; j <= 291; j++) state[j] = state[j+1];
	    state[292] = (byte) (f ^ plaintextbit);
	    ciphertextbit[0] = (byte) (ks[0] ^ plaintextbit);
	}

	
	static void acorn128_enc_onebyte(byte state[], byte plaintextbyte,
			      byte ciphertextbyte[], byte ksbyte[], byte cabyte, byte cbbyte)
			{
		int i;
	    byte ciphertextbit[] = {(byte) 0x00};
	    byte kstem[] = {(byte) 0x00};
	    byte plaintextbit, ca,cb;

	    ciphertextbyte[0] = 0x00;
	    ksbyte[0] = 0x00;
	    
	    for (i = 0; i < 8; i++)
	    {
	        ca = (byte) ((cabyte >> i) & 1);
	        cb = (byte) ((cbbyte >> i) & 1);
	        plaintextbit = (byte) ((plaintextbyte >> i) & 1);
	        Encrypt_StateUpdate128_1bit(state, plaintextbit, ciphertextbit, kstem, ca, cb);
	        ciphertextbyte[0] |= (ciphertextbit[0] << i);
	        ksbyte[0] |= (kstem[0] << i);
	    }	   
	}
	

	static void acorn128_initialization(Acorn128v2 arn) {
		int i,j;
        byte m[] = new byte[293];
        byte ks[] = {0x00};
        byte tem[] = {0x00};
        //initialize the state to 0
        for (j = 0; j <= 292; j++) arn.state[j] = 0;

        //set the value of m
        for (j = 0; j <=  15;   j++)   m[j] = arn.k[j];
        for (j = 16; j <= 31;   j++)   m[j] = arn.npub[j - 16];
        for (j = 32; j <= 223;  j++)   m[j] = arn.k[j & 0xf];
        m[32] ^= 1;

        //run the cipher for 1792 steps
        for (i = 0; i < 224; i++)
        {
             //acorn128_enc_onebyte(state, m[i], tem, ks, (byte)0xff, (byte)0xff);
        	acorn128_enc_onebyte(arn.state, m[i], tem, ks, (byte)0xff, (byte)0xff);
        }
  	
	}

	//the finalization state of acorn
	static void acorn128_tag_generation(int msglen, int adlen, int maclen, byte mac[], byte state[])
	{
	    int i;
	    byte plaintextbyte = 0;
	    byte ciphertextbyte[] = {0x00};
	    byte ksbyte[] = {0x00};

	    for (i = 0; i < 768/8; i++)
	    {
	        acorn128_enc_onebyte(state, plaintextbyte, ciphertextbyte, ksbyte, (byte)0xff, (byte)0xff);
	        if ( i >= (768/8 - 16) ) {mac[i-(768/8-16)] = ksbyte[0]; }
	    }
	}
	static int crypto_aead_encrypt(byte c[], int clen, byte m[], int mlen, byte ad[], int adlen,
		      byte nsec[], byte npub[], byte k[]) {
		
		Acorn128v2 arn = new Acorn128v2(m, mlen, ad, adlen, k, npub, nsec, c, clen);
		
		int i;
	    byte plaintextbyte;// ciphertextbyte = 0, ksbyte = 0;
	    byte ciphertextbyte[] = {0x00};
	    byte ksbyte[] = {0x00};
	    byte mac[] = new byte[16];
	    //byte[] state = new byte[293];
	    byte ca, cb;
	    
		 //initialization stage
	    acorn128_initialization(arn);	 
	    
	    //process the associated data
	    for (i = 0; i < adlen; i++)
	    {
	        acorn128_enc_onebyte(arn.state, ad[i], ciphertextbyte, ksbyte, (byte)0xff, (byte)0xff);
	    }
	    
	    for (i = 0; i < 256/8; i++)
	    {
	        if ( i == 0 ) plaintextbyte = 0x1;
	        else plaintextbyte = 0;

	        if ( i < 128/8)   
	        	ca = (byte)0xff;
	        else 
	        	ca = 0;

	        cb = (byte)0xff;

	        acorn128_enc_onebyte(arn.state, plaintextbyte, ciphertextbyte, ksbyte, ca, cb);
	    }	   

	    byte tempCipherByte[] = {0x00};
	    //process the plaintext
	    for (i = 0; i < mlen; i++)
	    {
	        acorn128_enc_onebyte(arn.state, m[i], tempCipherByte, ksbyte, (byte)0xff, (byte)0 );
	        c[i] = tempCipherByte[0];
	    }
	    
	    for (i = 0; i < 256/8; i++)
	    {
	        if (i == 0) plaintextbyte = 0x1;
	        else plaintextbyte = 0;

	        if ( i < 128/8)   
	        	ca = (byte)0xff;
	        else 
	        	ca = 0;

	        cb = 0;

	        acorn128_enc_onebyte(arn.state, plaintextbyte, ciphertextbyte, ksbyte, ca, cb);
	    }

	    //finalization stage, we assume that the tag length is a multiple of bytes
	    acorn128_tag_generation(mlen, adlen, 16, mac, arn.state);

	    clen = mlen + 16;
	    //memcpy(c+mlen, mac, 16);
	    for (i = 0; i< 16 ;i++) {
	    	c[mlen+i] = mac[i];
	    }
	   
		return clen;
		
	}
	
	static void Decrypt_StateUpdate128_1bit(byte state[], byte plaintextbit[], 
			byte ciphertextbit, byte ks[], byte ca, byte cb)
	{
	    int  j;
	    byte f;

	    state[289] ^= state[235] ^ state[230];
	    state[230] ^= state[196] ^ state[193];
	    state[193] ^= state[160] ^ state[154];
	    state[154] ^= state[111] ^ state[107];
	    state[107] ^= state[66]  ^ state[61];
	    state[61]  ^= state[23]  ^ state[0];

	    f = FBK128(state, ks, ca, cb);

	    for (j = 0; j <= 291; j++) state[j] = state[j+1];
	    plaintextbit[0] = (byte) (ks[0] ^ ciphertextbit);
	    state[292] = (byte) (f ^ plaintextbit[0]);//<<< TODO check this logic
	}
	
	// decrypt one byte
	static void acorn128_dec_onebyte(byte state[], byte plaintextbyte[],
	       byte ciphertextbyte, byte ksbyte[], byte cabyte, byte cbbyte)
	{
	    int i;
	    byte plaintextbit[] = {0x00};
	    byte ks[] = {0x00};
	    byte ciphertextbit, ca,cb;

	    plaintextbyte[0] = 0x00;
	    ksbyte[0] = 0x000;
	    for  (i = 0; i < 8; i++)
	    {
	        ca = (byte) ((cabyte >> i) & 1);
	        cb = (byte) ((cbbyte >> i) & 1);
	        ciphertextbit = (byte) ((ciphertextbyte >> i) & 1);
	        Decrypt_StateUpdate128_1bit(state, plaintextbit, ciphertextbit, ks, ca, cb);
	        plaintextbyte[0] |= (plaintextbit[0] << i);
	    }
	}
	 static int crypto_aead_decrypt(byte m[], int mlen, byte nsec[], byte c[], int clen, byte ad[],
		      int adlen, byte npub[], byte k[]) {
		 
		 Acorn128v2 arn = new Acorn128v2(m, mlen, ad, adlen, k, npub, nsec, c, clen);
		 
		    int i;
		    byte plaintextbyte;//, ciphertextbyte = 0, ksbyte = 0;
		    byte ciphertextbyte[] = {0x00};
		    byte ksbyte[] = {0x00};
		   // byte state[] = new byte[293];
		    byte tag[] = new byte[16];
		    byte check = 0;
		    byte ca, cb;

		    if (clen < 16) return -1;

		    //initialization stage
		    acorn128_initialization(arn);

		    //process the associated data
		    for (i = 0; i < adlen; i++)
		    {
		        acorn128_enc_onebyte(arn.state, ad[i], ciphertextbyte, ksbyte, (byte)0xff, (byte)0xff);
		    }

		    for (i = 0; i < 256/8; i++)
		    {
		        if ( i == 0 ) plaintextbyte = 0x1;
		        else plaintextbyte = 0;

		        if ( i < 128/8)   
		        	ca = (byte)0xff;
		        else 
		        	ca = 0;

		        cb = (byte)0xff;

		        acorn128_enc_onebyte(arn.state, plaintextbyte, ciphertextbyte, ksbyte, ca, cb);
		    }

		    //process the ciphertext
		    mlen = clen - 16;
		    
		    byte tempMessageByte[] = {0x00};
		    for (i = 0; i < mlen; i++)
		    {
		        acorn128_dec_onebyte(arn.state, tempMessageByte, c[i], ksbyte, (byte)0xff, (byte)0);
		        m[i] = tempMessageByte[0];
		    }
		    
		    for (i = 0; i < 256/8; i++)
		    {
		        if ( i == 0 ) plaintextbyte = 0x1;
		        else plaintextbyte = 0;

		        if ( i < 128/8)   
		        	ca = (byte)0xff;
		        else 
		        	ca = 0;

		        cb = 0;

		        acorn128_enc_onebyte(arn.state, plaintextbyte, ciphertextbyte, ksbyte, ca, cb);
		    }

		    //finalization stage, we assume that the tag length is a multiple of bytes
		    acorn128_tag_generation(mlen, adlen, 16, tag, arn.state);

		    for (i = 0; i  < 16; i++) 
		    	check |= (tag[i] ^ c[clen - 16 + i]);
		    
		    if (check == 0) { 
		    	
		    	//return 0;
		    	return mlen;
		    }
		    else 
		    	return -1;
		 
	 }
}
