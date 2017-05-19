package com.example.jyadav.encryptionalgorithms;


public class Aezv4 {
	public final static int CRYPTO_KEYBYTES = 48;
	public final static int CRYPTO_NSECBYTES = 0;
	public final static int CRYPTO_NPUBBYTES = 12;
	public final static int CRYPTO_ABYTES = 16;


	static boolean log = false;
	public final static void print(String name, byte var[], long len, int offset) {
		if (log) {
		    int i;
		    System.out.printf("%s[%d]=", name, len);
		    for (i = 0; i < len; ++i) {
		      String byteacter = String.format("%02x", var[i+offset]);
		      System.out.printf("%s", byteacter);
		    }
		    System.out.printf("\n");
		}
	}
	public final static void print(String name, long var[], long len, int offset) {
		if (log) {
		    int i;
		    System.out.printf("%s[%d]=", name, len);
		    for (i = 0; i < len; ++i) {
		      String byteacter = String.format("%d-", var[i+offset]);
		      System.out.printf("%s", byteacter);
		    }
		    System.out.printf("\n");
		}
	}
	public final static void print(String name, int var[], long len, int offset) {
		if (log) {
		    int i;
		    System.out.printf("%s[%d]=", name, len);
		    for (i = 0; i < len; ++i) {
		      String byteacter = String.format("%d-", var[i+offset]);
		      System.out.printf("%s", byteacter);
		    }
		    System.out.printf("\n");
		}
	}
	
	static void memcpy(byte[] dest, int offsetD, byte[] src, int offsetS,  int len) {
		for (int i=0;i<len;i++) dest[i+offsetD] = src[i+offsetS];
	}
	static void memset(byte[] dest, int offset, byte val, int len) {
		for (int i=0;i<len;i++) dest[i+offset] = val;
	}/*
	static void memcpy(int[] dest, int offsetD, int[] src, int offsetS,  int len) {
		for (int i=0;i<len;i++) dest[i+offsetD] = src[i+offsetS];
	}
	static void memset(int[] dest, int offset, int val, int len) {
		for (int i=0;i<len;i++) dest[i+offset] = val;
	}*/
	static void write32_big_endian(int x, byte[] p, int offset) {	 
	    p[0+offset] = (byte)(x>>24); p[1+offset] = (byte)(x>>16);
	    p[2+offset] = (byte)(x>> 8); p[3+offset] = (byte)(x>> 0);
	}
	
	static void swapBytes(byte[] p, int i, int j) {
		byte temp = p[i]; p[i] = p[j];p[j]=temp;		
	}
	static void correct_key(byte[] p, int offset, int nbytes) {	    
	    for (int i=0; i<nbytes; i+=4) { //write32_big_endian(p[i+offset], p, i+offset);
			swapBytes(p, 0+offset+i,3+offset+i); swapBytes(p, 1+offset+i,2+offset+i);
	    }
	}

	static void xor_bytes(byte[] src1, byte[]src2, int n, byte[] dst) {
	    while (n!=0) { n--; dst[n] = (byte) (src1[n] ^ src2[n]); }
	}
	static void xor_bytesWithOffset(byte[] src1, int offset1, byte[]src2, int offset2,int n, byte[] dst,int offset3) {
	    while (n!=0) { n--; dst[n+offset3] = (byte) (src1[n+offset1] ^ src2[n+offset2]); }
	}
	static void double_block(byte[] p) {
	    byte i, tmp = p[0];
	    for (i=0; i<15; i++)
	        p[i] = (byte) (((p[i]&0xFF) << 1) | ((p[i+1]&0xFF) >> 7));
	    p[15] = (byte) (((p[15]&0xFF) << 1) ^ ((((tmp&0xFF) >> 7)>0)?135:0));
	}
	static void mult_block(int x, byte[] src, byte[] dst) {
	    byte[] t= new byte[16];
	    byte[] r= new byte[16];
	    memcpy(t,0,src,0,16); memset(r,0,(byte)0x00,16);
	    while (x != 0) {
	    	//System.out.println(x+ ",x&1=" + (x&1));
	        if ((x&1)>0) 
	        	xor_bytes(r,t,16,r);
	        double_block(t);
	        //print("mult_block",t,16,0);
	        x>>=1;
	    }
	    memcpy(dst,0,r,0,16);
	}


	static void Extract(byte[] K, int kbytes, byte[] extracted_key) {
	    if (kbytes==48) memcpy(extracted_key,0, K,0, 48);	    
	    else            Blake2b.blake2b(extracted_key, 48, null, 0, K, kbytes);
	}
	static void E( byte[] K, int kbytes, int j, int i,
            byte[] src, int offset, byte[] dst, int offset2) {
		byte[] extracted_key = new byte[3*16];
		byte[] buf = new byte[16];
		byte[] delta = new byte[16];
		byte[] I = new byte[16];
		byte[] J= new byte[16];
		byte[] L = new byte[16];
		
		Extract(K, kbytes, extracted_key);
		print("Exe key", extracted_key,48,0);
		memcpy(I,0,extracted_key,0,16);
		memcpy(J,0,extracted_key,16,16);
		memcpy(L,0,extracted_key,32,16);
		
		/* Encipher */
		if (j == -1) {
			//int[] aes_key = new int[4*11];/* 44*4=176 bytes*/
			byte[] aes_key= new byte[176];
			memset(aes_key,0,(byte)0x00,64);         /* 0        */
			memcpy(aes_key,16, extracted_key,0, 48);  /* I J L    */
			correct_key(aes_key,16,3*16); //don't need as we are not writing int to byte
			memcpy(aes_key, 64, aes_key,16, 48);     /* I J L    */
			memcpy(aes_key,112, aes_key,16, 48);     /* I J L    */
			memcpy(aes_key,160, aes_key,16, 16);     /* I        */
			mult_block(i,J,buf); xor_bytesWithOffset(buf,0,src,offset,16,buf,0);
			print("buf", buf,16,0);
            print("aes key", aes_key,176,0);
			Rijndael.rijndaelEncryptRound(aes_key, 99, buf, 10); /*incl final MixColumns*/
		} else {
			//int[] aes4_key = new int[4*5];/* 20*4 = 80 bytes*/
			byte[] aes4_key = new byte[80];
			memset(aes4_key,0,(byte)0x00,64);
			if (j==2) {
				memcpy(aes4_key,16, L,0, 16);
				memcpy(aes4_key,32, I,0, 16);
				memcpy(aes4_key,48, J,0, 16);
				memcpy(aes4_key,64, L,0, 16);
			} else {
				memcpy(aes4_key,16, J,0, 16);
				memcpy(aes4_key,32, I,0, 16);
				memcpy(aes4_key,48, L,0, 16);
				memset(aes4_key,64,(byte)0x00,16);
			}
			// swap the integer value in big endian
			correct_key(aes4_key, 16, 4*16);// since aes4_key is byte, we starts from 16 byte location, for next 64 bytes
			if (j==0) {
	            mult_block(i,I,buf); xor_bytesWithOffset(buf,0, src,offset, 16, buf,0);
	            print("buf", buf,16,0);
	            print("aes key", aes4_key,80,0);
	            Rijndael.rijndaelEncryptRound(aes4_key, 99, buf, 4);
		    } else if (j==1 || j==2) {
		            mult_block((1<<(3+(i-1)/8))+(i-1)%8,I,buf);
		            xor_bytesWithOffset(buf,0, src,offset, 16, buf,0);
		            print("buf", buf,16,0);
		            print("aes key", aes4_key,80,0);
		            Rijndael.rijndaelEncryptRound(aes4_key, 99, buf, 4);
		    } else if (j>=3 && i==0) {
		            mult_block(1<<(j-3),L,delta);
		            print("delta", delta,16,0);
		            print("src", src,16,0);
		            xor_bytesWithOffset(delta,0,src,offset,16, buf,0);
		            print("buf00", buf,16,0);
		            print("aes key", aes4_key,80,0);
		            Rijndael.rijndaelEncryptRound(aes4_key, 99, buf, 4);
		            xor_bytes(buf, delta, 16, buf);
		    } else {			
		            mult_block(1<<(j-3),L,buf);
		    		//print("buf1", buf,16,0);
		            mult_block((1<<(3+(i-1)/8))+(i-1)%8,J,delta);
		            //print("delta", delta,16,0);
		            xor_bytes(delta, buf, 16, delta);
		            xor_bytesWithOffset(src,offset, delta,0, 16, buf,0);
		            print("buf", buf,16,0);
		            print("aes key", aes4_key,80,0);		            
		            Rijndael.rijndaelEncryptRound(aes4_key, 99, buf, 4);
		            xor_bytes(buf, delta, 16, buf);
		    }
		}
		memcpy(dst,offset2, buf,0, 16);
		print("E dst", dst, 16,0);	//System.out.println("\n\n");
	}


	
	static void AEZhash(byte[] K, int kbytes, byte[] N, int nbytes,
	    byte[] A, int abytes, int veclen, int tau, byte[] result) {

	    byte[] buf = new byte[16];
	    byte[] sum = new byte[16];
	    //byte[] p; int bytes;
	    int i;
	    boolean empty;

	    /* Initialize sum with hash of tau */
	    memset(buf,0,(byte)0x00,12); 
	    write32_big_endian(tau, buf, 12);
	    print("tau buf", buf, 16, 0);
	    //System.out.println("1");
	    E(K,kbytes,3,1,buf,0,sum,0);
	    
	    /* Hash nonce, accumulate into sum */
	    empty = (nbytes==0);
	    int nOffset=0;
	    for (i=1; nbytes>=16; i++, nbytes-=16, nOffset+=16 /*,N+=16*/) {
	    	//System.out.println("2, "+i);
	        E(K,kbytes,4,i,N, nOffset,buf,0); xor_bytes(sum, buf, 16, sum);
	    }
	    if (nbytes>0 || empty) {
	        memset(buf,0,(byte)0x00,16); memcpy(buf,0,N,nOffset,nbytes); buf[nbytes]=(byte)0x80;
	       // System.out.println("3");
	        E(K,kbytes,4,0,buf,0,buf,0);
	        xor_bytes(sum, buf, 16, sum);
	    }

	    /* Hash each vector element, accumulate into sum
	    /*for (k=0; k<veclen; k++) { veclen = 1
	    for (k=0; k<veclen; k++) {
	        p = A[k]; bytes = abytes[k]; empty = (bytes==0);*/
	    empty = (abytes==0);
	    int aOffset=0;
        for (i=1; abytes>=16; i++, abytes-=16, aOffset+=16/*, p+=16*/) {
        	//System.out.println("4, "+i);
            E(K,kbytes,5,i,A, aOffset,buf,0); xor_bytes(sum, buf, 16, sum);
        }
        if (abytes>0 || empty) {
            memset(buf,0,(byte)0x00,16); memcpy(buf,0,A,aOffset,abytes); buf[abytes]=(byte)0x80;
            //System.out.println("5");
            E(K,kbytes,5,0,buf,0,buf,0);
            xor_bytes(sum, buf, 16, sum);
        }
	    //}
	    memcpy(result,0,sum,0,16);
		}

	static void AEZprf(byte[] K, int kbytes, byte delta[/*16*/],
            int bytes, byte[] result) {

		byte[] buf = new byte[16];
		byte[] ctr = new byte[16];
		memset(ctr,0,(byte)0x00,16);
		for ( ; bytes >= 16; bytes-=16/*, result+=16*/) {
			int i=15;
			xor_bytes(delta, ctr, 16, buf);
			E(K,kbytes,-1,3,buf,0,result,i*16);
			do { ctr[i]++; i--; } while (ctr[i+1]==0);   /* ctr+=1 */
		}
		if (bytes>0) {
			xor_bytes(delta, ctr, 16, buf);
			E(K,kbytes,-1,3,buf,0,buf,0);
			memcpy(result,0, buf,0, bytes);
		}
	}
	/* Set d=0 for EncipherAEZtiny and d=1 for DecipherAEZtiny */
	static void AEZtiny(byte[] K, int kbytes, byte delta[/*16*/],
	                        byte[] in, int inbytes, int d, byte[] out) {
	    int rounds,i=7,j,k;
	    int step;
	    byte mask=0x00, pad=(byte)0x80;
	    byte[] L = new byte[16];
	    byte[] R = new byte[16];
	    byte[] buf = new byte[32];
	    if      (inbytes==1) rounds=24;
	    else if (inbytes==2) rounds=16;
	    else if (inbytes<16) rounds=10;
	    else {          i=6; rounds=8; }
	    /* Split (inbytes*8)/2 bits into L and R. Beware: May end in nibble. */
	    memcpy(L,0, in,0, (inbytes+1)/2);
	    memcpy(R,0, in, inbytes/2, (inbytes+1)/2);
	    if ((inbytes&1)>0) {                     /* Must shift R left by half a byte */
	        for (k=0; k<inbytes/2; k++)
	            R[k] = (byte)((R[k] << 4) | (R[k+1] >> 4));
	        R[inbytes/2] = (byte)(R[inbytes/2] << 4);
	        pad = 0x08; mask = (byte)0xf0;
	    }
	    if (d==1) {
	        if (inbytes < 16) {
	            memset(buf,0,(byte)0x00,16); memcpy(buf,0,in,0,inbytes); buf[0] |= 0x80;
	            xor_bytes(delta, buf, 16, buf);
	            E(K, kbytes,0,3,buf,0,buf,0);
	            L[0] ^= (buf[0] & 0x80);
	        }
	        j = rounds-1; step = -1;
	    } else {
	        j = 0; step = 1;
	    }
	    for (k=0; k<rounds/2; k++,j=(int)((int)j+2*step)) {
	        memset(buf,0,(byte)0x00, 16);
	        memcpy(buf,0, R,0,(inbytes+1)/2);
	        buf[inbytes/2] = (byte) ((buf[inbytes/2] & mask) | pad);
	        xor_bytes(buf, delta, 16, buf);
	        buf[15] ^= (byte)j;
	        E(K, kbytes,0,i,buf,0,buf,0);
	        xor_bytes(L, buf, 16, L);

	        memset(buf,0,(byte)0x00, 16);
	        memcpy(buf,0,L,0,(inbytes+1)/2);
	        buf[inbytes/2] = (byte) ((buf[inbytes/2] & mask) | pad);
	        xor_bytes(buf, delta, 16, buf);
	        buf[15] ^= (byte)((int)j+step);
	        E(K, kbytes,0,i,buf,0,buf,0);
	        xor_bytes(R, buf, 16, R);
	    }
	    memcpy(buf,0,R,0, inbytes/2);
	    memcpy(buf,inbytes/2, L,0, (inbytes+1)/2);
	    if ((inbytes&1)>0) {
	        for (k=inbytes-1; k>inbytes/2; k--)
	            buf[k] = (byte)((buf[k] >> 4) | (buf[k-1] << 4));
	        buf[inbytes/2] = (byte)((L[0] >> 4) | (R[inbytes/2] & 0xf0));
	    }
	    memcpy(out,0,buf,0,inbytes);
	    if ((inbytes < 16) && !(d==1)) {
	        memset(buf,inbytes,(byte)0x00,16-inbytes); buf[0] |= 0x80;
	        xor_bytes(delta, buf, 16, buf);
	        E(K, kbytes,0,3,buf,0,buf,0);
	        out[0] ^= (buf[0] & 0x80);
	    }
	}
	/* Set d=0 for EncipherAEZcore and d=1 for DecipherAEZcore */
	static void AEZcore(byte[] K, int kbytes, byte delta[/*16*/],
	                        byte[] in, int inbytes, int d, byte[] out) {
	    byte[] tmp = new byte[16]; byte[] X= new byte[16];
	    byte[] Y =new byte[16]; byte[] S = new byte[16];
	    byte[] in_orig = in; byte[] out_orig = out;
	    int i, inbytes_orig = inbytes;
	    int inOffset=0;
	    int outOffset =0;

	    memset(X,0,(byte)0x00,16); memset(Y,0,(byte)0x00,16);

	    /* Pass 1 over in[0:-32], store intermediate values in out[0:-32] */
	    for (i=1; inbytes >= 64; i++, inbytes-=32,inOffset +=i*32,outOffset += i*32/* in+=32, out+=32*/) {
	        E(K, kbytes, 1, i, in, 16+inOffset, tmp,0); xor_bytesWithOffset(in,inOffset, tmp,0, 16, out,outOffset);
	        E(K, kbytes, 0, 0, out,0, tmp,0); xor_bytesWithOffset(in, 16+inOffset, tmp,0, 16, out,16+outOffset);
	        xor_bytesWithOffset(out, 16+outOffset, X,0, 16, X,0);
	    }
	    //System.out.println("AEZcore 1");
	    /* Finish X calculation */
	    inbytes -= 32;                /* inbytes now has fragment length 0..31 */
	    if (inbytes >= 16) {
	        E(K, kbytes, 0, 4, in,inOffset, tmp,0); xor_bytes(X, tmp, 16, X);
	        inbytes -= 16; /*in += 16; out += 16;*/
	        inOffset +=16; outOffset +=16;
	        memset(tmp,0,(byte)0x00,16); memcpy(tmp,0,in,16+inOffset,inbytes); tmp[inbytes] = (byte)0x80;
	        E(K, kbytes, 0, 5, tmp,0, tmp,0); xor_bytes(X, tmp, 16, X);
	    } else if (inbytes > 0) {
	        memset(tmp,0,(byte)0x00,16); memcpy(tmp,0,in,inOffset,inbytes); tmp[inbytes] = (byte)0x80;
	        E(K, kbytes, 0, 4, tmp,0, tmp,0); xor_bytes(X, tmp, 16, X);
	    }
	    //System.out.println("AEZcore 2");
	    //in += inbytes; out += inbytes;
	    inOffset +=inbytes; outOffset += inbytes;
	    
	    /* Calculate S */
	    E(K, kbytes, 0, 1+d, in,16+inOffset, tmp,0);
	    xor_bytesWithOffset(X,0, in,inOffset, 16, out, outOffset);
	    xor_bytesWithOffset(delta, 0, out,outOffset, 16, out, outOffset);
	    xor_bytesWithOffset(tmp,0, out,outOffset, 16, out, outOffset);
	    E(K, kbytes, -1, 1+d, out,outOffset, tmp,0);
	    xor_bytesWithOffset(in,16+inOffset, tmp,0, 16, out,16+outOffset);
	    xor_bytesWithOffset(out,outOffset, out,16+outOffset, 16, S,0);
	    
	    //System.out.println("AEZcore 3");
	    /* Pass 2 over intermediate values in out[32..]. Final values written */
	    inbytes = inbytes_orig; out = out_orig; in = in_orig;
	    inOffset=0; outOffset=0;// Using the original byte array, so discard the offsets
	    for (i=1; inbytes >= 64; i++, inbytes-=32,inOffset +=(i-1)*32,outOffset +=(i-1)*32/*, in+=32, out+=32*/) {
	        E(K, kbytes, 2, i, S,0, tmp,0);
	        xor_bytesWithOffset(out,outOffset, tmp,0, 16, out, outOffset); 
	        xor_bytesWithOffset(out,16+outOffset, tmp,0, 16, out,16+outOffset);
	        xor_bytesWithOffset(out, outOffset, Y,0, 16, Y,0);
	        E(K, kbytes, 0, 0, out,16+outOffset, tmp,0); xor_bytesWithOffset(out,outOffset, tmp,0, 16, out, outOffset);
	        E(K, kbytes, 1, i, out,outOffset, tmp,0); xor_bytesWithOffset(out,16+outOffset, tmp,0, 16, out,16+outOffset);
	        memcpy(tmp,0, out,outOffset, 16); memcpy(out,0, out,16+outOffset, 16); memcpy(out,16+outOffset, tmp,0, 16);
	    }
	    /* Finish Y calculation and finish encryption of fragment bytes */
	    inbytes -= 32;                /* inbytes now has fragment length 0..31 */
	    if (inbytes >= 16) {
	        E(K, kbytes, -1, 4, S,0, tmp,0); xor_bytesWithOffset(in,inOffset, tmp,0, 16, out, outOffset);
	        E(K, kbytes, 0, 4, out,outOffset, tmp,0); xor_bytes(Y, tmp, 16, Y);
	        // in += 16; out += 16;
	        inbytes -= 16; inOffset +=16; outOffset += 16;
	        E(K, kbytes, -1, 5, S,0, tmp,0); xor_bytesWithOffset(in,inOffset, tmp,0, inbytes, tmp,0);
	        memcpy(out,outOffset,tmp,0,inbytes);
	        memset(tmp,inbytes,(byte)0x00,16-inbytes); tmp[inbytes] = (byte)0x80;
	        E(K, kbytes, 0, 5, tmp,0, tmp,0); xor_bytes(Y, tmp, 16, Y);
	    } else if (inbytes > 0) {
	        E(K, kbytes, -1, 4, S,0, tmp,0); xor_bytesWithOffset(in,inOffset, tmp,0, inbytes, tmp,0);
	        memcpy(out,outOffset,tmp,0,inbytes);
	        memset(tmp,inbytes,(byte)0x00,16-inbytes); tmp[inbytes] = (byte)0x80;
	        E(K, kbytes, 0, 4, tmp,0, tmp,0); xor_bytes(Y, tmp, 16, Y);
	    }
	    //in += inbytes; out += inbytes;
	    inOffset +=inbytes; outOffset += inbytes;

	    /* Finish encryption of last two blocks */
	    E(K, kbytes, -1, 2-d, out,16+outOffset, tmp,0);
	    xor_bytesWithOffset(out,outOffset, tmp,0, 16, out,outOffset);
	    E(K, kbytes, 0, 2-d, out,outOffset, tmp,0);
	    xor_bytesWithOffset(tmp,0, out,16+outOffset, 16, out,16+outOffset);
	    xor_bytesWithOffset(delta,0, out,16+outOffset, 16, out,16+outOffset);
	    xor_bytesWithOffset(Y,0, out,16+outOffset, 16, out,16+outOffset);
	    memcpy(tmp,0, out,outOffset, 16); memcpy(out,outOffset, out,16+outOffset, 16); memcpy(out,16+outOffset, tmp,0, 16);
	}


	static void Encipher(byte[] K, int kbytes, byte delta[/*16*/],
            byte[] in, int inbytes, byte[] out) {
		if (inbytes == 0) return;
		if (inbytes < 32) AEZtiny(K, kbytes, delta, in, inbytes, 0, out);
		else              AEZcore(K, kbytes, delta, in, inbytes, 0, out);
	}
	static void Decipher(byte[] K, int kbytes, byte delta[/*16*/],
            byte[] in, int inbytes, byte[] out) {
		if (inbytes == 0) return;
		if (inbytes < 32) AEZtiny(K, kbytes, delta, in, inbytes, 1, out);
		else              AEZcore(K, kbytes, delta, in, inbytes, 1, out);
	}
	static void Encrypt(byte[] K, int kbytes,byte[] N, int nbytes,
            byte[] AD, int adbytes, int veclen, int abytes,
            byte[] M, int mbytes, byte[] C) {
		byte[] delta = new byte[16];
		
		AEZhash(K, kbytes, N, nbytes, AD, adbytes, veclen, abytes*8, delta);
		print("delta", delta, 16, 0);

		if (mbytes==0) {
			AEZprf(K, kbytes, delta, abytes, C);
		} else {
			byte[] X = new byte[mbytes+abytes];
			memcpy(X,0, M,0, mbytes); memset(X,mbytes,(byte)0x00,abytes);
			Encipher(K, kbytes, delta, X, mbytes+abytes, X);
			memcpy(C,0, X,0, mbytes+abytes);		
   		}
	}
	
	static int crypto_aead_encrypt(byte c[], int clen, byte m[], int mlen, byte ad[], int adlen,
		      byte nsec[], byte npub[], byte k[]) {
		//byte *AD[] = {(byte[])ad}; veclen is 1, so no need to use this array
	    //unsigned adbytes[] = {(unsigned)adlen};

	    clen = mlen+16;
	    Encrypt(k, 16, npub, 12, ad, adlen, 1, 16, m, mlen, c);
		return clen;
	}
	
	static int Decrypt(byte[] K, int kbytes, byte[] N, int nbytes,
            byte[] AD, int adbytes,int  veclen, int abytes,
            byte[] C, int cbytes, byte []M) {
	    byte[] delta = new byte[16];
	    int i;
	    if (cbytes < abytes) return -1;
	    AEZhash(K, kbytes, N, nbytes, AD, adbytes, veclen, abytes*8, delta);
	    byte[] X = new byte[cbytes];
	    byte sum = 0;
	    if (cbytes==abytes) {
	        AEZprf(K, kbytes, delta, abytes, X);
	        for (i=0; i<abytes; i++) sum |= (X[i] ^ C[i]);
	    } else {
	        Decipher(K, kbytes, delta, C, cbytes, X);
	        for (i=0; i<abytes; i++) sum |= X[cbytes-abytes+i];
	        if (sum==0) memcpy(M,0,X,0,cbytes-abytes);
	    }

	    return (sum == 0 ? 0 : -1);  /* return 0 if valid, -1 if invalid */
	}

	static int crypto_aead_decrypt(byte m[], int mlen, byte nsec[], byte c[], int clen, byte ad[],
		      int adlen, byte npub[], byte k[]) {
		/*
		byte *AD[] = {(byte[])ad};
	    unsigned adbytes[] = {(unsigned)adlen};
		*/
	    if (mlen>0) mlen = clen-16;
	    Decrypt(k, 16, npub, 12, ad,
	                    adlen, 1, 16, c, clen, m);
	     
		return mlen;
	}
}
