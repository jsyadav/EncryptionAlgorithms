#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>

#define maj(x,y,z)     (  ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))  )
#define ch(x,y,z)      (  ((x) & (y)) ^ ( ((x) ^ 1) & (z))  )


extern void printjbarray(jbyteArray array, JNIEnv* env, char* msg);

void printstate(char* text, unsigned char* S) {
    int i;
    printf("%s(%lu)\n", text,sizeof(S));
    for (i = 0; i < 293; ++i)
        printf("%02x", S[i]);
    printf("\n");
}

unsigned char KSG128(unsigned char *state)
{
    return ( state[12] ^ state[154] ^ maj(state[235], state[61], state[193]) );
}

unsigned char FBK128(unsigned char *state, unsigned char *ks, unsigned char ca, unsigned char cb)
{
    unsigned char f;
    *ks = KSG128(state);
    f  = state[0] ^ (state[107] ^ 1) ^ maj(state[244], state[23], state[160]) ^ ch(state[230], state[111], state[66]) ^ (ca & state[196]) ^ (cb & (*ks));
    return f;
}

//encrypt one bit
void Encrypt_StateUpdate128_1bit(unsigned char *state, unsigned char plaintextbit, unsigned char *ciphertextbit, unsigned char *ks, unsigned char ca, unsigned char cb)
{
    unsigned int  j;
    unsigned char f;

    state[289] ^= state[235] ^ state[230];
    state[230] ^= state[196] ^ state[193];
    state[193] ^= state[160] ^ state[154];
    state[154] ^= state[111] ^ state[107];
    state[107] ^= state[66]  ^ state[61];
    state[61]  ^= state[23]  ^ state[0];

    f  = FBK128(state, ks, ca, cb);

    for (j = 0; j <= 291; j++) state[j] = state[j+1];
    state[292] = f ^ plaintextbit;
    *ciphertextbit = *ks ^ plaintextbit;
}


//decrypt one bit
void Decrypt_StateUpdate128_1bit(unsigned char *state, unsigned char *plaintextbit, unsigned char ciphertextbit, unsigned char *ks, unsigned char ca, unsigned char cb)
{
    unsigned int  j;
    unsigned char f;

    state[289] ^= state[235] ^ state[230];
    state[230] ^= state[196] ^ state[193];
    state[193] ^= state[160] ^ state[154];
    state[154] ^= state[111] ^ state[107];
    state[107] ^= state[66]  ^ state[61];
    state[61]  ^= state[23]  ^ state[0];

    f = FBK128(state, ks, ca, cb);

    for (j = 0; j <= 291; j++) state[j] = state[j+1];
    *plaintextbit = *ks ^ ciphertextbit;
    state[292] = f ^ *plaintextbit;
}

// encrypt one byte
void acorn128_enc_onebyte(unsigned char *state, unsigned char plaintextbyte,
                          unsigned char *ciphertextbyte, unsigned char *ksbyte, unsigned char cabyte, unsigned char cbbyte)
{
    unsigned char i;
    unsigned char plaintextbit,ciphertextbit,kstem,ca,cb;

    *ciphertextbyte = 0;
    kstem = 0;
    *ksbyte = 0;
    for (i = 0; i < 8; i++)
    {
        ca = (cabyte >> i) & 1;
        cb = (cbbyte >> i) & 1;
        plaintextbit = (plaintextbyte >> i) & 1;
        Encrypt_StateUpdate128_1bit(state, plaintextbit, &ciphertextbit, &kstem, ca, cb);
        *ciphertextbyte |= (ciphertextbit << i);
        *ksbyte |= (kstem << i);
    }
}


// decrypt one byte
void acorn128_dec_onebyte(unsigned char *state, unsigned char *plaintextbyte,
                          unsigned char ciphertextbyte, unsigned char *ksbyte, unsigned char cabyte, unsigned char cbbyte)
{
    unsigned char i;
    unsigned char plaintextbit,ciphertextbit, ks,ca,cb;

    *plaintextbyte = 0;
    for  (i = 0; i < 8; i++)
    {
        ca = (cabyte >> i) & 1;
        cb = (cbbyte >> i) & 1;
        ciphertextbit = (ciphertextbyte >> i) & 1;
        Decrypt_StateUpdate128_1bit(state, &plaintextbit, ciphertextbit, &ks, ca, cb);
        *plaintextbyte |= (plaintextbit << i);
    }

}

//The initialization state of ACORN
/*The input to initialization is the 128-bit key; 128-bit IV;*/
void acorn128_initialization(const unsigned char *key, const unsigned char *iv, unsigned char *state)
{
    int i,j;
    unsigned char m[293], ks, tem;

    //initialize the state to 0
    for (j = 0; j <= 292; j++)  state[j] = 0;

    //set the value of m
    for (j = 0; j <=  15;   j++)   m[j] = key[j];
    for (j = 16; j <= 31;   j++)   m[j] = iv[j - 16];
    for (j = 32; j <= 223;  j++)   m[j] = key[j & 0xf];
    m[32] ^= 1;

    //run the cipher for 1792 steps
    for (i = 0; i < 224; i++)
    {
        acorn128_enc_onebyte(state, m[i], &tem, &ks, 0xff, 0xff);

    }
}


//the finalization state of acorn
void acorn128_tag_generation(unsigned long long msglen, unsigned long long adlen, unsigned char maclen, unsigned char *mac, unsigned char *state)
{
    int i;
    unsigned char plaintextbyte  = 0;
    unsigned char ciphertextbyte = 0;
    unsigned char ksbyte = 0;

    for (i = 0; i < 768/8; i++)
    {
        acorn128_enc_onebyte(state, plaintextbyte, &ciphertextbyte, &ksbyte, 0xff, 0xff);
        if ( i >= (768/8 - 16) ) {mac[i-(768/8-16)] = ksbyte; }
    }
}

//encrypt a message.
int acorn_crypto_aead_encrypt(
        unsigned char *c,unsigned long long *clen,
        const unsigned char *m,unsigned long long mlen,
        const unsigned char *ad,unsigned long long adlen,
        const unsigned char *nsec,
        const unsigned char *npub,
        const unsigned char *k
)
{
    unsigned long long i;
    unsigned char plaintextbyte, ciphertextbyte, ksbyte, mac[16];
    unsigned char state[293];
    unsigned char ca, cb;

    //initialization stage
    acorn128_initialization(k, npub, state);


    //process the associated data
    for (i = 0; i < adlen; i++)
    {
        acorn128_enc_onebyte(state, ad[i], &ciphertextbyte, &ksbyte, 0xff, 0xff);
    }

    for (i = 0; i < 256/8; i++)
    {
        if ( i == 0 ) plaintextbyte = 0x1;
        else plaintextbyte = 0;

        if ( i < 128/8)   ca = 0xff;
        else ca = 0;

        cb = 0xff;

        acorn128_enc_onebyte(state, plaintextbyte, &ciphertextbyte, &ksbyte, ca, cb);
    }


    //process the plaintext
    for (i = 0; i < mlen; i++)
    {
        acorn128_enc_onebyte(state, m[i], &(c[i]), &ksbyte, 0xff, 0 );
    }

    for (i = 0; i < 256/8; i++)
    {
        if (i == 0) plaintextbyte = 0x1;
        else plaintextbyte = 0;

        if ( i < 128/8)   ca = 0xff;
        else ca = 0;

        cb = 0;
        acorn128_enc_onebyte(state, plaintextbyte, &ciphertextbyte, &ksbyte, ca, cb);
    }

    //finalization stage, we assume that the tag length is a multiple of bytes
    acorn128_tag_generation(mlen, adlen, 16, mac, state);

    *clen = mlen + 16;
    memcpy(c+mlen, mac, 16);

    //return 0;
    return *clen;
}


int acorn_crypto_aead_decrypt(
        unsigned char *m,unsigned long long *mlen,
        unsigned char *nsec,
        const unsigned char *c,unsigned long long clen,
        const unsigned char *ad,unsigned long long adlen,
        const unsigned char *npub,
        const unsigned char *k
)
{
    unsigned long long i;
    unsigned char plaintextbyte, ciphertextbyte, ksbyte;
    unsigned char state[293];
    unsigned char tag[16];
    unsigned char check = 0;
    unsigned char ca, cb;

    if (clen < 16) return -1;

    //initialization stage
    acorn128_initialization(k, npub, state);


    //process the associated data
    for (i = 0; i < adlen; i++)
    {
        acorn128_enc_onebyte(state, ad[i], &ciphertextbyte, &ksbyte, 0xff, 0xff);
    }

    for (i = 0; i < 256/8; i++)
    {
        if ( i == 0 ) plaintextbyte = 0x1;
        else plaintextbyte = 0;

        if ( i < 128/8)   ca = 0xff;
        else ca = 0;

        cb = 0xff;

        acorn128_enc_onebyte(state, plaintextbyte, &ciphertextbyte, &ksbyte, ca, cb);
    }

    //process the ciphertext
    *mlen = clen - 16;

    for (i = 0; i < *mlen; i++)
    {
        acorn128_dec_onebyte(state, &m[i], c[i], &ksbyte, 0xff, 0);
    }

    for (i = 0; i < 256/8; i++)
    {
        if ( i == 0 ) plaintextbyte = 0x1;
        else plaintextbyte = 0;

        if ( i < 128/8)   ca = 0xff;
        else ca = 0;

        cb = 0;

        acorn128_enc_onebyte(state, plaintextbyte, &ciphertextbyte, &ksbyte, ca, cb);
    }

    //finalization stage, we assume that the tag length is a multiple of bytes
    acorn128_tag_generation(*mlen, adlen, 16, tag, state);

    for (i = 0; i  < 16; i++) check |= (tag[i] ^ c[clen - 16 + i]);
    if (check == 0) return *mlen;//return 0;
    else return -1;
}



extern unsigned char* ba2uc(jbyteArray array,JNIEnv* env) ;

extern "C"
jint
Java_com_example_jyadav_encryptionalgorithms_MainActivity_acorn_1crypto_1aead_1encrypt(
        JNIEnv *e, jobject o, jbyteArray c, jint clen,
        jbyteArray m, jint mlen, jbyteArray ad, jint adlen,
        jbyteArray nsec, jbyteArray npub, jbyteArray k)
{
    //printjbarray(m,e,"msg");
    //printjbarray(ad,e,"ad");
    //printjbarray(nsec,e,"nsec");
    //printjbarray(npub,e,"npub");
    //printjbarray(k,e,"key");

    unsigned char cipher[clen];
    unsigned long long len;

    jint i =  acorn_crypto_aead_encrypt(
            cipher, &len, ba2uc(m,e), mlen,
            ba2uc(ad,e), adlen, ba2uc(nsec,e), ba2uc(npub,e), ba2uc(k,e));

    e->SetByteArrayRegion(c, 0, len, (const jbyte*) cipher);
    //printjbarray(c,e,"cipher");
    return len;
}


extern "C"
jint
Java_com_example_jyadav_encryptionalgorithms_MainActivity_acorn_1crypto_1aead_1decrypt(
        JNIEnv *e, jobject o, jbyteArray m, jint mlen, jbyteArray nsec,
        jbyteArray c, jint clen, jbyteArray ad, jint adlen,
        jbyteArray npub, jbyteArray k)
{
    //printjbarray(c,e,"cipher");
    //printjbarray(ad,e,"ad");
    //printjbarray(nsec,e,"nsec");
    //printjbarray(npub,e,"npub");
    //printjbarray(k,e,"key");

    unsigned char msg[mlen];
    unsigned long long len;

    jint i =  acorn_crypto_aead_decrypt(
            msg, &len, ba2uc(nsec,e), ba2uc(c,e), clen,
            ba2uc(ad,e), adlen,  ba2uc(npub,e), ba2uc(k,e));

    e->SetByteArrayRegion(m, 0, len, (const jbyte*) msg);
    //printjbarray(m,e,"plain");
    return len;
}