#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _MSC_VER
#define inline __inline
#endif

#define BS 16		// block size in byte
#define PBS 8

typedef uint64_t u64;
#define ROTL( n, X )    ( ( ( X ) << n ) | ( ( X ) >> ( 32 - n ) ) )
#define ROTL2( n, X, L )    ( ( ( X ) << ( n + 64 - L ) >> (64-L)) | ( ( X ) >> ( L - n ) ) )

char Simonz[5][65] =
        {"11111010001001010110000111001101111101000100101011000011100110",
         "10001110111110010011000010110101000111011111001001100001011010",
         "10101111011100000011010010011000101000010001111110010110110011",
         "11011011101011000110010111100000010010001010011100110100001111",
         "11010001111001101011011000100000010111000011001010010011101111"};

void SimonKeySetup128(const unsigned char *rk, uint64_t *rkexp) {
    int mm = 2;
    int nn = 64;
    int i, j = 0;

    uint64_t tmp = 0;
    uint64_t t1;

    rkexp[0] = ((uint64_t *) rk)[0];
    rkexp[1] = ((uint64_t *) rk + 1)[0];

    for (i = mm; i < 68; i++) {
        tmp = ROTL2((nn - 3), rkexp[i - 1], nn);
        tmp = tmp ^ ROTL2((nn - 1), tmp, nn);
        rkexp[i] = (~(rkexp[i - mm])) ^ tmp ^ (Simonz[2][(i - mm) % 62] - '0') ^ 3;

    };
}

#define LCS ROTL //left circular shift
#define f(x) ((LCS(x,1) & LCS(x,8)) ^ LCS(x,2))
#define R2(x, y, k1, k2) (y^=f(x), y^=k1, x^=f(y), x^=k2)


void SimonEncrypt128(uint64_t *SR, uint64_t *SL, const uint64_t k[]) {
    uint64_t i;
    for (i = 0; i < 68; i += 2) R2(SR[0], SL[0], k[i], k[i + 1]);
}


#define print 1
void printjbarray(jbyteArray array, JNIEnv* env, char* msg){
#if print==1
    jint len = env->GetArrayLength(array);
    __android_log_print(ANDROID_LOG_DEBUG, "LOG_TAG", "%s[%d]", msg, len);
    unsigned char* buf = (unsigned char*)malloc(sizeof(unsigned char)*len);
    jbyte *body = env->GetByteArrayElements(array, 0);
    for (int i = 0;i < len;i++){
        buf[i] = body[i];
        __android_log_print(ANDROID_LOG_DEBUG, "LOG_TAG", "%0X-",buf[i]);

    }
    __android_log_print(ANDROID_LOG_DEBUG, "LOG_TAG", "\n");
    env->ReleaseByteArrayElements(array, body, 0);
#endif
}

unsigned char* ba2uc(jbyteArray array,JNIEnv* env) {
    jint len = env->GetArrayLength(array);
    //printf("ba2uc %d\n",len);
    unsigned char* buf = (unsigned char*)malloc(sizeof(unsigned char)*len);
    jboolean isCopy;
    jbyte *body = env->GetByteArrayElements(array, &isCopy);
    for (int i = 0;i < len;i++)  buf[i] = body[i];
    // we don't need body array, since it is copied in buf
    env->ReleaseByteArrayElements(array,body,0);
    return buf;
}
// plaintext block size in byte

void jambu_initialization(const uint64_t *rk, const uint8_t *iv, uint64_t *stateS, uint64_t *stateR)
{
    /* load iv */
    stateS[0] = ((uint64_t *)iv)[0];

    /* update stateS with encryption */
    SimonEncrypt128(stateS, stateS + 1, rk);

    /* constant injection */
    stateS[0] ^= 0x5;

    /* stateR initialization */
    stateR[0] = stateS[1];

    return;
}

void jambu_tag_generation(const uint64_t *rk, uint64_t msglen, uint8_t *c, uint64_t *stateS, uint64_t *stateR)
{

    SimonEncrypt128(stateS, stateS + 1, rk);

    stateS[0] ^= stateR[0] ^ 0x03;
    stateR[0] ^= stateS[1];

    SimonEncrypt128(stateS, stateS + 1, rk);
    ((uint64_t *)(c+msglen))[0] = stateS[0] ^ stateS[1] ^ stateR[0];
}

int jambu_tag_verification(const uint64_t *rk, uint64_t msglen, const uint8_t *c, uint64_t *stateS, uint64_t *stateR)
{
    uint8_t t[8];
    int check = 0;
    int i;

    SimonEncrypt128(stateS, stateS + 1, rk);
    stateS[0] ^= stateR[0] ^ 0x03;
    stateR[0] ^= stateS[1];

    SimonEncrypt128(stateS, stateS + 1, rk);

    ((uint64_t *)t)[0] = stateS[0] ^ stateS[1] ^ stateR[0];
    for (i = 0; i < PBS; i++) check |= (c[msglen+i] ^ t[i]);
    if (0 == check) return 1; else return -1;
}

void jambu_aut_ad_step(const uint64_t *rk, const uint8_t *adblock,
                       uint64_t *stateS, uint64_t *stateR)
{
    SimonEncrypt128(stateS, stateS + 1, rk);
    stateS[0] ^= stateR[0] ^ 0x01;
    stateS[1] ^= ((uint64_t *)adblock)[0];
    stateR[0] ^= stateS[1];

    return;
}

void jambu_aut_ad_partial(const uint64_t *rk, const uint8_t *adblock,
                          uint64_t *stateS, uint64_t *stateR, uint64_t len)
{
    uint8_t p[8];

    memcpy(p, adblock, len);

    p[len] = 0x80; // pad '1'
    memset(p+len+1, 0, 7-len); // pad '0'

    SimonEncrypt128(stateS, stateS + 1, rk);
    stateS[0] ^= stateR[0] ^ 0x01;
    stateS[1] ^= ((uint64_t *)p)[0];
    stateR[0] ^= stateS[1];

    return;
}

void jambu_aut_ad_full(const uint64_t *rk, uint64_t *stateS, uint64_t *stateR)
{
    SimonEncrypt128(stateS, stateS + 1, rk);

    stateS[0] ^= stateR[0] ^ 0x01;
    stateS[1] ^= 0x80;
    stateR[0] ^= stateS[1];

    return;
}

void jambu_enc_aut_msg_step(const uint64_t *rk, const uint8_t *plaintextblk,
                            uint8_t *ciphertextblk, uint64_t *stateS, uint64_t *stateR)
{
    SimonEncrypt128(stateS, stateS + 1, rk);

    stateS[0] ^= stateR[0];
    stateS[1] ^= ((uint64_t *)plaintextblk)[0];
    stateR[0] ^= stateS[1];
    ((uint64_t *)ciphertextblk)[0] = stateS[0] ^ ((uint64_t *)plaintextblk)[0];

    return;
}

/* Deal with partial final block */
void jambu_enc_aut_msg_partial(const uint64_t *rk, const uint8_t *plaintextblk,
                               uint8_t *ciphertextblk, uint64_t *stateS, uint64_t *stateR, unsigned int len)
{
    uint8_t p[8];

    memcpy(p, plaintextblk, len);

    p[len] = 0x80; // pad '1'
    memset(p+len+1, 0, 7-len);// pad '0'

    SimonEncrypt128(stateS, stateS + 1, rk);
    stateS[0] ^= stateR[0];
    stateS[1] ^= ((uint64_t *)p)[0];
    stateR[0] ^= stateS[1];
    ((uint64_t *)ciphertextblk)[0] = stateS[0] ^ ((uint64_t *)p)[0];

    return;
}

void jambu_enc_aut_msg_full(const uint64_t *rk, uint64_t *stateS, uint64_t *stateR)
{

    SimonEncrypt128(stateS, stateS + 1, rk);

    stateS[0] ^= stateR[0];
    stateS[1] ^= 0x80;
    stateR[0] ^= stateS[1];

    return;
}

void jambu_dec_aut_msg_step(const uint64_t *rk, uint8_t *plaintextblk, const uint8_t *ciphertextblk, uint64_t *stateS, uint64_t *stateR)
{
    SimonEncrypt128(stateS, stateS + 1, rk);

    stateS[0] ^= stateR[0];
    ((uint64_t *)plaintextblk)[0] = stateS[0] ^ ((uint64_t *)ciphertextblk)[0];
    stateS[1] ^= ((uint64_t *)plaintextblk)[0];
    stateR[0] ^= stateS[1];


}

void jambu_dec_aut_partial(const uint64_t *rk, uint8_t *plaintextblk, const uint8_t *ciphertextblk, uint64_t *stateS, uint64_t *stateR, unsigned int len)
{
    uint8_t p[8];

    SimonEncrypt128(stateS, stateS + 1, rk);
    stateS[0] ^= stateR[0];
    ((uint64_t *)p)[0] = stateS[0] ^ ((uint64_t *)ciphertextblk)[0];
    p[len] = 0x80;
    memset(p+len+1, 0, 7-len);
    memcpy(plaintextblk, p, len);

    stateS[1] ^= ((uint64_t *)p)[0];
    stateR[0] ^= stateS[1];

}

int simon_crypto_aead_encrypt(
        unsigned char *c,unsigned long long *clen,
        const unsigned char *m,unsigned long long mlen,
        const unsigned char *ad,unsigned long long adlen,
        const unsigned char *nsec,
        const unsigned char *npub,
        const unsigned char *k
)
{
    unsigned int i;
    uint64_t jambu_state[2];
    uint64_t stateR[1];
    uint64_t EK[68]; // 68 round keys for Simon128/128

    // key expansion
    SimonKeySetup128(k, EK);

    // Initialization
    memset(jambu_state, 0, BS);
    memset(stateR, 0, (BS>>1));
    jambu_initialization(EK, npub, jambu_state, stateR);

    // process the associated data
    for (i = 0; (i + PBS) <= adlen; i += PBS) {
        jambu_aut_ad_step(EK, ad+i, jambu_state, stateR);
    }

    // deal with the partial block of associated data
    // in this program, we assume that the message length is a multiple of bytes.
    if ((adlen & (PBS-1)) != 0)  {
        jambu_aut_ad_partial(EK, ad + i, jambu_state, stateR, adlen & (PBS-1));
    }
    else
    {
        jambu_aut_ad_full(EK, jambu_state, stateR);
    }

    // encrypt the plaintext, we assume that the message length is multiple of bytes.
    for (i = 0; (i + PBS) <= mlen; i += PBS) {
        jambu_enc_aut_msg_step(EK, m+i, c+i, jambu_state, stateR);
    }

    // deal with the final plaintext block
    if ((mlen & (PBS-1)) != 0) {
        jambu_enc_aut_msg_partial(EK, m + i, c + i, jambu_state, stateR, mlen & (PBS-1));
    }
    else
    {
        jambu_enc_aut_msg_full(EK, jambu_state, stateR);
    }

    // finalization stage, we assume that the tag length is a multiple of bytes
    jambu_tag_generation(EK, mlen, c, jambu_state, stateR);
    *clen = mlen + PBS;
    return 0;
}

int simon_crypto_aead_decrypt(
        unsigned char *m,unsigned long long *mlen,
        unsigned char *nsec,
        const unsigned char *c,unsigned long long clen,
        const unsigned char *ad,unsigned long long adlen,
        const unsigned char *npub,
        const unsigned char *k
)
{
    unsigned int i;
    uint8_t check = 0;
    uint64_t jambu_state[BS >> 2];
    uint64_t stateR[BS >> 3];
    uint64_t EK[68];

    // key expansion
    SimonKeySetup128(k, EK);

    // Initialization
    memset(jambu_state, 0, BS);
    memset(stateR, 0, PBS);
    jambu_initialization(EK, npub, jambu_state, stateR);

    // process the associated data
    for (i = 0; (i + PBS) <= adlen; i += PBS) {
        jambu_aut_ad_step(EK, ad+i, jambu_state, stateR);
    }

    // deal with the partial block of associated data
    // in this program, we assume that the message length is a multiple of bytes.
    if (  (adlen & (PBS - 1)) != 0 )  {
        jambu_aut_ad_partial(EK, ad + i, jambu_state, stateR, adlen & (PBS - 1));
    }
    else
    {
        jambu_aut_ad_full(EK, jambu_state, stateR);
    }

    // decrypt the ciphertext
    *mlen = clen - PBS;
    for (i = 0; (i + PBS) <= *mlen; i = i + PBS) {
        jambu_dec_aut_msg_step(EK, m+i, c+i, jambu_state, stateR);
    }

    // deal with the final block
    if (((*mlen) & (PBS - 1)) != 0) {
        jambu_dec_aut_partial(EK, m+i, c+i, jambu_state, stateR, *mlen & (PBS - 1));
    }
    else
    {
        jambu_enc_aut_msg_full(EK, jambu_state, stateR);
    }

    // verification, we assume that the tag length is a multiple of bytes
    return jambu_tag_verification(EK, *mlen, c, jambu_state, stateR);
}


extern "C"
jint
Java_com_example_jyadav_encryptionalgorithms_MainActivity_simon_1crypto_1aead_1encrypt(
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

    jint i =  simon_crypto_aead_encrypt(
            cipher, &len, ba2uc(m,e), mlen,
            ba2uc(ad,e), adlen, ba2uc(nsec,e), ba2uc(npub,e), ba2uc(k,e));

    e->SetByteArrayRegion(c, 0, len, (const jbyte*) cipher);
    //printjbarray(c,e,"cipher");
    return len;
}


extern "C"
jint
Java_com_example_jyadav_encryptionalgorithms_MainActivity_simon_1crypto_1aead_1decrypt(
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

    jint i =  simon_crypto_aead_decrypt(
            msg, &len, ba2uc(nsec,e), ba2uc(c,e), clen,
            ba2uc(ad,e), adlen,  ba2uc(npub,e), ba2uc(k,e));

    e->SetByteArrayRegion(m, 0, len, (const jbyte*) msg);
    //printjbarray(m,e,"plain");
    return len;
}