package com.example.jyadav.encryptionalgorithms;

import android.net.Uri;
import android.os.SystemClock;
import android.provider.Settings;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.EditText;

import com.google.android.gms.appindexing.Action;
import com.google.android.gms.appindexing.AppIndex;
import com.google.android.gms.appindexing.Thing;
import com.google.android.gms.common.api.GoogleApiClient;

public class MainActivity extends AppCompatActivity {
    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    Button acorn_btn, acorn_btn_jni, jambu_btn, jambu_btn_jni, norx_btn, norx_btn_jni, aez_btn, aez_btn_jni;
    TextView acorn, acorn_jni, jambu, jambu_jni, norx, norx_jni, aez, aez_jni;
    EditText msgSize, iterations;


    int MLEN = 32;
    int ITER = 1000;
    int i;
    int mlen, alen, clen;
    byte a[],m[],c[],p[];

    private native int simon_crypto_aead_encrypt(byte c[], int clen,byte m[], int mlen,
                                           byte ad[], int adlen, byte nsec[],
                                           byte npub[],byte k[]);

    private native int simon_crypto_aead_decrypt(byte m[], int mlen, byte nsec[],
                                           byte c[], int clen, byte ad[],
                                           int adlen, byte npub[], byte k[]) ;

    private native int acorn_crypto_aead_encrypt(byte c[], int clen,byte m[], int mlen,
                                                 byte ad[], int adlen, byte nsec[],
                                                 byte npub[],byte k[]);

    private native int acorn_crypto_aead_decrypt(byte m[], int mlen, byte nsec[],
                                                 byte c[], int clen, byte ad[],
                                                 int adlen, byte npub[], byte k[]) ;

    private native int norx_crypto_aead_encrypt(byte c[], int clen,byte m[], int mlen,
                                                 byte ad[], int adlen, byte nsec[],
                                                 byte npub[],byte k[]);

    private native int norx_crypto_aead_decrypt(byte m[], int mlen, byte nsec[],
                                                 byte c[], int clen, byte ad[],
                                                 int adlen, byte npub[], byte k[]) ;

    private native int aez_crypto_aead_encrypt(byte c[], int clen,byte m[], int mlen,
                                                byte ad[], int adlen, byte nsec[],
                                                byte npub[],byte k[]);

    private native int aez_crypto_aead_decrypt(byte m[], int mlen, byte nsec[],
                                                byte c[], int clen, byte ad[],
                                                int adlen, byte npub[], byte k[]) ;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Get all the text view
        acorn = (TextView) findViewById(R.id.acorn);
        acorn_jni = (TextView) findViewById(R.id.acorn_jni);
        jambu = (TextView) findViewById(R.id.jambu);
        jambu_jni = (TextView) findViewById(R.id.jambu_jni);
        norx = (TextView) findViewById(R.id.norx);
        norx_jni = (TextView) findViewById(R.id.norx_jni);
        aez = (TextView) findViewById(R.id.aez);
        aez_jni = (TextView) findViewById(R.id.aez_jni);
        msgSize = (EditText)findViewById(R.id.msg_size);
        iterations = (EditText)findViewById(R.id.itr_num);


        // Get all the button view
        acorn_btn = (Button) findViewById(R.id.bt_acorn);
        acorn_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(msgSize.getText()!= null){
                    MLEN = Integer.valueOf(msgSize.getText().toString());
                    //System.out.println("Msg is "+ msgSize.getText());
                }
                if(iterations.getText()!= null){
                    ITER = Integer.valueOf(iterations.getText().toString());
                    //System.out.println("Iteration is "+ iterations.getText());
                }
                System.out.println("Msg is "+ MLEN +", iter " + ITER);
                acorn.setText("Running");
                new Thread(new Runnable() {
                    public void run() {

                        alen = mlen = MLEN;
                        a = new byte[alen];
                        for (i = 0; i < MLEN; ++i)
                            a[i] = (byte) ('A' + i % 26);
                        m = new byte[mlen];
                        for (i = 0; i < MLEN; ++i)
                            m[i] = (byte) ('a' + i % 26);

                        byte nsec[] = new byte[Acorn128v2.CRYPTO_NSECBYTES];
                        byte npub[] =
                                {(byte) 0x7c, (byte) 0xc2, (byte) 0x54, (byte) 0xf8, (byte) 0x1b, (byte) 0xe8, (byte) 0xe7,
                                        (byte) 0x8d, (byte) 0x76, (byte) 0x5a, (byte) 0x2e, (byte) 0x63, (byte) 0x33,
                                        (byte) 0x9f, (byte) 0xc9, (byte) 0x9a};
                        byte k[] =
                                {0x67, (byte) 0xc6, 0x69, 0x73, 0x51, (byte) 0xff, 0x4a, (byte) 0xec, 0x29, (byte) 0xcd,
                                        (byte) 0xba, (byte) 0xab, (byte) 0xf2, (byte) 0xfb, (byte) 0xe3, 0x46};

                        //Acorn128v2.print("k", k, Acorn128v2.CRYPTO_KEYBYTES, 0);
                        //Acorn128v2.print("n", npub, Acorn128v2.CRYPTO_NPUBBYTES, 0);
                        //Acorn128v2.print("a", a, alen, 0);
                        //Acorn128v2.print("m", m, mlen, 0);
                        c = new byte[m.length + Acorn128v2.CRYPTO_ABYTES];
                        long start = System.currentTimeMillis();
                        i = ITER;
                        while (i-- > 0) {
                            clen = Acorn128v2.crypto_aead_encrypt(c, clen, m, mlen, a, alen, nsec, npub, k);
                        }
                        long encyptTime = System.currentTimeMillis() - start;
                        //Acorn128v2.print("c", c, clen - Acorn128v2.CRYPTO_ABYTES, 0);
                        //Acorn128v2.print("t", c, Acorn128v2.CRYPTO_ABYTES, clen - Acorn128v2.CRYPTO_ABYTES);
                        p = new byte[mlen];
                        start = System.currentTimeMillis();
                        i = ITER;
                        while (i-- > 0) {
                            mlen = Acorn128v2.crypto_aead_decrypt(p, mlen, nsec, c, clen, a, alen, npub, k);
                        }
                        long decryptTime = System.currentTimeMillis() - start;
                        final StringBuffer buffer = new StringBuffer();
                        buffer.append((encyptTime*1000000)/(MLEN*ITER));buffer.append(" nanosec ------  ");
                        buffer.append((decryptTime*1000000)/(MLEN*ITER)); buffer.append("  nanosec");
                        if (mlen != -1) {
                            //Acorn128v2.print("p",p,mlen,0);
                            acorn.post(new Runnable() {
                                public void run() {
                                    acorn.setText(buffer.toString());
                                }
                            });

                        }
                    }
                }).start();
            }
        });

        acorn_btn_jni = (Button) findViewById(R.id.bt_acorn_jni);
        acorn_btn_jni.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(msgSize.getText()!= null){
                    MLEN = Integer.valueOf(msgSize.getText().toString());
                    //System.out.println("Msg is "+ msgSize.getText());
                }
                if(iterations.getText()!= null){
                    ITER = Integer.valueOf(iterations.getText().toString());
                    //System.out.println("Iteration is "+ iterations.getText());
                }
                System.out.println("Msg is "+ MLEN +", iter " + ITER);
                acorn_jni.setText("Running");
                new Thread(new Runnable() {
                    public void run() {

                        alen = mlen = MLEN;
                        a = new byte[alen];
                        for (i = 0; i < MLEN; ++i)
                            a[i] = (byte) ('A' + i % 26);
                        m = new byte[mlen];
                        for (i = 0; i < MLEN; ++i)
                            m[i] = (byte) ('a' + i % 26);

                        byte nsec[] = new byte[Acorn128v2.CRYPTO_NSECBYTES];
                        byte npub[] =
                                {(byte) 0x7c, (byte) 0xc2, (byte) 0x54, (byte) 0xf8, (byte) 0x1b, (byte) 0xe8, (byte) 0xe7,
                                        (byte) 0x8d, (byte) 0x76, (byte) 0x5a, (byte) 0x2e, (byte) 0x63, (byte) 0x33,
                                        (byte) 0x9f, (byte) 0xc9, (byte) 0x9a};
                        byte k[] =
                                {0x67, (byte) 0xc6, 0x69, 0x73, 0x51, (byte) 0xff, 0x4a, (byte) 0xec, 0x29, (byte) 0xcd,
                                        (byte) 0xba, (byte) 0xab, (byte) 0xf2, (byte) 0xfb, (byte) 0xe3, 0x46};

                        //Acorn128v2.print("k", k, Acorn128v2.CRYPTO_KEYBYTES, 0);
                        //Acorn128v2.print("n", npub, Acorn128v2.CRYPTO_NPUBBYTES, 0);
                        //Acorn128v2.print("a", a, alen, 0);
                        //Acorn128v2.print("m", m, mlen, 0);
                        c = new byte[m.length + Acorn128v2.CRYPTO_ABYTES];
                        long start = System.currentTimeMillis();
                        i = ITER;
                        while (i-- > 0) {
                            clen = acorn_crypto_aead_encrypt(c, clen, m, mlen, a, alen, nsec, npub, k);
                        }
                        long encyptTime = System.currentTimeMillis() - start;
                        //Acorn128v2.print("c", c, clen - Acorn128v2.CRYPTO_ABYTES, 0);
                        //Acorn128v2.print("t", c, Acorn128v2.CRYPTO_ABYTES, clen - Acorn128v2.CRYPTO_ABYTES);
                        p = new byte[mlen];
                        start = System.currentTimeMillis();
                        i = ITER;
                        while (i-- > 0) {
                            mlen = acorn_crypto_aead_decrypt(p, mlen, nsec, c, clen, a, alen, npub, k);
                        }
                        long decryptTime = System.currentTimeMillis() - start;
                        final StringBuffer buffer = new StringBuffer();
                        buffer.append((encyptTime*1000000)/(MLEN*ITER));buffer.append(" nanosec ------  ");
                        buffer.append((decryptTime*1000000)/(MLEN*ITER)); buffer.append("  nanosec");
                        if (mlen != -1) {
                            //Acorn128v2.print("p",p,mlen,0);
                            acorn_jni.post(new Runnable() {
                                public void run() {
                                    acorn_jni.setText(buffer.toString());
                                }
                            });

                        }
                    }
                }).start();
            }
        });
        jambu_btn = (Button) findViewById(R.id.bt_jambu);
        jambu_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(msgSize.getText()!= null){
                    MLEN = Integer.valueOf(msgSize.getText().toString());
                    //System.out.println("Msg is "+ msgSize.getText());
                }
                if(iterations.getText()!= null){
                    ITER = Integer.valueOf(iterations.getText().toString());
                    //System.out.println("Iteration is "+ iterations.getText());
                }
                System.out.println("Msg is "+ MLEN +", iter " + ITER);
                jambu.setText("Running");
                new Thread(new Runnable() {
                    public void run() {
                        alen = mlen = MLEN;
                        a = new byte[alen];
                        for (i = 0; i < MLEN; ++i)
                            a[i] = (byte) ('A' + i % 26);
                        m = new byte[mlen];
                        for (i = 0; i < MLEN; ++i)
                            m[i] = (byte) ('a' + i % 26);

                        byte nsec[] = new byte[SimonJambu.CRYPTO_NSECBYTES];
                        byte npub[] =
                                {(byte) 0x7c, (byte) 0xc2, (byte) 0x54, (byte) 0xf8, (byte) 0x1b, (byte) 0xe8, (byte) 0xe7,
                                        (byte) 0x8d};
                        byte k[] =
                                {0x67, (byte) 0xc6, 0x69, 0x73, 0x51, (byte) 0xff, 0x4a, (byte) 0xec, 0x29, (byte) 0xcd,
                                        (byte) 0xba, (byte) 0xab, (byte) 0xf2, (byte) 0xfb, (byte) 0xe3, 0x46};

                        //SimonJambu.print("k", k, SimonJambu.CRYPTO_KEYBYTES, 0);
                        //SimonJambu.print("n", npub, SimonJambu.CRYPTO_NPUBBYTES, 0);
                        //SimonJambu.print("a", a, alen, 0);
                        //SimonJambu.print("m", m, mlen, 0);
                        c = new byte[m.length + SimonJambu.CRYPTO_ABYTES];
                        long start = System.currentTimeMillis();
                        i = ITER;
                        while(i-- > 0 ){
                            clen = SimonJambu.crypto_aead_encrypt(c, clen, m, mlen, a, alen, nsec, npub, k);
                        }
                        long encyptTime= System.currentTimeMillis()-start;
                        //SimonJambu.print("c", c, clen - SimonJambu.CRYPTO_ABYTES, 0);
                        //SimonJambu.print("t", c, SimonJambu.CRYPTO_ABYTES, clen - SimonJambu.CRYPTO_ABYTES);
                        p = new byte[mlen];
                        start = System.currentTimeMillis();
                        i = ITER;
                        while(i-- > 0 ) {
                            mlen = SimonJambu.crypto_aead_decrypt(p, mlen, nsec, c, clen, a, alen, npub, k);
                        }
                        long decryptTime= System.currentTimeMillis()-start;
                        final StringBuffer buffer = new StringBuffer();
                        buffer.append((encyptTime*1000000)/(MLEN*ITER));buffer.append(" nanosec ------  ");
                        buffer.append((decryptTime*1000000)/(MLEN*ITER)); buffer.append("  nanosec");
                        if (mlen != -1) {
                            //SimonJambu.print("p",p,mlen,0);
                            jambu.post(new Runnable() {
                                public void run() {
                                    jambu.setText(buffer.toString());
                                }
                            });
                        }
                    }
                }).start();
            }
        });


        jambu_btn_jni = (Button) findViewById(R.id.bt_jambu_jni);
        jambu_btn_jni.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(msgSize.getText()!= null){
                    MLEN = Integer.valueOf(msgSize.getText().toString());
                    //System.out.println("Msg is "+ msgSize.getText());
                }
                if(iterations.getText()!= null){
                    ITER = Integer.valueOf(iterations.getText().toString());
                    //System.out.println("Iteration is "+ iterations.getText());
                }
                System.out.println("Msg is "+ MLEN +", iter " + ITER);
                jambu_jni.setText("Running");
                new Thread(new Runnable() {
                    public void run() {
                        alen = mlen = MLEN;
                        a = new byte[alen];
                        for (i = 0; i < MLEN; ++i)
                            a[i] = (byte) ('A' + i % 26);
                        m = new byte[mlen];
                        for (i = 0; i < MLEN; ++i)
                            m[i] = (byte) ('a' + i % 26);

                        byte nsec[] = new byte[SimonJambu.CRYPTO_NSECBYTES];
                        byte npub[] =
                                {(byte) 0x7c, (byte) 0xc2, (byte) 0x54, (byte) 0xf8, (byte) 0x1b, (byte) 0xe8, (byte) 0xe7,
                                        (byte) 0x8d};
                        byte k[] =
                                {0x67, (byte) 0xc6, 0x69, 0x73, 0x51, (byte) 0xff, 0x4a, (byte) 0xec, 0x29, (byte) 0xcd,
                                        (byte) 0xba, (byte) 0xab, (byte) 0xf2, (byte) 0xfb, (byte) 0xe3, 0x46};

                        //SimonJambu.print("k", k, SimonJambu.CRYPTO_KEYBYTES, 0);
                        //SimonJambu.print("n", npub, SimonJambu.CRYPTO_NPUBBYTES, 0);
                        //SimonJambu.print("a", a, alen, 0);
                        //SimonJambu.print("m", m, mlen, 0);
                        c = new byte[m.length + SimonJambu.CRYPTO_ABYTES];
                        long start = System.currentTimeMillis();
                        i = ITER;
                        while(i-- > 0 ){
                            clen = simon_crypto_aead_encrypt(c, clen, m, mlen, a, alen, nsec, npub, k);
                        }
                        long encyptTime= System.currentTimeMillis()-start;
                        //SimonJambu.print("c", c, clen - SimonJambu.CRYPTO_ABYTES, 0);
                        //SimonJambu.print("t", c, SimonJambu.CRYPTO_ABYTES, clen - SimonJambu.CRYPTO_ABYTES);
                        p = new byte[mlen];
                        start = System.currentTimeMillis();
                        i = ITER;
                        while(i-- > 0 ) {
                            mlen = simon_crypto_aead_decrypt(p, mlen, nsec, c, clen, a, alen, npub, k);
                        }
                        long decryptTime= System.currentTimeMillis()-start;
                        final StringBuffer buffer = new StringBuffer();
                        buffer.append((encyptTime*1000000)/(MLEN*ITER));buffer.append(" nanosec ------  ");
                        buffer.append((decryptTime*1000000)/(MLEN*ITER)); buffer.append("  nanosec");
                        if (mlen != -1) {
                            //SimonJambu.print("p",p,mlen,0);
                            jambu_jni.post(new Runnable() {
                                public void run() {
                                    jambu_jni.setText(buffer.toString());
                                }
                            });
                        }
                    }
                }).start();
            }
        });

        norx_btn = (Button) findViewById(R.id.bt_norx);
        norx_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(msgSize.getText()!= null){
                    MLEN = Integer.valueOf(msgSize.getText().toString());
                    //System.out.println("Msg is "+ msgSize.getText());
                }
                if(iterations.getText()!= null){
                    ITER = Integer.valueOf(iterations.getText().toString());
                    //System.out.println("Iteration is "+ iterations.getText());
                }
                System.out.println("Msg is "+ MLEN +", iter " + ITER);
                norx.setText("Running");
                new Thread(new Runnable() {
                    public void run() {

                        alen = mlen = MLEN;
                        a = new byte[alen];
                        for (i = 0; i < MLEN; ++i)
                            a[i] = (byte) ('A' + i % 26);
                        m = new byte[mlen];
                        for (i = 0; i < MLEN; ++i)
                            m[i] = (byte) ('a' + i % 26);

                        byte nsec[] = new byte[Norx.CRYPTO_NSECBYTES];
                        byte npub[] =
                                {(byte) 0x7c, (byte) 0xc2, (byte) 0x54, (byte) 0xf8, (byte) 0x1b, (byte) 0xe8, (byte) 0xe7,
                                        (byte) 0x8d, (byte) 0x76, (byte) 0x5a, (byte) 0x2e, (byte) 0x63, (byte) 0x33,
                                        (byte) 0x9f, (byte) 0xc9, (byte) 0x9a};
                        byte k[] =
                                {0x67, (byte) 0xc6, 0x69, 0x73, 0x51, (byte) 0xff, 0x4a, (byte) 0xec, 0x29, (byte) 0xcd,
                                        (byte) 0xba, (byte) 0xab, (byte) 0xf2, (byte) 0xfb, (byte) 0xe3, 0x46,
                                    0x67, (byte) 0xc6, 0x69, 0x73, 0x51, (byte) 0xff, 0x4a, (byte) 0xec, 0x29, (byte) 0xcd,
                                    (byte) 0xba, (byte) 0xab, (byte) 0xf2, (byte) 0xfb, (byte) 0xe3, 0x46};

                        //Norx.print("k", k, Acorn128v2.CRYPTO_KEYBYTES, 0);
                        //Norx.print("n", npub, Acorn128v2.CRYPTO_NPUBBYTES, 0);
                        //Norx.print("a", a, alen, 0);
                        //Norx.print("m", m, mlen, 0);
                        c = new byte[m.length + Norx.CRYPTO_ABYTES];
                        long start = System.currentTimeMillis();
                        i = ITER;
                        while (i-- > 0) {
                            clen = Norx.crypto_aead_encrypt(c, clen, m, mlen, a, alen, nsec, npub, k);
                        }
                        long encyptTime = System.currentTimeMillis() - start;
                        //Norx.print("c", c, clen - Norx.CRYPTO_ABYTES, 0);
                        //Norx.print("t", c, Norx.CRYPTO_ABYTES, clen - Norx.CRYPTO_ABYTES);
                        p = new byte[mlen];
                        start = System.currentTimeMillis();
                        i = ITER;
                        while (i-- > 0) {
                            mlen = Norx.crypto_aead_decrypt(p, mlen, nsec, c, clen, a, alen, npub, k);
                        }
                        long decryptTime = System.currentTimeMillis() - start;
                        final StringBuffer buffer = new StringBuffer();
                        buffer.append((encyptTime*1000000)/(MLEN*ITER));buffer.append(" nanosec ------  ");
                        buffer.append((decryptTime*1000000)/(MLEN*ITER)); buffer.append("  nanosec");
                        if (mlen != -1) {
                            //Norx.print("p",p,mlen,0);
                            norx.post(new Runnable() {
                                public void run() {
                                    norx.setText(buffer.toString());
                                }
                            });

                        }
                    }
                }).start();
            }
        });
        norx_btn_jni = (Button) findViewById(R.id.bt_norx_jni);
        norx_btn_jni.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(msgSize.getText()!= null){
                    MLEN = Integer.valueOf(msgSize.getText().toString());
                    //System.out.println("Msg is "+ msgSize.getText());
                }
                if(iterations.getText()!= null){
                    ITER = Integer.valueOf(iterations.getText().toString());
                    //System.out.println("Iteration is "+ iterations.getText());
                }
                System.out.println("Msg is "+ MLEN +", iter " + ITER);
                norx_jni.setText("Running");
                new Thread(new Runnable() {
                    public void run() {

                        alen = mlen = MLEN;
                        a = new byte[alen];
                        for (i = 0; i < MLEN; ++i)
                            a[i] = (byte) ('A' + i % 26);
                        m = new byte[mlen];
                        for (i = 0; i < MLEN; ++i)
                            m[i] = (byte) ('a' + i % 26);

                        byte nsec[] = new byte[Norx.CRYPTO_NSECBYTES];
                        byte npub[] =
                                {(byte) 0x7c, (byte) 0xc2, (byte) 0x54, (byte) 0xf8, (byte) 0x1b, (byte) 0xe8, (byte) 0xe7,
                                        (byte) 0x8d, (byte) 0x76, (byte) 0x5a, (byte) 0x2e, (byte) 0x63, (byte) 0x33,
                                        (byte) 0x9f, (byte) 0xc9, (byte) 0x9a};
                        byte k[] =
                                {0x67, (byte) 0xc6, 0x69, 0x73, 0x51, (byte) 0xff, 0x4a, (byte) 0xec, 0x29, (byte) 0xcd,
                                        (byte) 0xba, (byte) 0xab, (byte) 0xf2, (byte) 0xfb, (byte) 0xe3, 0x46,
                                        0x67, (byte) 0xc6, 0x69, 0x73, 0x51, (byte) 0xff, 0x4a, (byte) 0xec, 0x29, (byte) 0xcd,
                                        (byte) 0xba, (byte) 0xab, (byte) 0xf2, (byte) 0xfb, (byte) 0xe3, 0x46};

                        //Norx.print("k", k, Acorn128v2.CRYPTO_KEYBYTES, 0);
                        //Norx.print("n", npub, Acorn128v2.CRYPTO_NPUBBYTES, 0);
                        //Norx.print("a", a, alen, 0);
                        //Norx.print("m", m, mlen, 0);
                        c = new byte[m.length + Norx.CRYPTO_ABYTES];
                        long start = System.currentTimeMillis();
                        i = ITER;
                        while (i-- > 0) {
                            clen = norx_crypto_aead_encrypt(c, clen, m, mlen, a, alen, nsec, npub, k);
                        }
                        long encyptTime = System.currentTimeMillis() - start;
                        //Norx.print("c", c, clen - Norx.CRYPTO_ABYTES, 0);
                        //Norx.print("t", c, Norx.CRYPTO_ABYTES, clen - Norx.CRYPTO_ABYTES);
                        p = new byte[mlen];
                        start = System.currentTimeMillis();
                        i = ITER;
                        while (i-- > 0) {
                            mlen = norx_crypto_aead_decrypt(p, mlen, nsec, c, clen, a, alen, npub, k);
                        }
                        long decryptTime = System.currentTimeMillis() - start;
                        final StringBuffer buffer = new StringBuffer();
                        buffer.append((encyptTime*1000000)/(MLEN*ITER));buffer.append(" nanosec ------  ");
                        buffer.append((decryptTime*1000000)/(MLEN*ITER)); buffer.append("  nanosec");
                        if (mlen != -1) {
                            //Norx.print("p",p,mlen,0);
                            norx_jni.post(new Runnable() {
                                public void run() {
                                    norx_jni.setText(buffer.toString());
                                }
                            });

                        }
                    }
                }).start();
            }
        });
        aez_btn = (Button) findViewById(R.id.bt_aez);
        aez_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(msgSize.getText()!= null){
                    MLEN = Integer.valueOf(msgSize.getText().toString());
                    //System.out.println("Msg is "+ msgSize.getText());
                }
                if(iterations.getText()!= null){
                    ITER = Integer.valueOf(iterations.getText().toString());
                    //System.out.println("Iteration is "+ iterations.getText());
                }
                System.out.println("Msg is "+ MLEN +", iter " + ITER);
                aez.setText("Running");
                new Thread(new Runnable() {
                    public void run() {

                        alen = mlen = MLEN;
                        a = new byte[alen];
                        for (i = 0; i < MLEN; ++i)
                            a[i] = (byte) ('A' + i % 26);
                        m = new byte[mlen];
                        for (i = 0; i < MLEN; ++i)
                            m[i] = (byte) ('a' + i % 26);

                        byte nsec[] = new byte[Aezv4.CRYPTO_NSECBYTES];
                        byte npub[] =
                                {(byte) 0x7c, (byte) 0xc2, (byte) 0x54, (byte) 0xf8, (byte) 0x1b, (byte) 0xe8, (byte) 0xe7,
                                        (byte) 0x8d, (byte) 0x76, (byte) 0x5a, (byte) 0x2e, (byte) 0x63, (byte) 0x33,
                                        (byte) 0x9f, (byte) 0xc9, (byte) 0x9a};
                        byte k[] =
                                {0x67, (byte) 0xc6, 0x69, 0x73, 0x51, (byte) 0xff, 0x4a, (byte) 0xec, 0x29, (byte) 0xcd,
                                        (byte) 0xba, (byte) 0xab, (byte) 0xf2, (byte) 0xfb, (byte) 0xe3, 0x46,
                                        0x67, (byte) 0xc6, 0x69, 0x73, 0x51, (byte) 0xff, 0x4a, (byte) 0xec, 0x29, (byte) 0xcd,
                                        (byte) 0xba, (byte) 0xab, (byte) 0xf2, (byte) 0xfb, (byte) 0xe3, 0x46};

                        //Aezv4.print("k", k, Aezv4.CRYPTO_KEYBYTES, 0);
                        //Aezv4.print("n", npub, Aezv4.CRYPTO_NPUBBYTES, 0);
                        //Aezv4.print("a", a, alen, 0);
                        //Aezv4.print("m", m, mlen, 0);
                        c = new byte[m.length + Aezv4.CRYPTO_ABYTES];
                        long start = System.currentTimeMillis();
                        i = ITER;
                        while (i-- > 0) {
                            clen = Aezv4.crypto_aead_encrypt(c, clen, m, mlen, a, alen, nsec, npub, k);
                        }
                        long encyptTime = System.currentTimeMillis() - start;
                        //Aezv4.print("c", c, clen - Aezv4.CRYPTO_ABYTES, 0);
                        //Aezv4.print("t", c, Aezv4.CRYPTO_ABYTES, clen - Aezv4.CRYPTO_ABYTES);
                        p = new byte[mlen];
                        start = System.currentTimeMillis();
                        i = ITER;
                        while (i-- > 0) {
                            mlen = Aezv4.crypto_aead_decrypt(p, mlen, nsec, c, clen, a, alen, npub, k);
                        }
                        long decryptTime = System.currentTimeMillis() - start;
                        final StringBuffer buffer = new StringBuffer();
                        buffer.append((encyptTime*1000000)/(MLEN*ITER));buffer.append(" nanosec ------  ");
                        buffer.append((decryptTime*1000000)/(MLEN*ITER)); buffer.append("  nanosec");
                        if (mlen != -1) {
                            //Aezv4.print("p",p,mlen,0);
                            aez.post(new Runnable() {
                                public void run() {
                                    aez.setText(buffer.toString());
                                }
                            });

                        }
                    }
                }).start();
            }
        });
        aez_btn_jni = (Button) findViewById(R.id.bt_aez_jni);
        aez_btn_jni.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(msgSize.getText()!= null){
                    MLEN = Integer.valueOf(msgSize.getText().toString());
                    //System.out.println("Msg is "+ msgSize.getText());
                }
                if(iterations.getText()!= null){
                    ITER = Integer.valueOf(iterations.getText().toString());
                    //System.out.println("Iteration is "+ iterations.getText());
                }
                System.out.println("Msg is "+ MLEN +", iter " + ITER);
                aez_jni.setText("Running");
                new Thread(new Runnable() {
                    public void run() {

                        alen = mlen = MLEN;
                        a = new byte[alen];
                        for (i = 0; i < MLEN; ++i)
                            a[i] = (byte) ('A' + i % 26);
                        m = new byte[mlen];
                        for (i = 0; i < MLEN; ++i)
                            m[i] = (byte) ('a' + i % 26);

                        byte nsec[] = new byte[Aezv4.CRYPTO_NSECBYTES];
                        byte npub[] =
                                {(byte) 0x7c, (byte) 0xc2, (byte) 0x54, (byte) 0xf8, (byte) 0x1b, (byte) 0xe8, (byte) 0xe7,
                                        (byte) 0x8d, (byte) 0x76, (byte) 0x5a, (byte) 0x2e, (byte) 0x63, (byte) 0x33,
                                        (byte) 0x9f, (byte) 0xc9, (byte) 0x9a};
                        byte k[] =
                                {0x67, (byte) 0xc6, 0x69, 0x73, 0x51, (byte) 0xff, 0x4a, (byte) 0xec, 0x29, (byte) 0xcd,
                                        (byte) 0xba, (byte) 0xab, (byte) 0xf2, (byte) 0xfb, (byte) 0xe3, 0x46,
                                        0x67, (byte) 0xc6, 0x69, 0x73, 0x51, (byte) 0xff, 0x4a, (byte) 0xec, 0x29, (byte) 0xcd,
                                        (byte) 0xba, (byte) 0xab, (byte) 0xf2, (byte) 0xfb, (byte) 0xe3, 0x46};

                        //Aezv4.print("k", k, Aezv4.CRYPTO_KEYBYTES, 0);
                        //Aezv4.print("n", npub, Aezv4.CRYPTO_NPUBBYTES, 0);
                        //Aezv4.print("a", a, alen, 0);
                        //Aezv4.print("m", m, mlen, 0);
                        c = new byte[m.length + Aezv4.CRYPTO_ABYTES];
                        long start = System.currentTimeMillis();
                        i = ITER;
                        while (i-- > 0) {
                            clen = aez_crypto_aead_encrypt(c, clen, m, mlen, a, alen, nsec, npub, k);
                        }
                        long encyptTime = System.currentTimeMillis() - start;
                        //Aezv4.print("c", c, clen - Aezv4.CRYPTO_ABYTES, 0);
                        //Aezv4.print("t", c, Aezv4.CRYPTO_ABYTES, clen - Aezv4.CRYPTO_ABYTES);
                        p = new byte[mlen];
                        start = System.currentTimeMillis();
                        i = ITER;
                        while (i-- > 0) {
                            mlen = aez_crypto_aead_decrypt(p, mlen, nsec, c, clen, a, alen, npub, k);
                        }
                        long decryptTime = System.currentTimeMillis() - start;
                        final StringBuffer buffer = new StringBuffer();
                        buffer.append((encyptTime*1000000)/(MLEN*ITER));buffer.append(" nanosec ------  ");
                        buffer.append((decryptTime*1000000)/(MLEN*ITER)); buffer.append("  nanosec");
                        if (mlen != -1) {
                            //Aezv4.print("p",p,mlen,0);
                            aez_jni.post(new Runnable() {
                                public void run() {
                                    aez_jni.setText(buffer.toString());
                                }
                            });

                        }
                    }
                }).start();
            }
        });



    }


}
