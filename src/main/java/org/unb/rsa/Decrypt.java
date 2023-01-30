package org.unb.rsa;

import org.unb.rsa.models.PrivateKey;

import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;

public class Decrypt {

    public static BigInteger decryptCipher(BigInteger c, PrivateKey privateKey) {
        Instant start = Instant.now();
        BigInteger mDash = c.modPow(privateKey.getD(), privateKey.getP().multiply(privateKey.getQ()));
        System.out.printf("Decrypted message m = %s\n", mDash);
        Instant end = Instant.now();
        System.out.printf("Computation time of c ^ d mod n is %s ms\n", Duration.between(start, end).toMillis());
        return mDash;
    }
    public static BigInteger decryptCipherUsingCRT(BigInteger c, PrivateKey privateKey) {
        Instant start = Instant.now();
        BigInteger p = privateKey.getP();
        BigInteger q = privateKey.getQ();
        BigInteger n = p.multiply(q);
        BigInteger d = privateKey.getD();
        BigInteger qDash = q.modInverse(p);
        BigInteger pDash = p.modInverse(q);
        BigInteger dp = d.mod(p.subtract(BigInteger.ONE));
        BigInteger dq = d.mod(q.subtract(BigInteger.ONE));
        BigInteger cp = c.mod(p);
        BigInteger cq = c.mod(q);
        BigInteger mp = cp.modPow(dp, p);
        BigInteger mq = cq.modPow(dq, q);
        BigInteger mDash = mp.multiply(q).multiply(qDash).add(mq.multiply(p).multiply(pDash)).mod(n);
        Instant end = Instant.now();
        System.out.printf("Computation time of the CRT-based RSA decryption is %s ms\n", Duration.between(start, end).toMillis());
        return mDash;
    }
}
