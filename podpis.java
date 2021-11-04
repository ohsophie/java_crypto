package com.company;

import java.io.FileInputStream;
import java.io.IOException;

import java.math.BigInteger;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.util.LinkedList;
import java.util.List;
import java.util.Random;


public class podpis {

    // function to return file hash
    public static BigInteger GetHash(String filename) throws IOException, NoSuchAlgorithmException

    {
        MessageDigest md = MessageDigest.getInstance("MD5");
        FileInputStream fis = new FileInputStream(filename);
        byte[] dataBytes = new byte[1024];
        int nread = 0;
        while ((nread = fis.read(dataBytes)) != -1)
        {
            md.update(dataBytes, 0, nread);
        };
        byte[] mdbytes = md.digest();
        // делаем из хеша число
        BigInteger big = new BigInteger(1, mdbytes);
        // делаем обратно из числа хеш
        byte[] bytess = big.toByteArray();
        return big;
    }

    // function to return prime number
    public static BigInteger GeneratePrime() {
        BigInteger number;
        while (true) {
            BigInteger b = new BigInteger(32, new Random());
            if (IsPrime(b)) {
                number = b;
                break;
            }
        }
        return number;
    }

    // function to check if number is prime
    public static boolean IsPrime(BigInteger x) {

        for (BigInteger i = BigInteger.valueOf(2); i.compareTo(x) < 0; i = i.add(BigInteger.ONE)) {
            if (x.mod(i).equals(BigInteger.ZERO)) {
                return false;
            }
        }
        return true;
    }

    // function to return a signature
    public static BigInteger Sign(BigInteger hash, List<BigInteger> publicKey) {

        BigInteger d = publicKey.get(0);
        BigInteger n = publicKey.get(1);

        BigInteger signature = hash.modPow(d,n);

        return signature;
    }

    // function to verify a signature
    public static boolean Verify_Sign(BigInteger hash, List<BigInteger> privateKey, BigInteger signature) {

        BigInteger e = privateKey.get(0);
        BigInteger n = privateKey.get(1);

        BigInteger verification = hash.modPow(e,n);

        if (signature.equals(verification)) {
            return true;
        }
        return false;
    }

    // function to return keys
    public static List<List<BigInteger>> GenerateKeys() {
        List<BigInteger> publicKey = new LinkedList<BigInteger>();
        List<BigInteger> privateKey = new LinkedList<BigInteger>();
        List<List<BigInteger>> keys = new LinkedList<List<BigInteger>>();
        // prime numbers p & q
        BigInteger p = GeneratePrime();
        BigInteger q = GeneratePrime();
        // number n
        BigInteger n = p.multiply(q);
        BigInteger one = new BigInteger("1");
        // Euler's totient function
        BigInteger fi = p.subtract(one).multiply(q.subtract(one));
        // public exponent
        BigInteger e = new BigInteger("257"); // simple Fermat number
        // number d
        BigInteger d = e.modPow(one, fi);
        // compiling keys
        publicKey.add(e);
        publicKey.add(n);
        privateKey.add(d);
        privateKey.add(n);
        keys.add(publicKey);
        keys.add(privateKey);

        return keys;
    }

    // main function, driver code
    public static void main(String args[]) throws Exception {
        // hashing
        BigInteger hash = GetHash("pg66600.txt");
        //generating keys
        List<List<BigInteger>> keys = GenerateKeys();
        List<BigInteger> privateKey = keys.get(1);
        List<BigInteger> publicKey = keys.get(0);
        //signing
        BigInteger sig = Sign(hash, publicKey);
        System.out.println("Signature:\n " + sig.toString(16));
        // verifying signsture
        boolean VF = Verify_Sign(hash, privateKey, sig);
        if (VF) {
            System.out.println("Signature Valid");
        }
        else {
            System.out.println("Signature inValid");
        }

    }

}
