package com.soci.sdk; public final class SociCiphertext { private final byte[] value; public SociCiphertext(byte[] v){value=v.clone();} public byte[] toBytes(){return value.clone();} }
