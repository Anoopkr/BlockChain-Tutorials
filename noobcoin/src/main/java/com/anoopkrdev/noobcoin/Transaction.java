package com.anoopkrdev.noobcoin;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;

public class Transaction {

	/** The transaction id - this is also the hash of the transaction. */
	public String transactionId;

	/** The sender - The public key(address) of the sender of funds. */
	public PublicKey sender;

	/** The reciepient - The public key(address) of the receiver of funds. */
	public PublicKey reciepient;

	public float value;

	/**
	 * The signature.
	 * 
	 * A cryptographic signature, that proves the owner of the address is the one
	 * sending this transaction and that the data hasn’t been changed. Signatures
	 * perform two very important tasks: Firstly, they allow only the owner to spend
	 * their coins, secondly, they prevent others from tampering with their
	 * submitted transaction before a new block is mined
	 */
	public byte[] signature;

	/**
	 * The inputs.
	 * 
	 * Inputs, which are references to previous transactions that prove the sender
	 * has funds to send.
	 */
	public ArrayList<TransactionInput> inputs = new ArrayList<TransactionInput>();

	/**
	 * The outputs.
	 * 
	 * Outputs, which shows the amount relevant addresses received in the
	 * transaction. ( These outputs are referenced as inputs in new transactions )
	 */
	public ArrayList<TransactionOutput> outputs = new ArrayList<TransactionOutput>();

	/**
	 * The sequence - a rough count of how many transactions have been generated.
	 */
	private static int sequence = 0;

	// Constructor:
	public Transaction(PublicKey from, PublicKey to, float value, ArrayList<TransactionInput> inputs) {
		this.sender = from;
		this.reciepient = to;
		this.value = value;
		this.inputs = inputs;
	}

	// This Calculates the transaction hash (which will be used as its Id)
	private String calulateHash() {
		sequence++; // increase the sequence to avoid 2 identical transactions having the same hash
		return StringUtil.applySha256(StringUtil.getStringFromKey(sender) + StringUtil.getStringFromKey(reciepient)
				+ Float.toString(value) + sequence);
	}

	// Signs all the data we dont wish to be tampered with.
	public void generateSignature(PrivateKey privateKey) {
		String data = StringUtil.getStringFromKey(sender) + StringUtil.getStringFromKey(reciepient)
				+ Float.toString(value);
		signature = StringUtil.applyECDSASig(privateKey, data);
	}

	// Verifies the data we signed hasnt been tampered with
	public boolean verifiySignature() {
		String data = StringUtil.getStringFromKey(sender) + StringUtil.getStringFromKey(reciepient)
				+ Float.toString(value);
		return StringUtil.verifyECDSASig(sender, data, signature);
	}

}