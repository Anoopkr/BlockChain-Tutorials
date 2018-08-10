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

	// Returns true if new transaction could be created.
	public boolean processTransaction() {
		if (verifiySignature() == false) {
			System.out.println("#Transaction Signature failed to verify");
			return false;
		}

		// gather transaction inputs (Make sure they are unspent):
		for (TransactionInput i : inputs) {
			i.UTXO = NoobChain.UTXOs.get(i.transactionOutputId);
		}

		// check if transaction is valid:
		if (getInputsValue() < NoobChain.minimumTransaction) {
			System.out.println("#Transaction Inputs to small: " + getInputsValue());
			return false;
		}

		// generate transaction outputs:
		float leftOver = getInputsValue() - value; // get value of inputs then the left over change:
		transactionId = calulateHash();
		outputs.add(new TransactionOutput(this.reciepient, value, transactionId)); // send value to recipient
		outputs.add(new TransactionOutput(this.sender, leftOver, transactionId)); // send the left over 'change' back to
																					// sender

		// add outputs to Unspent list
		for (TransactionOutput o : outputs) {
			NoobChain.UTXOs.put(o.id, o);
		}

		// remove transaction inputs from UTXO lists as spent:
		for (TransactionInput i : inputs) {
			if (i.UTXO == null)
				continue; // if Transaction can't be found skip it
			NoobChain.UTXOs.remove(i.UTXO.id);
		}

		return true;
	}

	// returns sum of inputs(UTXOs) values
	public float getInputsValue() {
		float total = 0;
		for (TransactionInput i : inputs) {
			if (i.UTXO == null)
				continue; // if Transaction can't be found skip it
			total += i.UTXO.value;
		}
		return total;
	}

	public float getOutputsValue() {
		float total = 0;
		for (TransactionOutput o : outputs) {
			total += o.value;
		}
		return total;
	}

}