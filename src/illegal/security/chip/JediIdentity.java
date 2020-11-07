package illegal.security.chip;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;


public class JediIdentity {
	private static final byte OFFSET_TMP_KEY = (byte) 0;

	private static final byte OFFSET_FLAG_TMP_KEY_TYPE = (byte) 1;
	
	private static final byte LEN_TMP = (byte) 2;

	public static final short RSA2048_INT_SIZE = (short) 0x100;
	private static final short RSA2048_PQ_SIZE = (short) 0x80;

	public static final short LEN_ID_SERIAL = (short) 0x10;
	public static final short LEN_ID_PUB_N = RSA2048_INT_SIZE;
	public static final short LEN_ID_PUB_E = RSA2048_INT_SIZE;
	public static final short LEN_ID_SIG = RSA2048_INT_SIZE;

//	private static final short OFFSET_ID_SERIAL = (short) 0x0;
//	private static final short OFFSET_ID_PUB_N = OFFSET_ID_SERIAL + LEN_ID_SERIAL;
//	private static final short OFFSET_ID_PUB_E = OFFSET_ID_PUB_N + LEN_ID_PUB_N;
//	private static final short OFFSET_ID_SIG = OFFSET_ID_PUB_E + LEN_ID_PUB_E;
//	
//	private static final short OFFSET_KEY_P = (short) 0x0;
//	private static final short OFFSET_KEY_Q = OFFSET_KEY_P + RSA2048_PQ_SIZE;
//	private static final short OFFSET_KEY_PQ = OFFSET_KEY_Q + RSA2048_PQ_SIZE;
//	private static final short OFFSET_KEY_DP1 = OFFSET_KEY_PQ + RSA2048_PQ_SIZE;
//	private static final short OFFSET_KEY_DQ1 = OFFSET_KEY_DP1 + RSA2048_PQ_SIZE;
//
//	private static final short LEN_ID = OFFSET_ID_SIG + LEN_ID_SIG;
//	private static final short LEN_KEY = OFFSET_KEY_DQ1 + RSA2048_PQ_SIZE;
	
	private static final short KEY_TYPE_UNSPECIFIED = (short) 0;
	private static final short KEY_TYPE_PUB_N = (short) 1;
	private static final short KEY_TYPE_PUB_E = (short) 2;
	private static final short KEY_TYPE_PUB_SIG = (short) 3;
	private static final short KEY_TYPE_PRIV_P = (short) 4;
	private static final short KEY_TYPE_PRIV_Q = (short) 5;
	private static final short KEY_TYPE_PRIV_PQ = (short) 6;
	private static final short KEY_TYPE_PRIV_DP1 = (short) 7;
	private static final short KEY_TYPE_PRIV_DQ1 = (short) 8;
	private static final short KEY_TYPE_EXPORT_PUB_N = (short) 9;
	private static final short KEY_TYPE_EXPORT_PUB_E = (short) 10;

	/**
	 * Serial number of the security chip.
	 */
	private final byte[] serialNumber;
	/**
	 * Controller-unique public key.
	 */
	private final RSAPublicKey cukPub;
	/**
	 * Controller-unique private key.
	 */
	private final RSAPrivateCrtKey cukPriv;
	/**
	 * Signature of the public identity block.
	 */
	private final byte[] idSig;
	/**
	 * Transient state array.
	 */
	private final short[] tmp;
	/**
	 * Transient buffer for receiving key blocks or other large objects.
	 */
	private final byte[] keyScratchPad;

	public JediIdentity() {
		this.serialNumber = new byte[(short) 8];
		this.idSig = new byte[(short) 0x100];
		this.tmp = JCSystem.makeTransientShortArray(LEN_TMP, JCSystem.CLEAR_ON_DESELECT);
		this.keyScratchPad = JCSystem.makeTransientByteArray(JediIdentity.RSA2048_INT_SIZE, JCSystem.CLEAR_ON_DESELECT);
		this.cukPub = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
		this.cukPriv = (RSAPrivateCrtKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
		this.reset();
	}

	/**
	 * Resets the object to uninitialized state.
	 * 
	 * In this state, all key blocks are reset to uninitialized state and other data are filled with 0x00.
	 * All transient states are also cleared.
	 */
	public void nuke() {
		this.reset();
		this.cukPub.clearKey();
		this.cukPriv.clearKey();
		Util.arrayFillNonAtomic(this.serialNumber, (short) 0, (short) this.serialNumber.length, (byte) 0);
		Util.arrayFillNonAtomic(this.idSig, (short) 0, (short) this.idSig.length, (byte) 0);
	}

	/**
	 * Resets all transient states
	 */
	public void reset() {
		this.setTmpKeyOffset((short) 0);
		this.setTmpKeyTypeFlag(KEY_TYPE_UNSPECIFIED);
		this.clearScratchPad();
	}

	private void setTmpKeyOffset(short off) {
		this.tmp[OFFSET_TMP_KEY] = off;
	}

	private void incTmpKeyOffset(short inc) {
		this.tmp[OFFSET_TMP_KEY] += inc;
	}

	private short getTmpKeyOffset() {
		return this.tmp[OFFSET_TMP_KEY];
	}

	private void setTmpKeyTypeFlag(short flag) {
		this.tmp[OFFSET_FLAG_TMP_KEY_TYPE] = flag;
	}

	private short getTmpKeyTypeFlag() {
		return this.tmp[OFFSET_FLAG_TMP_KEY_TYPE];
	}

	private void clearScratchPad() {
		Util.arrayFillNonAtomic(this.keyScratchPad, (short) 0, (short) this.keyScratchPad.length, (byte) 0);
	}

	private short putKeyObject(final byte[] buffer, short offset, short len, short keyType) {
		short actual;
		
		// Determine bounds based on object type
		short bounds = 0;
		switch (keyType) {
		case KEY_TYPE_PUB_N:
		case KEY_TYPE_PUB_E:
		case KEY_TYPE_PUB_SIG:
			bounds = JediIdentity.RSA2048_INT_SIZE;
			break;
		case KEY_TYPE_PRIV_P:
		case KEY_TYPE_PRIV_Q:
		case KEY_TYPE_PRIV_PQ:
		case KEY_TYPE_PRIV_DP1:
		case KEY_TYPE_PRIV_DQ1:
			bounds = JediIdentity.RSA2048_PQ_SIZE;
			break;
		default:
			ISOException.throwIt((short) 0x9c01);
			return (short) 0;
		}

		if (this.getTmpKeyTypeFlag() == KEY_TYPE_UNSPECIFIED) {
			this.setTmpKeyTypeFlag(keyType);
		} else if (this.getTmpKeyTypeFlag() != keyType) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			return (short) 0;
		}

		short remaining = (short) (bounds - this.getTmpKeyOffset());
		if (remaining < 0) {
			ISOException.throwIt((short) 0x9c02);
			return (short) 0;
		}
		if (len > remaining) {
			actual = remaining;
		} else {
			actual = len;
		}
		Util.arrayCopyNonAtomic(buffer, offset, this.keyScratchPad, this.getTmpKeyOffset(), actual);
		this.incTmpKeyOffset(actual);
		if (this.getTmpKeyOffset() == bounds) {
			switch (keyType) {
			case KEY_TYPE_PUB_N:
				this.cukPub.setModulus(this.keyScratchPad, (short) 0, JediIdentity.RSA2048_INT_SIZE);
				break;
			case KEY_TYPE_PUB_E:
				this.cukPub.setExponent(this.keyScratchPad, (short) 0, JediIdentity.RSA2048_INT_SIZE);
				break;
			case KEY_TYPE_PUB_SIG:
				Util.arrayCopyNonAtomic(this.keyScratchPad, (short) 0, this.idSig, (short) 0, (short) this.idSig.length);
				break;
			case KEY_TYPE_PRIV_P:
				this.cukPriv.setP(this.keyScratchPad, (short) 0, JediIdentity.RSA2048_PQ_SIZE);
				break;
			case KEY_TYPE_PRIV_Q:
				this.cukPriv.setQ(this.keyScratchPad, (short) 0, JediIdentity.RSA2048_PQ_SIZE);
				break;
			case KEY_TYPE_PRIV_PQ:
				this.cukPriv.setPQ(this.keyScratchPad, (short) 0, JediIdentity.RSA2048_PQ_SIZE);
				break;
			case KEY_TYPE_PRIV_DP1:
				this.cukPriv.setDP1(this.keyScratchPad, (short) 0, JediIdentity.RSA2048_PQ_SIZE);
				break;
			case KEY_TYPE_PRIV_DQ1:
				this.cukPriv.setDQ1(this.keyScratchPad, (short) 0, JediIdentity.RSA2048_PQ_SIZE);
				break;
			default:
				ISOException.throwIt((short) 0x9c01);
				return (short) 0;
			}
			this.setTmpKeyTypeFlag(KEY_TYPE_UNSPECIFIED);
			this.setTmpKeyOffset((short) 0);
		}
		return actual;
	}

	/**
	 * Generates controller-unique RSA keypair.
	 */
	public void genKeyPair() throws ISOException {
		KeyPair kp = null;
		// Check for hw capabilities
		try {
			kp = new KeyPair(this.cukPub, this.cukPriv);
		} catch (CryptoException e) {
			// RSA 2048 is not supported
			if (e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
				ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
			} else {
				ISOException.throwIt(ISO7816.SW_UNKNOWN);
			}
		}

		// Actually generate the key
		kp.genKeyPair();
	}

	public short putPrivateKeyP(final byte[] buffer, short offset, short len) {
		return this.putKeyObject(buffer, offset, len, KEY_TYPE_PRIV_P);
	}
	
	public short putPrivateKeyQ(final byte[] buffer, short offset, short len) {
		return this.putKeyObject(buffer, offset, len, KEY_TYPE_PRIV_Q);
	}

	public short putPrivateKeyPQ(final byte[] buffer, short offset, short len) {
		return this.putKeyObject(buffer, offset, len, KEY_TYPE_PRIV_PQ);
	}

	public short putPrivateKeyDP1(final byte[] buffer, short offset, short len) {
		return this.putKeyObject(buffer, offset, len, KEY_TYPE_PRIV_DP1);
	}

	public short putPrivateKeyDQ1(final byte[] buffer, short offset, short len) {
		return this.putKeyObject(buffer, offset, len, KEY_TYPE_PRIV_DQ1);
	}
	
	/**
	 * Copies the serial number from a buffer into the object.
	 * Note that the length must be equal to the size of the serial number or it will be rejected with
	 * {@link ISO7816#SW_WRONG_LENGTH ISO7816.SW_WRONG_LENGTH}. Therefore the input must NOT be split
	 * into chunks/pages.
	 * @param buffer The buffer that contains the serial number.
	 * @param boffset Offset where the serial number is located.
	 * @param len Number of bytes to copy.
	 * @return Number of bytes copied.
	 */
	public short putSerialNumber(final byte[] buffer, short boffset, short len) {
		short sz;
		if (len != this.serialNumber.length) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return 0;
		}
		sz = Util.arrayCopyNonAtomic(buffer, boffset, this.serialNumber, (short) 0, len);
		return sz;
	}

	public final byte[] getSerialNumber() {
		return this.serialNumber;
	}

	public short putPublicKeyN(final byte[] buffer, short offset, short len) {
		return this.putKeyObject(buffer, offset, len, KEY_TYPE_PUB_N);
	}

	public short putPublicKeyE(final byte[] buffer, short offset, short len) {
		return this.putKeyObject(buffer, offset, len, KEY_TYPE_PUB_E);
	}
	
	public short putIdSig(final byte[] buffer, short offset, short len) {
		return this.putKeyObject(buffer, offset, len, KEY_TYPE_PUB_SIG);
	}

	public final RSAPublicKey getPublicKey() {
		return this.cukPub;
	}

	public final byte[] exportPublicKeyN() {
		this.setTmpKeyTypeFlag(KEY_TYPE_EXPORT_PUB_N);
		this.getPublicKey().getModulus(this.keyScratchPad, (short) 0);
		return this.keyScratchPad;
	}

	public final byte[] exportPublicKeyE() {
		this.setTmpKeyTypeFlag(KEY_TYPE_EXPORT_PUB_E);
		this.getPublicKey().getExponent(this.keyScratchPad, (short) 0);
		return this.keyScratchPad;
	}

	public void finishExport() {
		this.setTmpKeyTypeFlag(KEY_TYPE_UNSPECIFIED);
	}

	public final RSAPrivateCrtKey getPrivateKey() {
		return this.cukPriv;
	}

	public final byte[] getIdSig() {
		return this.idSig;
	}

	/**
	 * Returns the readiness of the object.
	 * 
	 * Note that this only checks if the private and public keys are initialized.
	 * Unsigned key blocks will still pass the test.
	 * @return true if ready.
	 */
	public boolean isReady() {
		return this.cukPriv.isInitialized() && this.cukPub.isInitialized();
	}
}
