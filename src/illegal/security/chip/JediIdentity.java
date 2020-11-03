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
	private static final byte OFFSET_TMP_SERIAL = (byte) 0;
	private static final byte OFFSET_TMP_ID_KEYX = (byte) 1;
	private static final byte OFFSET_TMP_KEY = (byte) 2;

	private static final byte FLAG_TMP_KEY_TYPE = (byte) 3;
	
	private static final byte LEN_TMP = (byte) 4;

	public static final short RSA2048_INT_SIZE = (short) 0x100;

	public static final short LEN_ID_SERIAL = (short) 0x10;
	public static final short LEN_ID_PUB_N = RSA2048_INT_SIZE;
	public static final short LEN_ID_PUB_E = RSA2048_INT_SIZE;
	public static final short LEN_ID_SIG = RSA2048_INT_SIZE;

	private static final short OFFSET_ID_SERIAL = (short) 0x0;
	private static final short OFFSET_ID_PUB_N = OFFSET_ID_SERIAL + LEN_ID_SERIAL;
	private static final short OFFSET_ID_PUB_E = OFFSET_ID_PUB_N + LEN_ID_PUB_N;
	private static final short OFFSET_ID_SIG = OFFSET_ID_PUB_E + LEN_ID_PUB_E;

	private static final short LEN_ID = OFFSET_ID_SIG + LEN_ID_SIG;
	
	private static final short KEY_TYPE_UNSPECIFIED = (short) 0;
	private static final short KEY_TYPE_PUB_N = (short) 1;
	private static final short KEY_TYPE_PUB_E = (short) 2;
	private static final short KEY_TYPE_PUB_SIG = (short) 3;
	private static final short KEY_TYPE_PRIV_P = (short) 4;
	private static final short KEY_TYPE_PRIV_Q = (short) 5;
	private static final short KEY_TYPE_PRIV_PQ = (short) 6;
	private static final short KEY_TYPE_PRIV_DP1 = (short) 7;
	private static final short KEY_TYPE_PRIV_DQ1 = (short) 8;

	/**
	 * True if the object is ready to use
	 */
	private boolean ready;
	/**
	 * Serial number of the security chip
	 */
	private final byte[] serialNumber;
	/**
	 * Controller-unique public key
	 */
	private RSAPublicKey cukPub;
	/**
	 * Controller-unique private key
	 */
	private RSAPrivateCrtKey cukPriv;
	/**
	 * Signature of the public identity block
	 */
	private final byte[] idSig;
	private final short[] tmp;
	private final byte[] keyScratchPad;

	public JediIdentity() {
		this.serialNumber = new byte[(short) 8];
		this.idSig = new byte[(short) 0x100];
		this.tmp = JCSystem.makeTransientShortArray(LEN_TMP, JCSystem.CLEAR_ON_DESELECT);
		this.keyScratchPad = JCSystem.makeTransientByteArray((short) 0x100, JCSystem.CLEAR_ON_DESELECT);
		this.cukPub = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
		this.cukPriv = (RSAPrivateCrtKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
		this.nuke();
	}

	/**
	 * Resets the object to uninitialized state.
	 */
	public void nuke() {
		this.reset();
		this.ready = false;
		this.cukPub.clearKey();
		this.cukPriv.clearKey();
		Util.arrayFillNonAtomic(this.serialNumber, (short) 0, (short) this.serialNumber.length, (byte) 0);
		Util.arrayFillNonAtomic(this.idSig, (short) 0, (short) this.idSig.length, (byte) 0);
	}

	/**
	 * Resets all transient states
	 */
	public void reset() {
		this.setTmpSerialOffset((short) 0);
		this.setTmpIdKeyXOffset((short) 0);
		this.setTmpKeyOffset((short) 0);
		this.setTmpKeyTypeFlag(KEY_TYPE_UNSPECIFIED);
		this.clearScratchPad();
	}

	private void setTmpSerialOffset(short off) {
		this.tmp[OFFSET_TMP_SERIAL] = off;
	}

	private void incTmpSerialOffset(short inc) {
		this.tmp[OFFSET_TMP_SERIAL] += inc;
	}

	private short getTmpSerialOffset() {
		return this.tmp[OFFSET_TMP_SERIAL];
	}

	private void setTmpIdKeyXOffset(short off) {
		this.tmp[OFFSET_TMP_ID_KEYX] = off;
	}

	private void incTmpIdKeyXOffset(short inc) {
		this.tmp[OFFSET_TMP_ID_KEYX] += inc;
	}

	private short getTmpIdKeyXOffset() {
		return this.tmp[OFFSET_TMP_ID_KEYX];
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
		this.tmp[FLAG_TMP_KEY_TYPE] = flag;
	}

	private short getTmpKeyTypeFlag() {
		return this.tmp[FLAG_TMP_KEY_TYPE];
	}

	private void clearScratchPad() {
		Util.arrayFillNonAtomic(this.keyScratchPad, (short) 0, (short) this.keyScratchPad.length, (byte) 0);
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
		this.ready = true;
	}

	public short putFullIdentityBlock(byte[] buffer, short offset, short len) {
		short idOffset = this.getTmpIdKeyXOffset();
		short actual_total = 0;
		while (len > 0) {
			short actual;
			if (OFFSET_ID_SERIAL <= idOffset && idOffset < OFFSET_ID_PUB_N) {
				// Serial
				actual = this.putSerialNumber(buffer, offset, len);
			} else if (OFFSET_ID_PUB_N <= idOffset && idOffset < OFFSET_ID_PUB_E) {
				// Public key (Modulus)
				actual = this.putPublicKeyN(buffer, offset, len);
			} else if (OFFSET_ID_PUB_E <= idOffset && idOffset < OFFSET_ID_SIG) {
				// Public key (Exponent)
				actual = this.putPublicKeyE(buffer, offset, len);
			} else if (OFFSET_ID_SIG <= idOffset && idOffset < LEN_ID) {
				// Signature of the identity block
				actual = this.putPublicKeyN(buffer, offset, len);
				// Finalize import
				this.ready = true;
			} else {
				// Out-of-bound, shouldn't happen
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				break;
			}
			len -= actual;
			actual_total += actual;
		}
		this.incTmpIdKeyXOffset(actual_total);
		return actual_total;
	}

	public void putExtendedKeyBlock(byte[] buffer, short offset, short len) {
		// TODO
	}

	private short putKeyObject(byte[] buffer, short offset, short len, short keyType) {
		short actual;
		short bounds = 0;
		switch (keyType) {
		case KEY_TYPE_PUB_N:
		case KEY_TYPE_PUB_E:
		case KEY_TYPE_PUB_SIG:
			bounds = 0x100;
			break;
		case KEY_TYPE_PRIV_P:
		case KEY_TYPE_PRIV_Q:
		case KEY_TYPE_PRIV_PQ:
		case KEY_TYPE_PRIV_DP1:
		case KEY_TYPE_PRIV_DQ1:
			bounds = 0x80;
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
				this.cukPub.setModulus(this.keyScratchPad, (short) 0, (short) 0x100);
				break;
			case KEY_TYPE_PUB_E:
				this.cukPub.setExponent(this.keyScratchPad, (short) 0, (short) 0x100);
				break;
			case KEY_TYPE_PUB_SIG:
				Util.arrayCopyNonAtomic(this.keyScratchPad, (short) 0, this.idSig, (short) 0, (short) this.idSig.length);
				break;
			case KEY_TYPE_PRIV_P:
				this.cukPriv.setP(this.keyScratchPad, (short) 0, (short) 0x80);
				break;
			case KEY_TYPE_PRIV_Q:
				this.cukPriv.setQ(this.keyScratchPad, (short) 0, (short) 0x80);
				break;
			case KEY_TYPE_PRIV_PQ:
				this.cukPriv.setPQ(this.keyScratchPad, (short) 0, (short) 0x80);
				break;
			case KEY_TYPE_PRIV_DP1:
				this.cukPriv.setDP1(this.keyScratchPad, (short) 0, (short) 0x80);
				break;
			case KEY_TYPE_PRIV_DQ1:
				this.cukPriv.setDQ1(this.keyScratchPad, (short) 0, (short) 0x80);
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

	public short putPrivateKeyP(byte[] buffer, short offset, short len) {
		return this.putKeyObject(buffer, offset, len, KEY_TYPE_PRIV_P);
	}
	
	public short putPrivateKeyQ(byte[] buffer, short offset, short len) {
		return this.putKeyObject(buffer, offset, len, KEY_TYPE_PRIV_Q);
	}

	public short putPrivateKeyPQ(byte[] buffer, short offset, short len) {
		return this.putKeyObject(buffer, offset, len, KEY_TYPE_PRIV_PQ);
	}

	public short putPrivateKeyDP1(byte[] buffer, short offset, short len) {
		return this.putKeyObject(buffer, offset, len, KEY_TYPE_PRIV_DP1);
	}

	public short putPrivateKeyDQ1(byte[] buffer, short offset, short len) {
		return this.putKeyObject(buffer, offset, len, KEY_TYPE_PRIV_DQ1);
	}
	
	/**
	 * Copies the serial number from a buffer into the object.
	 * @param buffer The buffer that contains the serial number.
	 * @param boffset Offset where the serial number is located.
	 * @param len Number of bytes to copy.
	 */
	public short putSerialNumber(byte[] buffer, short boffset, short len) {
		short min;
		short diff = (short) (this.serialNumber.length - this.getTmpSerialOffset());
		short sz;
		if (len < diff) {
			min = len;
		} else if (diff < 0) {
			min = 0;
		} else {
			min = diff;
		}
		sz = Util.arrayCopyNonAtomic(buffer, boffset,
								this.serialNumber, this.getTmpSerialOffset(),
								min);
		this.incTmpSerialOffset(sz);
		return sz;
	}

	public final byte[] getSerialNumber() {
		return this.serialNumber;
	}

	public short putPublicKeyN(byte[] buffer, short offset, short len) {
		return this.putKeyObject(buffer, offset, len, KEY_TYPE_PUB_N);
	}

	public short putPublicKeyE(byte[] buffer, short offset, short len) {
		return this.putKeyObject(buffer, offset, len, KEY_TYPE_PUB_E);
	}
	
	public short putIdSig(byte[] buffer, short offset, short len) {
		return this.putKeyObject(buffer, offset, len, KEY_TYPE_PUB_SIG);
	}

	public final RSAPublicKey getPublicKey() {
		return this.cukPub;
	}

	public final RSAPrivateCrtKey getPrivateKey() {
		return this.cukPriv;
	}

	public boolean isReady() {
		return this.ready;
	}
}
