package illegal.security.chip;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.Signature;

public class ISCApplet extends Applet {
	private static final short LEN_TEMP_STATES = (short) 0x2;
	private static final short LEN_DS4RESP_SIG = JediIdentity.RSA2048_INT_SIZE;
	// Offsets
	private static final short OFFSET_TS_AUTH_CPAGE = (short) 0x0;
	private static final short OFFSET_TS_PAGE_SIZE = (short) 0x1;

	private static final short OFFSET_DS4RESP_SIG = (short) 0x0;
	private static final short OFFSET_DS4RESP_ID_SERIAL = OFFSET_DS4RESP_SIG + LEN_DS4RESP_SIG;
	private static final short OFFSET_DS4RESP_ID_PUB_N = OFFSET_DS4RESP_ID_SERIAL + JediIdentity.LEN_ID_SERIAL;
	private static final short OFFSET_DS4RESP_ID_PUB_E = OFFSET_DS4RESP_ID_PUB_N + JediIdentity.LEN_ID_PUB_N;
	private static final short OFFSET_DS4RESP_ID_SIG = OFFSET_DS4RESP_ID_PUB_E + JediIdentity.LEN_ID_PUB_E;

	private static final short LEN_DS4RESP = OFFSET_DS4RESP_ID_SIG + JediIdentity.LEN_ID_SIG;

	// APDU classes
	private static final byte CLA_AUTH = (byte) 0x80;
	private static final byte CLA_CONFIG = (byte) 0x81;

	// APDU commands for CLA_AUTH
	private static final byte INS_AUTH_SET_CHALLENGE = (byte) 0x44;
	private static final byte INS_AUTH_GET_RESPONSE = (byte) 0x46;
	private static final byte INS_AUTH_RESET = (byte) 0x48;

	// APDU commands for CLA_CONFIG
	private static final byte INS_CONFIG_GET_STATUS = (byte) 0x00;
	private static final byte INS_CONFIG_GEN_KEYS = (byte) 0x0f;
	// Import public pages
	private static final byte INS_CONFIG_IMPORT_SERIAL = (byte) 0x10;
	private static final byte INS_CONFIG_IMPORT_PUB_N = (byte) 0x11;
	private static final byte INS_CONFIG_IMPORT_PUB_E = (byte) 0x12;
	private static final byte INS_CONFIG_IMPORT_SIG_ID = (byte) 0x13;
	// Import private pages
	private static final byte INS_CONFIG_IMPORT_PRIV_P = (byte) 0x20;
	private static final byte INS_CONFIG_IMPORT_PRIV_Q = (byte) 0x21;
	private static final byte INS_CONFIG_IMPORT_PRIV_PQ = (byte) 0x22;
	private static final byte INS_CONFIG_IMPORT_PRIV_DP1 = (byte) 0x23;
	private static final byte INS_CONFIG_IMPORT_PRIV_DQ1 = (byte) 0x24;
	// Import DS4ID/DS4KeyX
	private static final byte INS_CONFIG_IMPORT_FULL = (byte) 0x30;
	private static final byte INS_CONFIG_IMPORT_FULL_PRIV = (byte) 0x31;
	// Nuke applet data
	private static final byte INS_CONFIG_NUKE = (byte) 0xff;

	private Signature sigChallenge;
	private final JediIdentity id;
	private final short[] tempStates;
	private final byte[] signature;

	public ISCApplet() {
		this.sigChallenge = Signature.getInstance(Signature.ALG_RSA_SHA_256_PKCS1_PSS, false);
		this.id = new JediIdentity();
		this.tempStates = JCSystem.makeTransientShortArray(LEN_TEMP_STATES, JCSystem.CLEAR_ON_DESELECT);
		this.signature = JCSystem.makeTransientByteArray(JediIdentity.RSA2048_INT_SIZE, JCSystem.CLEAR_ON_DESELECT);
	}

	public static void install(byte[] bArray, short bOffset, byte bLength)
			throws ISOException {
		// TODO
		ISCApplet app = new ISCApplet();
		app.register();
	}

	private void processAuthReset(APDU apdu) throws ISOException {
		this.sigChallenge.init(this.id.getPrivateKey(), Signature.MODE_SIGN);
		// starts from page 0
		tempStates[OFFSET_TS_AUTH_CPAGE] = (short) 0;
		tempStates[OFFSET_TS_PAGE_SIZE] = (short) 0;
		Util.arrayFillNonAtomic(this.signature, (short) 0, (short) this.signature.length, (byte) 0);
	}

	private void processAuthSetChallenge(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		short rectifiedP1, rectifiedP2, remaining;

		// Rectify P1 and P2
		rectifiedP1 = (short) (buf[ISO7816.OFFSET_P1] & 0xff);
		rectifiedP2 = (short) (buf[ISO7816.OFFSET_P2] & 0xff);
		remaining = (short) (buf[ISO7816.OFFSET_LC] & 0xff);
		// Our stream implementation requires the offset to be strictly incremental. So check those.
		if (tempStates[OFFSET_TS_PAGE_SIZE] == 0) {
			tempStates[OFFSET_TS_PAGE_SIZE] = rectifiedP1;
		} else if (tempStates[OFFSET_TS_PAGE_SIZE] != rectifiedP1) {
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
		if (tempStates[OFFSET_TS_AUTH_CPAGE] != rectifiedP2) {
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
		
		short bytes = apdu.setIncomingAndReceive();
		while (remaining > 0) {
			if (remaining <= bytes) {
				this.sigChallenge.sign(buf, ISO7816.OFFSET_CDATA, remaining, this.signature, (short) 0);
				remaining -= bytes;
			} else {
				this.sigChallenge.update(buf, ISO7816.OFFSET_CDATA, bytes);
				remaining -= bytes;
				bytes = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
			}
		}
		tempStates[OFFSET_TS_AUTH_CPAGE]++;
	}

	private void processAuthGetResponse(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		short rectifiedP1, rectifiedP2, remaining, byteOffset;
		rectifiedP1 = (short) (buf[ISO7816.OFFSET_P1] & 0xff);
		rectifiedP2 = (short) (buf[ISO7816.OFFSET_P2] & 0xff);
		remaining = apdu.setOutgoing();
		byteOffset = (short) ((short) (rectifiedP1 * rectifiedP2) % LEN_DS4RESP);
		while (remaining > 0) {
			if (byteOffset >= OFFSET_DS4RESP_SIG && byteOffset < OFFSET_DS4RESP_ID_SERIAL) {
				// TODO
			}
		}

	}

	public void process(APDU apdu) throws ISOException {
		// TODO
		byte[] buf = apdu.getBuffer();
		
		switch (buf[ISO7816.OFFSET_CLA]) {
		case ISO7816.CLA_ISO7816:
			switch (buf[ISO7816.OFFSET_INS]) {
			case ISO7816.INS_SELECT:
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
			break;
		case CLA_AUTH:
			if (!this.id.isReady()) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				return;
			}
			switch (buf[ISO7816.OFFSET_INS]) {
			case INS_AUTH_RESET:
				this.processAuthReset(apdu);
				break;
			case INS_AUTH_SET_CHALLENGE:
				this.processAuthSetChallenge(apdu);
				break;
			case INS_AUTH_GET_RESPONSE:
				this.processAuthGetResponse(apdu);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
			break;
		case CLA_CONFIG:
			switch (buf[ISO7816.OFFSET_INS]) {
			// TODO
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
			break;
		default:
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
	}

} // ISCApplet
