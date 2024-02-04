package crypto;

import java.util.Random;


public class Encrypt {

	public static final int CAESAR = 0;
	public static final int VIGENERE = 1;
	public static final int XOR = 2;
	public static final int ONETIME = 3;
	public static final int CBC = 4;

	public static final byte SPACE = 32;

	final static Random rand = new Random(2L);

	// -----------------------General-------------------------

	/**
	 * General method to encode a message using a key, you can choose the method you
	 * want to use to encode.
	 * 
	 * @param message the message to encode already cleaned
	 * @param key     the key used to encode
	 * @param type    the method used to encode : 0 = Caesar, 1 = Vigenere, 2 = XOR,
	 *                3 = One time pad, 4 = CBC
	 * 
	 * @return an encoded String if the method is called with an unknown type of
	 *         algorithm, it returns the original message
	 */
	public static String encrypt(String message, String key, int type) {
		String stringResultat;

		byte[] plainText = Helper.stringToBytes(message);

		byte[] pad = Helper.stringToBytes(key);

		byte[] byteResultat = switch (type) {
            case CAESAR -> caesar(plainText, pad[0]);
            case VIGENERE -> vigenere(plainText, pad);
            case XOR -> xor(plainText, pad[0]);
            case ONETIME -> oneTimePad(plainText, pad);
            case CBC -> cbc(plainText, pad);
            default -> plainText;
        };

        stringResultat = Helper.bytesToString(byteResultat);

		return stringResultat;
	}

	// -----------------------Caesar-------------------------

	/**
	 * Method to encode a byte array message using a single character key the key is
	 * simply added to each byte of the original message
	 * 
	 * @param plainText     The byte array representing the string to encode
	 * @param key           the byte corresponding to the char we use to shift
	 * @param spaceEncoding if false, then spaces are not encoded
	 * @return an encoded byte array
	 */
	public static byte[] caesar(byte[] plainText, byte key, boolean spaceEncoding) {
		assert (plainText != null);
		byte[] resultat = new byte[plainText.length];

		for (int i = 0; i < plainText.length; i++) {
			if (plainText[i] == SPACE && !spaceEncoding) {
				resultat[i] = SPACE;

			} else {

				resultat[i] = (byte) (plainText[i] + key);
			}

		}
		return resultat;
	}

	/**
	 * Method to encode a byte array message using a single character key the key is
	 * simply added to each byte of the original message spaces are not encoded
	 * 
	 * @param plainText The byte array representing the string to encode
	 * @param key       the byte corresponding to the char we use to shift
	 * @return an encoded byte array
	 */
	public static byte[] caesar(byte[] plainText, byte key) {

		return caesar(plainText, key, false);
	}

	// -----------------------XOR-------------------------

	/**
	 * Method to encode a byte array using a XOR with a single byte long key
	 * 
	 * @param plainText     the byte array representing the string to encode
	 * @param key           the byte we will use to XOR
	 * @param spaceEncoding if false, then spaces are not encoded
	 * @return an encoded byte array
	 */
	public static byte[] xor(byte[] plainText, byte key, boolean spaceEncoding) {
		byte[] resultat = new byte[plainText.length];
		for (int i = 0; i < plainText.length; i++) {
			if (plainText[i] == SPACE && !spaceEncoding) {
				resultat[i] = SPACE;

			} else {
				resultat[i] = (byte) (plainText[i] ^ key);

			}

		}

		return resultat;
	}

	/**
	 * Method to encode a byte array using a XOR with a single byte long key spaces
	 * are not encoded
	 * 
	 * @param key the byte we will use to XOR
	 * @return an encoded byte array
	 */
	public static byte[] xor(byte[] plainText, byte key) {
		return xor(plainText, key, false);
	}
	// -----------------------Vigenere-------------------------

	/**
	 * Method to encode a byte array using a byte array keyword The keyword is
	 * repeated along the message to encode The bytes of the keyword are added to
	 * those of the message to encode
	 * 
	 * @param plainText     the byte array representing the message to encode
	 * @param keyword       the byte array representing the key used to perform the
	 *                      shift
	 * @param spaceEncoding if false, then spaces are not encoded
	 * @return an encoded byte array
	 */
	public static byte[] vigenere(byte[] plainText, byte[] keyword, boolean spaceEncoding) {
		byte[] resultat = new byte[plainText.length];
		int j = 0;

		for (int i = 0; i < plainText.length; i++) {
			if (plainText[i] == SPACE && !spaceEncoding) {
				resultat[i] = SPACE;

			} else {
				resultat[i] = (byte) (plainText[i] + keyword[j]);
				j = (j + 1) % keyword.length;

			}

		}

		return resultat;
	}

	/**
	 * Method to encode a byte array using a byte array keyword The keyword is
	 * repeated along the message to encode spaces are not encoded The bytes of the
	 * keyword are added to those of the message to encode
	 * 
	 * @param plainText the byte array representing the message to encode
	 * @param keyword   the byte array representing the key used to perform the
	 *                  shift
	 * @return an encoded byte array
	 */
	public static byte[] vigenere(byte[] plainText, byte[] keyword) {
		return vigenere(plainText, keyword, false);
	}

	// -----------------------One Time Pad-------------------------

	/**
	 * Method to encode a byte array using a one time pad of the same length. The
	 * method XOR them together.
	 * 
	 * @param plainText the byte array representing the string to encode
	 * @param pad       the one time pad
	 * @return an encoded byte array
	 */
	public static byte[] oneTimePad(byte[] plainText, byte[] pad) {
		assert (plainText.length <= pad.length);

		byte[] resultat = new byte[plainText.length];

		for (int i = 0; i < plainText.length; i++) {
			resultat[i] = (byte) (plainText[i] ^ pad[i]);

		}

		return resultat;
	}

	// -----------------------Basic CBC-------------------------

	/**
	 * Method applying a basic chain block counter of XOR without encryption method.
	 * Encodes spaces.
	 * 
	 * @param plainText the byte array representing the string to encode
	 * @param iv        the pad of size BLOCKSIZE we use to start the chain encoding
	 * @return an encoded byte array
	 */
	public static byte[] cbc(byte[] plainText, byte[] iv) {
		byte[] resultat = new byte[plainText.length];
		int nb;
		int l = iv.length;
		byte[] pad = iv.clone();

		nb = plainText.length / l;

		for (int i = 0; i < nb; i++) {

			for (int j = 0; j < l; j++) {

				resultat[i * l + j] = (byte) (pad[j] ^ plainText[i * l + j]);
				pad[j] = resultat[i * l + j];

			}

		}
		if (plainText.length % l != 0) {
			int nbRestant = plainText.length % l;
			for (int i = nb * l; i < nbRestant + (nb * l); i++) {
				resultat[i] = (byte) (pad[i - (nb * l)] ^ plainText[i]);
			}

		}

		return resultat;
	}

	/**
	 * Generate a random pad/IV of bytes to be used for encoding
	 * 
	 * @param size the size of the pad
	 * @return random bytes in an array
	 */
	public static byte[] generatePad(int size) {
		byte[] pad = new byte[size];
		for (int i = 0; i < size; i++) {
			pad[i] = (byte) (rand.nextInt(256));

		}

		return pad;

	}

}
