package crypto;

import static crypto.Helper.bytesToString;
import static crypto.Helper.stringToBytes;

import java.util.*;
import java.util.Map.Entry;

public class Decrypt {

	public static final int ALPHABETSIZE = Byte.MAX_VALUE - Byte.MIN_VALUE + 1; // 256
	public static final int APOSITION = 97 + ALPHABETSIZE / 2;
	public static final int CAESAR = 0;
	public static final int VIGENERE = 1;
	public static final int XOR = 2;

	// source : https://en.wikipedia.org/wiki/Letter_frequency
	public static final double[] ENGLISHFREQUENCIES = { 0.08497, 0.01492, 0.02202, 0.04253, 0.11162, 0.02228, 0.02015,
			0.06094, 0.07546, 0.00153, 0.01292, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.07587, 0.06327,
			0.09356, 0.02758, 0.00978, 0.0256, 0.0015, 0.01994, 0.00077 };

	/**
	 * Method to break a string encoded with different types of cryptosystems
	 * 
	 * @param type the integer representing the method to break : 0 = Caesar, 1 =
	 *             Vigenere, 2 = XOR
	 * @return the decoded string or the original encoded message if type is not in
	 *         the list above.
	 */
	public static String breakCipher(String cipher, int type) {

		byte[] encryptedText = stringToBytes(cipher);
		byte[] byteResultat;
		byte[][] bruteForceResultat;

        return switch (type) {
            case CAESAR -> {
                byteResultat = Encrypt.caesar(encryptedText, caesarWithFrequencies(encryptedText));
                yield bytesToString(byteResultat);
            }
            case VIGENERE -> {
                byteResultat = Encrypt.vigenere(encryptedText, vigenereWithFrequencies(encryptedText));
                yield bytesToString(byteResultat);
            }
            case XOR -> {
                bruteForceResultat = xorBruteForce(encryptedText);
                yield arrayToString(bruteForceResultat);
            }
            default -> cipher;
        };

	}

	/**
	 * Converts a 2D byte array to a String
	 * 
	 * @param bruteForceResult a 2D byte array containing the result of a brute
	 *                         force method
	 */
	public static String arrayToString(byte[][] bruteForceResult) {
		StringBuilder resultat = new StringBuilder();
        for (byte[] bytes : bruteForceResult) {

            resultat.append(bytesToString(bytes)).append(System.lineSeparator());

        }

		return resultat.toString();
	}

	// -----------------------Caesar-------------------------

	/**
	 * Method to decode a byte array encoded using the Caesar scheme This is done by
	 * the brute force generation of all the possible options
	 * 
	 * @param cipher the byte array representing the encoded text
	 * @return a 2D byte array containing all the possibilities
	 */
	public static byte[][] caesarBruteForce(byte[] cipher) {
		byte[][] resultat = new byte[ALPHABETSIZE][];
		for (int i = 0; i < ALPHABETSIZE; i++) {

			resultat[i] = Encrypt.caesar(cipher, (byte) i);

		}

		return resultat;
	}

	/**
	 * Method that finds the key to decode a Caesar encoding by comparing
	 * frequencies
	 * 
	 * @param cipherText the byte array representing the encoded text
	 * @return the encoding key
	 */
	public static byte caesarWithFrequencies(byte[] cipherText) {
		float[] frequencies = computeFrequencies(cipherText);
		byte key;
		key = caesarFindKey(frequencies);

		return key;
	}

	/**
	 * Method that computes the frequencies of letters inside a byte array
	 * corresponding to a String
	 * 
	 * @param cipherText the byte array
	 * @return the character frequencies as an array of float
	 */
	public static float[] computeFrequencies(byte[] cipherText) {
		float[] resultat = new float[ALPHABETSIZE];

		for (byte b : cipherText) {
            if (b != Encrypt.SPACE) {

                resultat[b + 127]++;
            }

        }
		for (int i = 0; i < ALPHABETSIZE; i++) {

			resultat[i] /= cipherText.length;
		}
		return resultat;
	}

	/**
	 * Method that finds the key used by a Caesar encoding from an array of
	 * character frequencies
	 * 
	 * @param charFrequencies the array of character frequencies
	 * @return the key
	 */
	public static byte caesarFindKey(float[] charFrequencies) {
		float[] produitScalaire = new float[ALPHABETSIZE];
		for (int i = 0; i < ALPHABETSIZE; i++) {
			for (int j = 0; j < ENGLISHFREQUENCIES.length; j++) {

				produitScalaire[i] += (float) (ENGLISHFREQUENCIES[j] * charFrequencies[(i + j) % 256]);
			}
		}
		int indiceMax = 0;
		for (int i = 0; i < ALPHABETSIZE; i++) {
			if (produitScalaire[i] > produitScalaire[indiceMax]) {
				indiceMax = i;
			}

		}

		return (byte) (APOSITION - (indiceMax + 1));
	}

	// -----------------------XOR-------------------------

	/**
	 * Method to decode a byte array encoded using a XOR This is done by the brute
	 * force generation of all the possible options
	 * 
	 * @param cipher the byte array representing the encoded text
	 * @return the array of possibilities for the clear text
	 */
	public static byte[][] xorBruteForce(byte[] cipher) {
		byte[][] resultat = new byte[ALPHABETSIZE][];
		for (int i = 0; i < ALPHABETSIZE; i++) {

			resultat[i] = Encrypt.xor(cipher, (byte) i);

		}

		return resultat;
	}

	// -----------------------Vigenere-------------------------
	// Algorithm : see https://www.youtube.com/watch?v=LaWp_Kq0cKs
	/**
	 * Method to decode a byte array encoded following the Vigenere pattern, but in
	 * a clever way, saving up on large amounts of computations
	 * 
	 * @param cipher the byte array representing the encoded text
	 * @return the byte encoding of the clear text
	 */
	public static byte[] vigenereWithFrequencies(byte[] cipher) {
		List<Byte> cipherNoSpace = removeSpaces(cipher);
		int keyLength = vigenereFindKeyLength(cipherNoSpace);

        return vigenereFindKey(cipherNoSpace, keyLength);
	}

	/**
	 * Helper Method used to remove the space character in a byte array for the
	 * clever Vigenere decoding
	 * 
	 * @param array the array to clean
	 * @return a List of bytes without spaces
	 */
	public static List<Byte> removeSpaces(byte[] array) {
		List<Byte> resultat = new ArrayList<>();
        for (byte b : array) {
            if (b != Encrypt.SPACE) {
                resultat.add(b);
            }
        }
		return resultat;
	}

	/**
	 * Method that computes the key length for a Vigenere cipher text.
	 * 
	 * @param cipher the byte array representing the encoded text without space
	 * @return the length of the key
	 */
	public static int vigenereFindKeyLength(List<Byte> cipher) {
		int[] coincidence = coincidence(cipher);
		ArrayList<Integer> indices;
		indices = maximumLocal(coincidence);
        return keyLength(indices);
	}

	public static int keyLength(ArrayList<Integer> indices) {
		Map<Integer, Integer> distance = new HashMap<>();
		int keyLength = 0;
		int j;
		int occurence;
		for (int i = 0; i < indices.size() - 1; i++) {
			j = indices.get(i + 1) - indices.get(i);
			occurence = (distance.containsKey(j)) ? distance.get(j) + 1 : 1;
			distance.put(j, occurence);
		}
		int occMax = 0;
		for (Entry<Integer, Integer> map : distance.entrySet()) {
			if (map.getValue() > occMax) {
				occMax = map.getValue();
				keyLength = map.getKey();

			}
			else if ((map.getValue() == occMax) && map.getKey()>keyLength ) 
			{
				keyLength = map.getKey();
			}
		}
		return keyLength;

	}

	public static ArrayList<Integer> maximumLocal(int[] coincidence) {
		ArrayList<Integer> indices = new ArrayList<>();
		int borne = (int) Math.ceil(coincidence.length / 2.0);

		for (int i = 0; i < borne; i++) {
			if ((i == 0) && (coincidence[i] > coincidence[i + 1]) && (coincidence[i] > coincidence[i + 2])) {
				indices.add(i);
			} else if ((i == 1) && (coincidence[i] > coincidence[i + 1]) && (coincidence[i] > coincidence[i + 2])
					&& (coincidence[i] > coincidence[i - 1])) {
				indices.add(i);
			} else if ((i > 1) && (coincidence[i] > coincidence[i + 1]) && (coincidence[i] > coincidence[i + 2])
					&& (coincidence[i] > coincidence[i - 1]) && (coincidence[i] > coincidence[i - 2])) {
				indices.add(i);
			}
		}
		return indices;
	}

	public static int[] coincidence(List<Byte> cipher) {
		int[] resultat = new int[cipher.size() - 1];
		for (int i = 0; i < resultat.length; i++) {
			for (int j = i + 1; j < cipher.size(); j++) {
				if (Objects.equals(cipher.get(j), cipher.get(j - (i + 1)))) {
					resultat[i]++;
				}
			}
		}
		return resultat;
	}

	/**
	 * Takes the cipher without space, and the key length, and uses the dot product
	 * with the English language frequencies to compute the shifting for each letter
	 * of the key
	 * 
	 * @param cipher    the byte array representing the encoded text without space
	 * @param keyLength the length of the key we want to find
	 * @return the inverse key to decode the Vigenere cipher text
	 */
	public static byte[] vigenereFindKey(List<Byte> cipher, int keyLength) {


		byte[] keyword = new byte[keyLength];
		for (int i = 0; i < keyLength; i++) {
			ArrayList<Byte> cipherPartition = new ArrayList<>();
			for (int j = 0; j < cipher.size(); j++) {
				if (j % keyLength == i) {
					cipherPartition.add(cipher.get(j));
				}
			}
			keyword[i] = caesarWithFrequencies(toArray(cipherPartition));
		}
		return keyword;

	}

	private static byte[] toArray(ArrayList<Byte> liste) {
		byte[] resultat = new byte[liste.size()];
		for (int i = 0; i < resultat.length; i++) {
			resultat[i] = liste.get(i);
		}

		return resultat;
	}

	// -----------------------Basic CBC-------------------------

	/**
	 * Method used to decode a String encoded following the CBC pattern
	 * 
	 * @param cipher the byte array representing the encoded text
	 * @param iv     the pad of size BLOCKSIZE we use to start the chain encoding
	 * @return the clear text
	 */
	public static byte[] decryptCBC(byte[] cipher, byte[] iv) {
		byte[] resultat = new byte[cipher.length];
		int nb;
		int l = iv.length;
		byte[] pad = iv.clone();
		nb = cipher.length / l;
		for (int i = 0; i < nb; i++) {
			for (int j = 0; j < l; j++) {
				resultat[i * l + j] = (byte) (pad[j] ^ cipher[i * l + j]);
				pad[j] = cipher[i * l + j];
			}
		}
		if (cipher.length % l != 0) {
			int nbRestant = cipher.length % l;
			for (int i = nb * l; i < nbRestant + (nb * l); i++) {
				resultat[i] = (byte) (pad[i - (nb * l)] ^ cipher[i]);
			}
		}
		return resultat;
	}

}
