package crypto;

import static crypto.Helper.cleanString;
import static crypto.Helper.stringToBytes;
import static crypto.Helper.bytesToString;
import java.util.List;

/*
 * Part 1: Encode (with note that one can reuse the functions to decode)
 * Part 2: bruteForceDecode (caesar, xor) and CBCDecode
 * Part 3: frequency analysis and key-length search
 * Bonus: CBC with encryption, shell
 */
public class Main {

	// ---------------------------MAIN---------------------------
	public static void main(String args[]) {

		String inputMessage = Helper.readStringFromFile("text_one.txt");
		String key = "2cF%5";

		String messageClean = cleanString(inputMessage);

		byte[] messageBytes = stringToBytes(messageClean);
		byte[] keyBytes = stringToBytes(key);

		System.out.println("Original input sanitized : " + messageClean);
		System.out.println();

		System.out.println("------Caesar------");
		testCaesar(messageBytes, keyBytes[0]);
		System.out.println();

		// TODO: TO BE COMPLETED
		System.out.println();
		String inputMessage2 = Helper.readStringFromFile("text_two.txt");
		String key2 = "bueb999d";
		String messageClean2 = cleanString(inputMessage2);
		System.out.println("Original input sanitized : " + messageClean2);
		System.out.println();
		System.out.println("------Vigenere------");
		testVigenere(messageClean2, key2);
		System.out.println();

		System.out.println();
		String inputMessage3 = Helper.readStringFromFile("text_three.txt");
		String key3 = "b8tcjiq";
		String messageClean3 = cleanString(inputMessage3);
		System.out.println("Original input sanitized : " + messageClean3);
		System.out.println();
		System.out.println("------CBC------");
		testCBC(messageClean3, key3);
		System.out.println();

		System.out.println();
		String key4 = "56rr";
		System.out.println("Original input sanitized : " + messageClean3);
		System.out.println();
		System.out.println("------XOR------");
		testXor(messageClean3, key4);
		System.out.println();

		System.out.println();
		System.out.println("Original input sanitized : " + messageClean);
		System.out.println();
		System.out.println("------OTP------");
		testOTP(messageClean);
		System.out.println();

		System.out.println();
		System.out.println("------Challenge------");
		System.out.println();
		String inputMessage4 = Helper.readStringFromFile("challenge-encrypted.txt");
		System.out.println("Decrypted Challenge : " + Decrypt.breakCipher(inputMessage4, 1));

		System.out.println();
		System.out.println("------MiniTests------");
		System.out.println();

		System.out.println("Test Caesar : ");
		byte[] plainBytes = { 105, 32, 119, 97, 110, 116 };
		byte key1 = 50;
		byte[] cipherText = Encrypt.caesar(plainBytes, key1);
		afficherTab(cipherText);
		System.out.println();

		System.out.println("Test Vigenere : ");
		byte[] keyWord = { 50, -10, 100 };
		byte[] cipherText1 = Encrypt.vigenere(plainBytes, keyWord);
		afficherTab(cipherText1);
		System.out.println();

		System.out.println("Test Xor : ");
		byte[] cipherText2 = Encrypt.xor(plainBytes, key1);
		afficherTab(cipherText2);
		System.out.println();

		System.out.println("Test Cbc : ");
		byte[] plainBytes1 = { 98, 111, 110, 110, 101, 32, 98, 120 };
		byte[] plainBytes2 = { 98, 111 };
		byte[] pad = { 1, 2, 3 };
		byte[] cipherText3 = Encrypt.cbc(plainBytes1, pad);
		byte[] cipherText4 = Encrypt.cbc(plainBytes2, pad);
		afficherTab(cipherText3);
		System.out.println();
		afficherTab(cipherText4);
		System.out.println();

		System.out.println("test coincidence ");
		byte[] array = stringToBytes("AA F  C AWW A");
		List<Byte> array1 = Decrypt.removeSpaces(array);
		int[] occurence = Decrypt.coincidence(array1);
		for (int i = 0; i < occurence.length; i++) {
			System.out.println(occurence[i] + " ");
		}
		System.out.println();

		System.out.println("test vigenere With Frequencies");
		byte[] textvig = stringToBytes(inputMessage);
		byte[] key5 = stringToBytes("qrdd");
		byte[] textvigencr = Encrypt.vigenere(textvig, key5);
		byte[] vigenereKey = Decrypt.vigenereWithFrequencies(textvigencr);
		afficherTab(vigenereKey);
		System.out.println();
		afficherTab(key5);

	}

	// Run the Encoding and Decoding using the caesar pattern
	public static void testCaesar(byte[] string, byte key) {
		// Encoding
		byte[] result = Encrypt.caesar(string, key);
		String s = bytesToString(result);
		System.out.println("Encoded : " + s);

		// Decoding with key
		String sD = bytesToString(Encrypt.caesar(result, (byte) (-key)));
		System.out.println("Decoded knowing the key : " + sD);

		// Decoding without key
		byte[][] bruteForceResult = Decrypt.caesarBruteForce(result);
		String sDA = Decrypt.arrayToString(bruteForceResult);
		Helper.writeStringToFile(sDA, "bruteForceCaesar.txt");

		byte decodingKey = Decrypt.caesarWithFrequencies(result);
		String sFD = bytesToString(Encrypt.caesar(result, decodingKey));
		System.out.println("Decoded without knowing the key : " + sFD);

	}

	public static void testVigenere(String message, String key) {
		// Encoding
		String s = Encrypt.encrypt(message, key, 1);
		System.out.println("Encoded :" + s);
		// Decoding with frequencies
		System.out.println("Decoded without knowing the key : " + Decrypt.breakCipher(s, 1));

	}

	public static void testCBC(String message, String key) {
		// Encoding
		String s = Encrypt.encrypt(message, key, 4);
		System.out.println("Encoded :" + s);
		// Decoding with key
		byte[] messageBytes = stringToBytes(s);
		byte[] keyBytes = stringToBytes(key);
		String resultat = bytesToString(Decrypt.decryptCBC(messageBytes, keyBytes));
		System.out.println("Decoded : " + resultat);

	}

	public static void testXor(String message, String key) {
		// Encoding
		String s = Encrypt.encrypt(message, key, 2);
		System.out.println("Encoded :" + s);
		// Decoding with BruteForce 
		String sda = Decrypt.breakCipher(s, 2);
		Helper.writeStringToFile(sda, "bruteForceXor.txt");

	}

	public static void testOTP(String message) {
		// Encoding
		byte[] randomByte = Encrypt.generatePad(message.length());
		String key = Helper.bytesToString(randomByte);
		System.out.println(Encrypt.encrypt(message, key, 3));
	}

	public static void afficherTab(byte[] tab) {
		for (int i = 0; i < tab.length; i++) {
			System.out.print(tab[i] + " ");
		}

	}

}
