package CBC_Algorithm;
import java.util.*; 
public class DES_Encryption { 
	// Initial Permutation Table
    int[] Permute = { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12,
                      4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 
                      16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 
                      19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 
                      31, 23, 15, 7 };
    
    // Initial Inverse Permutation Table
    int[] InversePermute = { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 
                             23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 
                             45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 
                             28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 
                             50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 }; 
    
    // Key Permutation Generation
    int[] KeyPermute = { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26,18, 
                        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 
                        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 
                        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 }; 
    
    // Key Choice Table
    int[] KeyChoice = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 
                        4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 
                        30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 
                        50, 36, 29, 32 }; 
    
    // Extention Table
    int[] Expansion = { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 
                        13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 
                        21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 
                        31, 32, 1 };
    
    // Substitution Tables
    int[][][] sbox = { 
            { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, 
              { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, 
              { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, 
              { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } }, 
            { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, 
              { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, 
              { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, 
              { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } }, 
            { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, 
              { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, 
              { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, 
              { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } }, 
            { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, 
              { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, 
              { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, 
              { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } }, 
            { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, 
              { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, 
              { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, 
              { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } }, 
            { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, 
              { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, 
              { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, 
              { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } }, 
            { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, 
              { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, 
              { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, 
              { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } }, 
            { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, 
              { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, 
              { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, 
              { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } } 
            };
    
    // f' Permutation
    int[] fPermute = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31,
                       10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 
                       4, 25 };
    
    // Shift Bit Array for Key
    // "In the generation of keys K1, K2, K9, and K16, we apply a one-bit left rotation.
    //In all other keys, we apply a rotation by two bits to the left."
    int[] shiftBits = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
  
      //Convert Hexadecimals to Binary
        String hextoBin(String input){
            long coverted = Long.parseUnsignedLong(input, 16);
            String binary = Long.toBinaryString(coverted);
            while (binary.length() < (input.length()*4)) 
                    binary = "0" + binary; 
            return binary;
        }
  
      //Convert Binary to Hexadecimals
        String bintoHex(String input){
            long coverted = Long.parseUnsignedLong(input, 2);
            String hexa = Long.toHexString(coverted).toUpperCase();
            while (hexa.length() < (input.length()/4)) 
                    hexa = "0" + hexa; 
            return hexa;
        }
  
        //Each part of the DES has its own permutation section. So, we send the 
        //permutation table responsible for the section.
        String permutation(String input, int[] table){
            String output = "";
            input = hextoBin(input);
            for (int i = 0 ; i < table.length; i++)
                output += input.charAt(table [i] - 1);
            output = bintoHex(output);
            return output;
        }
  
        String XOR(String S1, String S2) {
        	long FirstNumber = Long.parseUnsignedLong(S1, 16);  
            long SecondNumber = Long.parseUnsignedLong(S2, 16); 
            FirstNumber = FirstNumber ^ SecondNumber;
            S1 = Long.toHexString(FirstNumber);
            while(S1.length() < S2.length())
            	S1 = "0" + S1;
        	return S1;
        } 
  
        // left Circular Shifting bits 
        //With every call of this function, it is sent to it the number of bits to 
        //shift with from the shiftBits array
        String RotateLeft(String Input , int NumberInBits) {
        	int BinaryLength = Input.length() * 4; 
        	int permute[] = new int[BinaryLength]; 
        	for (int i = 0; i < BinaryLength - 1; i++) 
                permute[i] = (i + 2); 
            permute[BinaryLength - 1] = 1; 
            NumberInBits-=1;
            while (NumberInBits > 0) {
                Input = permutation(Input , permute); 
                NumberInBits-=1;
            }
            return Input; 
        } 
  
        String[] generateKeys(String key) { 
            String keys[] = new String[16]; 
            key = permutation(key, KeyPermute);
            int i=0 ;
            while (i<16){
                key = RotateLeft(key.substring(0, 7), shiftBits[i]) + RotateLeft(key.substring(7, 14), shiftBits[i]); 
                keys[i] = permutation(key, KeyChoice); 
                i++;
            } 
            return keys; 
        }
  
        //This function does the splitting to 8 substitution boxes and combine them
        // them into 32 bits.
        String split(String input) {
        	input = hextoBin(input);
        	String output = "";
            int j=0;
            for (int i = 0; i < 48; i+=6){
                String sub = input.substring(i, i+6);
                int r = Integer.parseInt(sub.charAt(0) + "" + sub.charAt(5), 2);
                int c = Integer.parseInt(sub.substring(1,5), 2);
                // combine
                output += Integer.toHexString(sbox[j][r][c]);
                j++;
            }
            return output;
        }
  
        String round(String input, String key, int num) { 
            String L = input.substring(0, 8); 
            String R = input.substring(8, 16); 
            String nextL = R; 
            // f' function
            R = permutation(R, Expansion);  
            R = XOR(R, key);  
            R = split(R);  
            R = permutation(R, fPermute); 
            L = XOR(L, R);  
            // combine
            return nextL + L; 
        } 
  
      //DES function block
        public String encryption(String inputText, String key) { 
            String keys[] = generateKeys(key); 
            inputText = permutation(inputText, Permute); 
            for (int i = 0; i < 16; i++) 
                 inputText = round(inputText, keys[i], i);
            //Swap left and right
            String combine = inputText.substring(8, 16) + inputText.substring(0, 8); 
            String encryptedText = permutation(combine, InversePermute); 
            return encryptedText; 
        } 
        
        //DES decryption block
        //Starts from 15 till reaches the 0 round that will give us the decrypted text
        String decryption(String encryptedText, String key) {  
            String keys[] = generateKeys(key);  
            encryptedText = permutation(encryptedText, Permute); 
            for (int i = 15; i > -1; i--)
                encryptedText = round(encryptedText, keys[i], 15 - i); 
            //Swap left and right
            encryptedText = encryptedText.substring(8, 16) + encryptedText.substring(0, 8); 
            String decryptedText = permutation(encryptedText, InversePermute); 
            return decryptedText; 
        }
} 
