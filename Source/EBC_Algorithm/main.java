package EBC_Algorithm;
import CBC_Algorithm.DES_Encryption;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.UnsupportedEncodingException;
import java.util.Scanner;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.lang.Object;
import java.security.NoSuchAlgorithmException;

public class main {
	
	//Convert the text to hexadecimal
		public static String ASCIItoHEX(String ascii)
	    {
	        String hex = "";
	        for (int i = 0; i < ascii.length(); i++) {
	            char ch = ascii.charAt(i);
	            String substr = Integer.toHexString((int)ch);
	            hex += substr;
	        }
	        return hex;
	    }

		//Converts hexadecimal to text (ASCII)
		public static String hexToASCII(String hex) 
	    { 
	        String ascii = ""; 
	        for (int i = 0; i < hex.length(); i += 2) { 
	            String subhex = hex.substring(i, i + 2); 
	            char ch = (char)Integer.parseInt(subhex, 16); 
	            ascii += ch; 
	        } 
	        return ascii; 
	    } 
		
		//Pads depends on the size of the last 8 bytes
		//Only comes here for checking the last 8 bytes
		public static String Padding(String text , int size) {
			String textHex = ASCIItoHEX(text);
			//If number of last 8 bytes is 8, we will pad another 8 bytes of padding
			if(size == 8) {
				for(int i=0;i<15;i++)
					textHex = textHex + "0";
				textHex = textHex + Integer.toString(8);
			}
			//If number of the last 8 bytes is less than 8, it will add padding till it reaches 8 bytes
			else {
				for(int i=0;i<(8-size)*2 - 1;i++)
					textHex = textHex + "0";
				textHex = textHex + Integer.toString(8-size);
			}
			return textHex;
		}

	
	public static void main(String args[]) throws NoSuchAlgorithmException {
		 Scanner scan = new Scanner(System.in);
		 String key = "ADABB09182736CCD"; 
		 DES_Encryption DES = new DES_Encryption(); 
		 String EncryptedMessage = "";
		 String message = "";
		 
		 File file = new File("original.txt");
         try {
			Scanner sc = new Scanner(file);
         FileWriter fw = new FileWriter("encrypted.txt",false);
         while (sc.hasNextLine()) {
   	      message = sc.nextLine();
   	      int n = message.length();
   	      int bitss = n * 8;         //Every character is two Hex = 8 bits, so the maximum data is 64 bits = 8 bytes for every round
   		  int Sub = bitss;
		 if(Sub < 64) {
			String TextPadding = Padding(message , n);
			String Encrypt = DES.encryption(TextPadding , key);
			EncryptedMessage = EncryptedMessage + Encrypt;
			System.out.println("Text Encrypted: " + Encrypt);
		 }
		 else if(Sub == 64) {
			 String TextPadding = Padding(message , n);
			 System.out.println(TextPadding);
			 String Encrypt1 = DES.encryption(TextPadding.substring(0 , 16) , key);
			 EncryptedMessage = EncryptedMessage + Encrypt1;;
			 System.out.println("Text Encrypted: " + Encrypt1);
			 String Encrypt2 = DES.encryption(TextPadding.substring(16 , 32) , key);
			 EncryptedMessage = EncryptedMessage + Encrypt2;
			 System.out.println("Text Encrypted: " + Encrypt2);
		 }
		 else {
			 int i=0;
			 while(Sub > 64) {
				 String Encrypt = DES.encryption(ASCIItoHEX(message.substring(i, i+8)) , key);
				 EncryptedMessage = EncryptedMessage + Encrypt;
				 System.out.println("Text Encrypted: " + Encrypt);
				 Sub = Sub - 64;
				 i+=8;
			 }
			 if(Sub < 64 ) {
					String TextPadding = Padding(message.substring(i, i+(Sub/8)) , Sub/8);
					String Encrypt = DES.encryption(TextPadding , key);
					EncryptedMessage = EncryptedMessage + Encrypt;
					System.out.println("Text Encrypted: " + Encrypt);
				 }
				 else if(Sub == 64) {
					 String TextPadding = Padding(message.substring(i,i+8), 8);
					 String Encrypt1 = DES.encryption(TextPadding.substring(0, 16) , key);
					 EncryptedMessage = EncryptedMessage + Encrypt1;
					 System.out.println("Text Encrypted: " + Encrypt1);
					 String Encrypt2 = DES.encryption(TextPadding.substring(16, 32) , key);
					 EncryptedMessage = EncryptedMessage + Encrypt2;
					 System.out.println("Text Encrypted: " + Encrypt2);
				 }
		 }
		 System.out.println("Encrypted the text : " + EncryptedMessage);
		 System.out.println("Check the encryption.txt file");
		 fw.write(EncryptedMessage);
	     }
	     fw.close();
	     sc.close();
		 
         } catch (Exception e) {
 			// TODO Auto-generated catch block
 			e.printStackTrace();
 		}
	}
}
