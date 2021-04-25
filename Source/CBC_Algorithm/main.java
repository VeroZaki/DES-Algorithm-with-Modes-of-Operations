package CBC_Algorithm;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;  

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
	
	//Convert array of bytes into hexadecimal (Initialization vector)
	private static String convertBytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte temp : bytes) {
            result.append(String.format("%02x", temp));
        }
        return result.toString();
    }
	
	//Convert from hexadecimal to decimal
	private static int HextoDecimal(char Hex) {
	    if (Hex >= '0' && Hex <= '9') 
	        return Hex - '0';
	        
	    if (Hex >= 'A' && Hex <= 'F') 
	        return Hex - 'A' + 10;
	    
	    if (Hex >= 'a' && Hex <= 'f') 
	        return Hex - 'a' + 10;
	    
	    throw new IllegalArgumentException();
	}

	//Convert from decimal to hexadecimal
	private static char DecimaltoHex(int DecimalNumber) {
	    if (DecimalNumber < 0 || DecimalNumber > 15) {
	        throw new IllegalArgumentException();
	    }
	    return "0123456789ABCDEF".charAt(DecimalNumber);
	}
	
	//Convert from string to hexadecimal
	public static String StringToHexadecimal(String S) {
	    StringBuffer sb = new StringBuffer();
	    //Converting string to character array
		char ch[] = S.toCharArray();
		for(int i = 0; i < ch.length; i++) {
			String hexString = Integer.toHexString(ch[i]);
			sb.append(hexString);
			}
	    String result = sb.toString();   
	    return result;
	}
	
	//XORing string and an array of bytes (Initialization Vector)
	static String XOR(String S1, byte[] S2) {
		String FirstNumber = convertBytesToHex(S2);
		String SecondNumber = ASCIItoHEX(S1);
		String XORString = "";
	    char[] chars = new char[FirstNumber.length()];
	    for (int i = 0; i < chars.length; i++) {
	        chars[i] = DecimaltoHex(HextoDecimal(FirstNumber.charAt(i)) ^ HextoDecimal(SecondNumber.charAt(i)));
	        XORString = XORString + chars[i];
	    }
    	return XORString;
    }
	
	//XORing two strings
	static String XORStringConvert(String S1, String S2) {
		String SecondNumber = ASCIItoHEX(S1);
		String XORString = "";
	    char[] chars = new char[S2.length()];
	    for (int i = 0; i < chars.length; i++) {
	        chars[i] = DecimaltoHex(HextoDecimal(S2.charAt(i)) ^ HextoDecimal(SecondNumber.charAt(i)));
	        XORString = XORString + chars[i];
	    }
    	return XORString;
    }
	
	public static void main(String args[]) throws NoSuchAlgorithmException {
		 Scanner scan = new Scanner(System.in);
		 String key = "28DA0E78FA203C9A"; 
		 DES_Encryption DES = new DES_Encryption(); 
		 String message = "";
		 String EncryptedMessage = "";
		 String EncryptedMore64 ="";
		 byte[] IntializationVector = new byte[8];
	     new SecureRandom().nextBytes(IntializationVector);
	     
	     try {
	         File file = new File("original.txt");
	         Scanner sc = new Scanner(file);
	         FileWriter fw = new FileWriter("encrypted.txt",false); //the true will append the new data
				
	         while (sc.hasNextLine()) {
	        	      message = sc.nextLine();
	        	      int n = message.length();
	        	      int bitss = n * 8;         //Every character is two Hex = 8 bits, so the maximum data is 64 bits = 8 bytes for every round
	        		  int Sub = bitss;
	        	      
			 //If the entire text is less than 64 bits
		 if(Sub < 64) {
			String TextPadding = Padding(message , n);
			String XORString = XOR(TextPadding, IntializationVector);
			String Encrypted = DES.encryption(XORString , key);
			System.out.println("Encrypt : " + Encrypted);
			EncryptedMessage = EncryptedMessage + Encrypted;
		 }
		//If the entire text is equal to 64 bits
		 else if(Sub == 64) {
			 String TextPadding = Padding(message , n);
			 String XORString = XOR(TextPadding.substring(0 , 8), IntializationVector);
			 String Encrypted1 = DES.encryption(XORString , key);
			 EncryptedMessage = EncryptedMessage + Encrypted1;
			 System.out.println("Encrypt : " + Encrypted1);
			 
			 XORString = XORStringConvert(TextPadding.substring(8 , 16), Encrypted1);
			 String Encrypted2 = DES.encryption(XORString , key);
			 EncryptedMessage = EncryptedMessage + Encrypted2;
			 System.out.println("Encrypt : " + Encrypted2);
		 }
		//If the entire text is more than 64 bits
		 else {
			 int i=0;
			 String XORString = XOR(message.substring(i, i+8), IntializationVector);
			 Sub = Sub - 64;
			 i+=8;
			 EncryptedMore64 = DES.encryption(XORString , key);
			 EncryptedMessage = EncryptedMessage + EncryptedMore64;
			 System.out.println("Encrypt :" + EncryptedMore64);
			 
			 //Getting all encrypted except for the last 8 bytes
			 while(Sub > 64) {
				 XORString = XORStringConvert(message.substring(i, i+8), EncryptedMore64);	 
				 EncryptedMore64 = DES.encryption(XORString , key);
				 EncryptedMessage = EncryptedMessage + EncryptedMore64;
				 System.out.println("Encrypt :" + EncryptedMore64);
				 Sub = Sub - 64;
				 i+=8;
			 }
			 //For the last 8 bytes
			 // If less than 8 bytes 
			 if(Sub < 64 ) {
				 String TextPadding = Padding(message.substring(i, i+(Sub/8)) , Sub/8);
				 XORString = XORStringConvert(TextPadding, EncryptedMore64);
				 String EncryptedAfterLoop = DES.encryption(XORString , key);
				 System.out.println("Encrypt :" + EncryptedAfterLoop);
				 EncryptedMessage = EncryptedMessage + EncryptedAfterLoop;
				 }
			 //If equal 8 bytes
			 else if(Sub == 64) {
				 String TextPadding = Padding(message.substring(i,i+8), 8);
				 XORString = XORStringConvert(TextPadding.substring(0 , 8), EncryptedMore64);
				 String EncryptedAfterLoop1 = DES.encryption(XORString , key);
				 EncryptedMessage = EncryptedMessage + EncryptedAfterLoop1;
				 System.out.println("Encrypt :" + EncryptedAfterLoop1);
				 
				 XORString = XORStringConvert(TextPadding.substring(8 , 16), EncryptedAfterLoop1);
				 String EncryptedAfterLoop2 = DES.encryption(XORString , key);
				 EncryptedMessage = EncryptedMessage + EncryptedAfterLoop2;
				 System.out.println("Encrypt :" + EncryptedAfterLoop2);
			}
		 }
		 // The entire encrypted message
		 System.out.println("Encryption of the whole text :" + EncryptedMessage);
		 System.out.println("Check the encryption.txt file");
		 fw.write(EncryptedMessage);
	     }
	     fw.close();
	     sc.close();
	     } catch (IOException e) {
	         System.out.println("An error occurred.");
	         e.printStackTrace();
	     }
	}
	     
}
