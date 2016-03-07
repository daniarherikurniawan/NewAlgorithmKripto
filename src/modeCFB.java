import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.BitSet;

public class modeCFB {
	/*Path to open File*/
	final static String mainPath = "/media/daniar/myPassport/WorkPlace/Windows/NewAlgorithmKripto/file/";
	/*Initialization Vector*/
	String IV = "";
	
	/*Key with minimum 8 Byte length or 8 characters*
	 * 1 character = 8 bit = 1 Byte*/	
	String key;
	
	/*Plain text that will be encrypted */
	ArrayList<Integer> plainText;
	/*Chiper text that will be decrypted */
	ArrayList<Integer> chiperText;
	/*Result text is the result of decrypted chiper text */
	ArrayList<Integer> resultText;
	
	/*Constructor of modeCFB*/
	public modeCFB(){
		/*initialization*/
		key = new String("abcdefghijklmnopqrst123456789012");
		this.plainText = new ArrayList<Integer>();
		this.chiperText = new ArrayList<Integer>();
		this.resultText = new ArrayList<Integer>();
	}
	
	
	public static void main(String args[]) { 
		
		/*Create an instance of modeCFB class*/
		modeCFB cfb = new modeCFB();
		
		
		/*Mode Encryption*/
			
			/*Read plain text from PlainText.txt*/
			cfb.plainText = readFile(mainPath+"PlainText.txt");
			
			/*Start the CFB mode*/
			cfb.chiperText = cfb.startEncryptionModeCFB(cfb.plainText);
			
			/*Write chiper text to ChiperText.txt*/
			writeFile(cfb.chiperText, mainPath+"ChiperText.txt");
		
			
		/*Mode Decryption*/
			
			/*Read chiper text from ChiperText.txt*/
			cfb.chiperText = readFile(mainPath+"ChiperText.txt");
			
			/*Start the CFB mode*/
			cfb.resultText = cfb.startDecryptionModeCFB(cfb.chiperText);
			
			/*Write result text to ResultText.txt*/
			writeFile(cfb.resultText, mainPath+"ResultText.txt");
			
		System.out.println("Success");
		
	} 
	
	/*Start the encryption mode CFB*/
	public ArrayList<Integer> startEncryptionModeCFB(ArrayList<Integer> plainText){
		ArrayList<Integer> result = new ArrayList<Integer>();
		for (int i = 0 ; i < plainText.size() ; i ++){
			
			/*adjust the size of block to be sent for encryption
			 * in this case we assume that one block is one Byte*/
			ArrayList<Integer> singleBlock = new ArrayList<Integer>();
			singleBlock.add(plainText.get(i));
			
			/*CFB 8-bit -> this loop will encrypt per character*/
			result.addAll(blockE(singleBlock));
		}
		return result;
	}
	

	/*Start the decryption mode CFB*/
	public ArrayList<Integer> startDecryptionModeCFB(ArrayList<Integer> cipherText){
		ArrayList<Integer> result = new ArrayList<Integer>();
		for (int i = 0 ; i < cipherText.size() ; i ++){
			
			/*adjust the size of block to be sent for encryption
			 * in this case we assume that one block is one Byte*/
			ArrayList<Integer> singleBlock = new ArrayList<Integer>();
			singleBlock.add(cipherText.get(i));
			
			/*CFB 8-bit -> this loop will encrypt per character*/
			result.addAll(blockE(singleBlock));
		}
		return result;
	}
	
	/*To encrypt*/
	public ArrayList<Integer> blockE(ArrayList<Integer> blockPlainText){
		/*To save the chiper text*/
		ArrayList<Integer> cipher = new ArrayList<Integer>();
		
		/*Prepare the key that match the length of the block*/
		String keyStr = key.substring(0,blockPlainText.size());
		byte[] byteOfKey = keyStr.getBytes(StandardCharsets.UTF_8);
		BitSet bitsetKey = BitSet.valueOf(new byte[] { byteOfKey[0] });
		
		for (int i = 0 ; i < blockPlainText.size() ; i ++){
			/*Operation happens per Byte*/
			BitSet bits = new BitSet(); 
			bits = intToBitSet(blockPlainText.get(i));
			
			/*The real algorithm begins here*/
			bits.xor(bitsetKey);
			
			/*After binary operation, it will be converted to integer*/
			cipher.add(bitSetToInt(bits));
		}
		return cipher;
	}

	/*To decrypt*/
	public ArrayList<Integer> blockD(ArrayList<Integer> blockPlainText){
		/*To save the chiper text*/
		ArrayList<Integer> cipher = new ArrayList<Integer>();
		
		/*Prepare the key that match the length of the block*/
		String keyStr = key.substring(0,blockPlainText.size());
		byte[] byteOfKey = keyStr.getBytes(StandardCharsets.UTF_8);
		BitSet bitsetKey = BitSet.valueOf(new byte[] { byteOfKey[0] });
		
		for (int i = 0 ; i < blockPlainText.size() ; i ++){
			/*Operation happens per Byte*/
			BitSet bits = new BitSet(); 
			bits = intToBitSet(blockPlainText.get(i));
			
			/*The real algorithm begins here*/
			bits.xor(bitsetKey);
			
			/*After binary operation, it will be converted to integer*/
			cipher.add(bitSetToInt(bits));
		}
		return cipher;
	}

	/*This function will convert String to Hexadecimal */
	public static String stringToHex(String arg) {
	    return String.format("%040x", new BigInteger(1, arg.getBytes(/*YOUR_CHARSET?*/)));
	}
	
	/*This function will give space between two consequence characters as Hexadecimal format*/
	public static String formatHex(String strHex){
		StringBuilder str = new StringBuilder(strHex);
		int idx = str.length() - 2;

		while (idx > 0)
		{
		    str.insert(idx, " ");
		    idx = idx - 2;
		}
		return str.toString();
	}
	
	/*This function will insert space every 8 characters to represent one Byte*/
	public static String formatByte(String strByte){
		StringBuilder str = new StringBuilder(strByte);
		int idx = str.length() - 8;

		while (idx > 0)
		{
		    str.insert(idx, " ");
		    idx = idx - 8;
		}
		return str.toString();
	}
	
	/*This function convert BitSet to Integer*/
	public static int bitSetToInt(BitSet bitSet){
	    int bitInteger = 0;
	    for(int i = 0 ; i < 32; i++)
	        if(bitSet.get(i))
	            bitInteger |= (1 << i);
	    return bitInteger;
	}
	
	/*This function convert BitSet to Binary*/
	public static String bitSetToBinary(BitSet bitSet){
		int in = bitSetToInt(bitSet);
		return (Integer.toBinaryString(in));
	}

	/*This function convert Long to BitSet*/
	public static BitSet intToBitSet(long value) {
	    BitSet bits = new BitSet();
	    int index = 0;
	    while (value != 0L) {
	      if (value % 2L != 0) {
	        bits.set(index);
	      }
	      ++index;
	      value = value >>> 1;
	    }
	    return bits;
	  }
	
	/*This function will read any file and convert the content to array of Integer
	 * the single Integer is between 0 - 255 even though there is a special character*/
	public static ArrayList<Integer> readFile(String path){
		FileInputStream fis = null;
		ArrayList<Integer> myList = new ArrayList<Integer>();
    	try {
			fis = new FileInputStream(path);
			int content;
			while ((content = fis.read()) != -1) {
	            myList.add(content);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (fis != null)
					fis.close();
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}
		return myList;
	}

	/*This function will write an array of Integer to the desired file*/
	public static void writeFile(ArrayList<Integer> myList, String path){
		BufferedOutputStream bos;
		try {
			bos = new BufferedOutputStream(
			        new FileOutputStream(new File(path)));
			for (int i = 0; i < myList.size(); i++) {
            	bos.write(myList.get(i).intValue());
    		}
	        bos.close();
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
